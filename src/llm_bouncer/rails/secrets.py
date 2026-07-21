"""SecretsRail — catches credentials and PII before they reach the model.

Two layers, in order:

  1. **Known shapes.** Credentials from major vendors have fixed, recognisable
     formats: an AWS access key is `AKIA` plus sixteen uppercase alphanumerics, a
     GitHub token starts `ghp_`. These match precisely, with near-zero false
     positives, and they name what they found.
  2. **Shannon entropy.** For everything else. A secret is by construction
     random-looking, and randomness is measurable. This catches the in-house
     token from a vendor nobody wrote a regex for.

Layer 1 runs first because it is both cheaper and more specific — knowing "this
is an AWS access key" is far more actionable than "this looked random".

--------------------------------------------------------------------------
Why this rail is the one that must NOT log what it found
--------------------------------------------------------------------------
`InjectionRail` records the text it matched, because seeing the attack is how
you tune the pack. This rail must do the opposite.

If a rail that detects API keys writes the key it detected into the audit log,
then the audit log becomes the largest collection of plaintext credentials in
the system — assembled, helpfully, by the security tool. Every leak the rail
successfully caught is now stored in a file with different access controls,
different retention, and a much higher chance of being shipped to a log
aggregator.

So the metadata here carries the *kind* of secret and *where* it was, never the
value. That asymmetry with InjectionRail is deliberate, and it is the single
most important line of reasoning in this file.
"""

import math
import re
from collections import Counter

from llm_bouncer.rails.base import Rail
from llm_bouncer.result import RailResult, Severity

# ---------------------------------------------------------------------------
# Layer 1 — known credential shapes
#
# Each entry: (kind, compiled regex, severity).
#
# Order matters. More specific patterns come first, so an AWS key is reported as
# "aws_access_key" rather than as a generic high-entropy blob. The first match
# wins, and a precise name is what makes an alert actionable.
# ---------------------------------------------------------------------------

_KNOWN_SHAPES = [
    (
        "private_key",
        # A PEM header is unambiguous — nothing else looks like this, and finding
        # one means an entire private key is probably in the payload.
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
        Severity.CRITICAL,
    ),
    (
        "aws_access_key",
        # AKIA (long-lived user key) or ASIA (temporary STS key), then 16
        # uppercase alphanumerics. The word boundaries stop it matching a longer
        # random run that merely happens to contain "AKIA".
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        Severity.CRITICAL,
    ),
    (
        "github_token",
        # ghp_ personal, gho_ OAuth, ghu_/ghs_ app, ghr_ refresh.
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
        Severity.CRITICAL,
    ),
    (
        "anthropic_key",
        # MUST stay ahead of openai_key. Both begin `sk-`, and the OpenAI pattern
        # would happily swallow `sk-ant-...` and report it as the wrong vendor —
        # which sends whoever is on call to rotate a credential at the wrong
        # provider during an incident. Caught by a test; see
        # test_more_specific_vendor_prefix_wins.
        re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"),
        Severity.CRITICAL,
    ),
    (
        "openai_key",
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b"),
        Severity.CRITICAL,
    ),
    (
        "slack_token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),
        Severity.CRITICAL,
    ),
    (
        "google_api_key",
        re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        Severity.CRITICAL,
    ),
    (
        "jwt",
        # Three base64url segments separated by dots. A JWT is not automatically
        # a secret — but one pasted into a chat box is nearly always a live
        # session token, and it usually carries readable claims about a user.
        re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
        Severity.CRITICAL,
    ),
    (
        "bearer_token",
        # Generic fallback: an Authorization header pasted whole.
        re.compile(r"\b(?:Bearer|Basic)\s+[A-Za-z0-9_\-\.=+/]{16,}"),
        Severity.CRITICAL,
    ),
    (
        "assigned_secret",
        # Catches `api_key = "..."`, `password: hunter2`, `SECRET_TOKEN=abc123`.
        # The assignment is what carries the meaning — the value alone might be
        # any string, but a human labelled it a secret by naming the variable.
        re.compile(
            r"\b(?:api[_\-]?key|secret|passwd|password|token|access[_\-]?key|private[_\-]?key)"
            r"\s*[:=]\s*[\"\']?([A-Za-z0-9_\-\.]{8,})[\"\']?",
            re.IGNORECASE,
        ),
        Severity.HIGH,
    ),
    (
        "email",
        # PII rather than a credential, hence HIGH rather than CRITICAL. Leaking
        # a customer's address into a model's context is a privacy problem, not
        # an account takeover.
        re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        Severity.HIGH,
    ),
]

# Payment cards are handled separately from the list above, because the regex
# alone is not good enough — see `_find_card` for why.
_CARD_CANDIDATE = re.compile(r"\b(?:\d[ \-]?){13,19}\b")

# ---------------------------------------------------------------------------
# Layer 2 — entropy
# ---------------------------------------------------------------------------

# Character class for entropy candidates: what a secret could plausibly be made
# of. Deliberately excludes `:/?&.` so a long URL breaks into short harmless
# pieces instead of arriving as one high-entropy token.
#
# The length bound is NOT baked in here. It is compiled per instance from
# `min_token_length` — an earlier draft hardcoded `{16,}` and any
# `min_token_length` below 16 silently did nothing, because the regex never
# produced a candidate short enough for the setting to matter. A configuration
# knob that quietly has no effect is worse than not offering one.
_TOKEN_CHARS = r"[A-Za-z0-9+/=_\-]"

# Shapes that are long and random-looking but are not secrets. Excluded before
# the entropy test rather than after, so they never reach it.
_KNOWN_BENIGN = [
    # UUID / GUID. Random by design, and printed in logs and docs constantly.
    re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        re.IGNORECASE,
    ),
    # ISO-8601 timestamps.
    re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"),
]


def shannon_entropy(text: str) -> float:
    """Bits of information per character, by Shannon's formula.

        H = -Σ p(c) · log₂ p(c)

    Read it as: how surprising is the next character, on average?

    Work through "aaaa" — one distinct character, p = 1.0, log₂(1) = 0, so
    H = 0. Perfectly predictable, no information. Now "abcd" — four characters
    at p = 0.25 each, log₂(0.25) = -2, so H = 2. Two bits per character, which is
    exactly what it takes to pick one of four options.

    The ceiling is log₂(alphabet size): 4 bits for hex, 6 for base64. Real
    secrets sit near their ceiling because they were generated randomly. English
    text sits far below it — "password" repeats letters, follows spelling rules,
    and lands around 2.75.

    That gap is the whole detection mechanism, and it is also the whole
    limitation: entropy measures *randomness*, and randomness is only correlated
    with secrecy. A UUID scores high and is not a secret; a password of
    "hunter2" scores low and is one.
    """
    if not text:
        return 0.0

    counts = Counter(text)
    length = len(text)

    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def _luhn_valid(digits: str) -> bool:
    """Luhn checksum — the check digit every real payment card carries.

    Why bother, when a regex for "13 to 19 digits" already matches? Because that
    regex also matches order numbers, phone numbers with country codes, tracking
    numbers, and timestamps in milliseconds. Luhn rejects roughly nine out of ten
    random digit strings, which turns a noisy pattern into a usable one.

    A worked-in-passing note on the algorithm: double every second digit from the
    right, subtract 9 from any result above 9, sum everything, and a valid number
    is divisible by 10.
    """
    if not digits.isdigit():
        return False

    total = 0
    for index, char in enumerate(reversed(digits)):
        digit = int(char)
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit

    return total % 10 == 0


class SecretsRail(Rail):
    """Detects credentials and PII; blocks them, or redacts them on request.

    Example::

        SecretsRail().check("my key is AKIAIOSFODNN7EXAMPLE")
        # BLOCK, metadata={"kind": "aws_access_key", ...}

        SecretsRail(redact=True).check("my key is AKIAIOSFODNN7EXAMPLE")
        # TRANSFORM, text="my key is [REDACTED:aws_access_key]"

    Args:
        redact: If True, return TRANSFORM with the secret replaced instead of
            BLOCK. Off by default — see `check` for the reasoning.
        entropy_threshold: Bits per character above which an unknown token is
            treated as a secret. Default 3.5.
        min_token_length: Shortest token the entropy check will consider.
            Default 20.

    Raises:
        ValueError: If the threshold or minimum length is not positive.
    """

    name = "secrets"

    def __init__(
        self,
        redact: bool = False,
        entropy_threshold: float = 3.5,
        min_token_length: int = 20,
    ) -> None:
        if entropy_threshold <= 0:
            raise ValueError(
                f"entropy_threshold must be positive, got {entropy_threshold}"
            )
        if min_token_length <= 0:
            raise ValueError(
                f"min_token_length must be positive, got {min_token_length}"
            )

        self.redact = redact

        # Why 3.5 bits per character.
        #
        # The two distributions this sits between:
        #
        #   English words        ~2.0 - 3.2   "supercalifragilistic" is 3.02
        #   Random base64/hex    ~3.8 - 6.0   a 40-char API token is 5.0+
        #
        # 3.5 sits in the gap. Lower starts catching long compound words and
        # concatenated identifiers; higher starts missing shorter tokens, whose
        # entropy is dragged down by having too few characters to spread across
        # the alphabet.
        #
        # It is a heuristic with no clean separation, which is exactly why the
        # known-shape layer runs first and does the precise work.
        self.entropy_threshold = entropy_threshold

        # Why a 20-character minimum.
        #
        # Entropy per character is unstable on short strings — an 8-character
        # token cannot score high because it has too few characters to spread
        # over its alphabet, while a short ordinary word can score deceptively
        # high by having no repeats at all. ("subway" has six distinct letters
        # in six positions: 2.58, higher than much longer English text.)
        #
        # 20 is also below every real credential worth catching: AWS keys are 20,
        # GitHub tokens 40, and anything shorter is usually too weak to be a
        # production secret anyway.
        self.min_token_length = min_token_length

        # Built from the setting rather than a module constant, so lowering
        # min_token_length actually widens what gets considered.
        self._token = re.compile(f"{_TOKEN_CHARS}{{{min_token_length},}}")

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    def _find_known_shape(self, text: str):
        """Return `(kind, span, severity)` for the first known credential found."""
        for kind, pattern, severity in _KNOWN_SHAPES:
            match = pattern.search(text)
            if match:
                return kind, match.span(), severity
        return None

    def _find_card(self, text: str):
        """Return the span of the first Luhn-valid payment card number.

        Two stages, because either alone is useless: the regex finds digit runs
        of a plausible length, and Luhn discards the ones that are order numbers,
        phone numbers, or timestamps.
        """
        for match in _CARD_CANDIDATE.finditer(text):
            digits = re.sub(r"[ \-]", "", match.group(0))
            if 13 <= len(digits) <= 19 and _luhn_valid(digits):
                return match.span()
        return None

    def _find_high_entropy(self, text: str):
        """Return `(span, entropy)` for the first token that looks random."""
        for match in self._token.finditer(text):
            token = match.group(0)

            if any(shape.match(token) for shape in _KNOWN_BENIGN):
                continue

            # Require both letters and digits.
            #
            # This single condition removes most of the false positives the
            # entropy score alone would produce. Long English words and
            # snake_case identifiers are letters-only; large numbers are
            # digits-only. Real credentials are generated over a mixed alphabet
            # and essentially always contain both.
            has_letter = any(c.isalpha() for c in token)
            has_digit = any(c.isdigit() for c in token)
            if not (has_letter and has_digit):
                continue

            entropy = shannon_entropy(token)
            if entropy >= self.entropy_threshold:
                return match.span(), entropy

        return None

    # ------------------------------------------------------------------
    # The rail contract
    # ------------------------------------------------------------------

    def check(self, text: str) -> RailResult:
        """BLOCK on a detected secret, or TRANSFORM with it redacted.

        **Why `redact` defaults to False.** Redaction is the friendlier
        behaviour and the more dangerous default. It keeps the conversation
        going, which is what a user wants — but it means a request containing a
        live credential still reaches the model, minus the part that was
        recognised. If detection was incomplete, the leak proceeds quietly with a
        reassuring "redacted" line in the audit log. Blocking is the honest
        default; redaction is an informed opt-in.

        **Metadata carries the kind and the position, never the value.** See the
        module docstring — a rail that logs the secrets it catches turns the
        audit log into the biggest plaintext credential store in the system.

        Detection order is known shapes, then payment cards, then entropy: most
        specific to least, so the reported `kind` is as precise as it can be.
        """
        found = self._find_known_shape(text)
        if found:
            kind, span, severity = found
            return self._respond(text, kind, span, severity)

        card_span = self._find_card(text)
        if card_span:
            return self._respond(text, "payment_card", card_span, Severity.CRITICAL)

        entropy_hit = self._find_high_entropy(text)
        if entropy_hit:
            span, entropy = entropy_hit
            return self._respond(
                text,
                "high_entropy_blob",
                span,
                # HIGH, not CRITICAL. The known-shape layer knows what it found;
                # this layer only knows the text looked random, and randomness
                # merely correlates with secrecy. Ranking a guess the same as a
                # confirmed AWS key would make CRITICAL meaningless.
                Severity.HIGH,
                entropy=round(entropy, 2),
            )

        return self._allow()

    def _respond(self, text, kind, span, severity, **extra):
        """Build the BLOCK or TRANSFORM result for a detection.

        `start`/`length` are recorded instead of the matched text. That is enough
        to answer "where in the payload was it?" while never storing the secret
        itself.
        """
        start, end = span
        metadata = {"kind": kind, "start": start, "length": end - start, **extra}

        if not self.redact:
            return self._block(
                f"detected {kind}",
                severity=severity,
                **metadata,
            )

        # Redact every occurrence, not only the one that was found. The detector
        # returns the first match; a payload with three AWS keys would otherwise
        # leave two of them intact in the "sanitised" text — which is worse than
        # not redacting at all, because the audit log now claims it was handled.
        redacted = self._redact_all(text, kind)

        return self._transform(
            redacted,
            f"redacted {kind}",
            severity=severity,
            **metadata,
        )

    def _redact_all(self, text: str, kind: str) -> str:
        """Replace every occurrence of the detected kind with a placeholder.

        The placeholder names the kind — `[REDACTED:aws_access_key]` — because a
        human reading the sanitised prompt later needs to know what used to be
        there. It does not leak the value, only the category.
        """
        placeholder = f"[REDACTED:{kind}]"

        if kind == "payment_card":
            def replace_card(match):
                digits = re.sub(r"[ \-]", "", match.group(0))
                if 13 <= len(digits) <= 19 and _luhn_valid(digits):
                    return placeholder
                return match.group(0)

            return _CARD_CANDIDATE.sub(replace_card, text)

        if kind == "high_entropy_blob":
            def replace_token(match):
                token = match.group(0)
                if any(shape.match(token) for shape in _KNOWN_BENIGN):
                    return token
                if not (
                    any(c.isalpha() for c in token) and any(c.isdigit() for c in token)
                ):
                    return token
                if shannon_entropy(token) >= self.entropy_threshold:
                    return placeholder
                return token

            return self._token.sub(replace_token, text)

        for known_kind, pattern, _ in _KNOWN_SHAPES:
            if known_kind == kind:
                return pattern.sub(placeholder, text)

        return text

    def __repr__(self) -> str:
        return (
            f"<SecretsRail redact={self.redact} "
            f"entropy>={self.entropy_threshold} min_len={self.min_token_length}>"
        )
