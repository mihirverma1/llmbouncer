"""SecretsRail — catches credentials and PII. See docs/design-notes.md.

Two layers: known vendor shapes (regex, precise, named), then Shannon entropy for
unknown random-looking tokens. Unlike InjectionRail, this rail never logs the
value it finds — only kind/start/length — because a log of caught secrets is the
biggest plaintext credential store in the system.
"""

import math
import re
from collections import Counter

from llm_bouncer.rails.base import Rail
from llm_bouncer.result import RailResult, Severity

# Known credential shapes: (kind, regex, severity). Order matters — more specific
# first, so an AWS key reports as "aws_access_key", and sk-ant- before sk-.
_KNOWN_SHAPES = [
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"), Severity.CRITICAL),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), Severity.CRITICAL),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), Severity.CRITICAL),
    # sk-ant- MUST precede sk- or the OpenAI pattern swallows Anthropic keys and
    # reports the wrong vendor.
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"), Severity.CRITICAL),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b"), Severity.CRITICAL),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"), Severity.CRITICAL),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), Severity.CRITICAL),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), Severity.CRITICAL),
    ("bearer_token", re.compile(r"\b(?:Bearer|Basic)\s+[A-Za-z0-9_\-\.=+/]{16,}"), Severity.CRITICAL),
    # `api_key = "..."`, `password: hunter2` — the label carries the meaning.
    # 6+ chars, not 8: weak passwords are the ones most worth catching.
    ("assigned_secret", re.compile(
        r"\b(?:api[_\-]?key|secret|passwd|password|token|access[_\-]?key|private[_\-]?key)"
        r"\s*[:=]\s*[\"\']?(?:[A-Za-z0-9_\-\.]{6,})[\"\']?", re.IGNORECASE), Severity.HIGH),
    # PII, hence HIGH not CRITICAL.
    ("email", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), Severity.HIGH),
]

_SEVERITY_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}

# Bound on redaction passes. Each pass must remove a kind, so this is generous;
# it exists only so a pathological pack can't spin forever.
_MAX_REDACTION_PASSES = 10

# Payment cards: regex finds candidates, Luhn rejects the ~90% that are order
# numbers / phone numbers / timestamps.
_CARD_CANDIDATE = re.compile(r"\b(?:\d[ \-]?){13,19}\b")

# Entropy candidate character class. Excludes :/?&. so a URL breaks into short
# harmless pieces. Length bound is compiled per instance from min_token_length.
_TOKEN_CHARS = r"[A-Za-z0-9+/=_\-]"

# High-entropy but not secrets — excluded before the entropy test.
_KNOWN_BENIGN = [
    re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE),  # UUID
    re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"),  # ISO-8601
]


def shannon_entropy(text: str) -> float:
    """Bits of information per character: H = -Σ p(c)·log2 p(c).

    0 for "aaaa" (predictable), 2 for "abcd" (one of four). Real secrets sit near
    their alphabet ceiling; English sits far below. See design-notes.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _luhn_valid(digits: str) -> bool:
    """Luhn checksum — the check digit every real payment card carries."""
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
    """Detects credentials and PII; blocks, or redacts on request.

    Args:
        redact: TRANSFORM with the secret replaced instead of BLOCK. Off by
            default — redaction still sends the request onward, so incomplete
            detection leaks quietly.
        entropy_threshold: Bits/char above which an unknown token is a secret.
        min_token_length: Shortest token the entropy check considers.
    Raises:
        ValueError: If threshold or min length is not positive.
    """

    name = "secrets"

    def __init__(self, redact: bool = False, entropy_threshold: float = 3.5, min_token_length: int = 20) -> None:
        if entropy_threshold <= 0:
            raise ValueError(f"entropy_threshold must be positive, got {entropy_threshold}")
        if min_token_length <= 0:
            raise ValueError(f"min_token_length must be positive, got {min_token_length}")
        self.redact = redact
        # 3.5 sits between English (~2-3.2) and random base64/hex (~3.8-6).
        self.entropy_threshold = entropy_threshold
        # 20: entropy/char is unstable below it, and every real credential is longer.
        self.min_token_length = min_token_length
        # Compiled from the setting so lowering it actually widens candidates.
        self._token = re.compile(f"{_TOKEN_CHARS}{{{min_token_length},}}")

    def _find_known_shape(self, text: str):
        for kind, pattern, severity in _KNOWN_SHAPES:
            match = pattern.search(text)
            if match:
                return kind, match.span(), severity
        return None

    def _find_card(self, text: str):
        for match in _CARD_CANDIDATE.finditer(text):
            digits = re.sub(r"[ \-]", "", match.group(0))
            if 13 <= len(digits) <= 19 and _luhn_valid(digits):
                return match.span()
        return None

    def _find_high_entropy(self, text: str):
        for match in self._token.finditer(text):
            token = match.group(0)
            if any(shape.match(token) for shape in _KNOWN_BENIGN):
                continue
            # Require letters AND digits — kills long words and big numbers, the
            # main source of entropy false positives.
            if not (any(c.isalpha() for c in token) and any(c.isdigit() for c in token)):
                continue
            entropy = shannon_entropy(token)
            if entropy >= self.entropy_threshold:
                return match.span(), entropy
        return None

    def _detect(self, text):
        """First secret found, most specific kind first. None if clean."""
        found = self._find_known_shape(text)
        if found:
            kind, span, severity = found
            return kind, span, severity, {}

        card_span = self._find_card(text)
        if card_span:
            return "payment_card", card_span, Severity.CRITICAL, {}

        entropy_hit = self._find_high_entropy(text)
        if entropy_hit:
            span, entropy = entropy_hit
            # HIGH not CRITICAL — a guess must not outrank a confirmed vendor key.
            return "high_entropy_blob", span, Severity.HIGH, {"entropy": round(entropy, 2)}

        return None

    def check(self, text: str) -> RailResult:
        detection = self._detect(text)
        if detection is None:
            return self._allow()

        kind, span, severity, extra = detection
        start, end = span

        if not self.redact:
            # Record position/length, NEVER the value.
            return self._block(
                f"detected {kind}",
                severity=severity,
                kind=kind,
                start=start,
                length=end - start,
                **extra,
            )

        # Redact until the text is clean, not just the first kind found. A single
        # pass would leave an email beside a redacted AWS key and still report
        # success — the guardrail lying about having worked.
        redacted, kinds, worst = text, [], severity
        for _ in range(_MAX_REDACTION_PASSES):
            found = self._detect(redacted)
            if found is None:
                break
            found_kind, _, found_severity, _ = found
            stripped = self._redact_all(redacted, found_kind)
            if stripped == redacted:
                break  # no progress; stop rather than spin
            redacted = stripped
            kinds.append(found_kind)
            if _SEVERITY_RANK[found_severity] > _SEVERITY_RANK[worst]:
                worst = found_severity

        unique = list(dict.fromkeys(kinds))
        return self._transform(
            redacted,
            f"redacted {', '.join(unique)}",
            severity=worst,
            kind=unique[0] if unique else kind,
            kinds=unique,
            count=redacted.count("[REDACTED:"),
            **extra,
        )

    def _redact_all(self, text: str, kind: str) -> str:
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
                if not (any(c.isalpha() for c in token) and any(c.isdigit() for c in token)):
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
        return f"<SecretsRail redact={self.redact} entropy>={self.entropy_threshold} min_len={self.min_token_length}>"
