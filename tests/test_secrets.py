"""Tests for SecretsRail.

Every credential in this file is fake. `AKIAIOSFODNN7EXAMPLE` is AWS's own
documented placeholder, and the rest are structurally valid but invented — which
is the point, since the rail matches on *shape*, and a shape is all it needs.

Two things get the most attention here:

  1. **Benign prose must not trip the entropy check.** That is the failure mode
     that makes an entropy-based rail unusable, and it is why the threshold and
     the minimum length both have tests explaining their values.
  2. **The rail must never store the secret it caught.** There is an explicit
     test asserting the value is absent from the result, because a rail that
     logs credentials turns the audit log into the largest plaintext credential
     store in the system.
"""

import pytest

from llm_bouncer.rails.secrets import SecretsRail, shannon_entropy
from llm_bouncer.result import Severity, Verdict


@pytest.fixture
def rail():
    return SecretsRail()


@pytest.fixture
def redacting():
    return SecretsRail(redact=True)


# ---------------------------------------------------------------------------
# The entropy function itself
# ---------------------------------------------------------------------------


def test_entropy_of_empty_string_is_zero():
    assert shannon_entropy("") == 0.0


def test_entropy_of_single_repeated_character_is_zero():
    """H = 0 means perfectly predictable — one symbol, p = 1.0, log2(1) = 0.

    No surprise in the next character, therefore no information.
    """
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_entropy_of_four_equally_likely_characters_is_two_bits():
    """Four symbols at p = 0.25 each: H = 2.0, exactly the bits needed to pick one of four.

    The hand-checkable case that proves the implementation matches the formula.
    """
    assert shannon_entropy("abcd") == pytest.approx(2.0)


def test_random_token_scores_higher_than_english():
    """The entire detection mechanism in one assertion.

    Secrets are generated randomly and sit near their alphabet's ceiling.
    English follows spelling rules and repeats letters, so it sits far below.
    Everything else in this rail is threshold placement on that gap.
    """
    english = "the quick brown fox jumps over the lazy dog"
    token = "aB3xK9mQ7pL2vN8wR4tY6uI0oP5sD1fG"

    assert shannon_entropy(token) > shannon_entropy(english)


# ---------------------------------------------------------------------------
# Layer 1 — known credential shapes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kind,text",
    [
        ("aws_access_key", "my key is AKIAIOSFODNN7EXAMPLE ok?"),
        ("aws_access_key", "temp creds ASIAY34FZKBOKMUTVV7A here"),
        # These test strings are shaped to match THIS library's regexes while
        # deliberately NOT matching GitHub/vendor secret scanners — no real
        # numeric ID blocks, obvious "NOTAREAL" markers. A test fixture that
        # looks enough like a live credential to trip push protection is its own
        # small incident, and it is avoidable.
        ("github_token", "token ghp_NOTAREALTOKENxxxxxxxxxxxxxxxxxxxxxxxx bye"),
        ("openai_key", "use sk-proj-NOTAREALKEYxxxxxxxxxxxxxxxx for the demo"),
        ("anthropic_key", "key sk-ant-NOTAREALKEYxxxxxxxxxxxxxxxx done"),
        ("slack_token", "xoxb-NOTAREAL-SLACK-TOKEN-000000 is the bot token"),
        # Google keys are AIza plus exactly 35 characters, 39 total.
        ("google_api_key", "AIzaSyD1abcdefghijklmnopqrstuvwxyz01234 maps key"),
        ("private_key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEow..."),
        ("email", "contact me at alice.smith@example.com please"),
    ],
)
def test_known_shapes_are_detected_and_named(rail, kind, text):
    """Each vendor shape blocks and reports what it is.

    The `kind` matters as much as the block. "An AWS access key was pasted" tells
    an on-call engineer which credential to rotate; "something secret-looking was
    found" does not.
    """
    result = rail.check(text)

    assert result.verdict is Verdict.BLOCK
    assert result.rail == "secrets"
    assert result.metadata["kind"] == kind


def test_credentials_are_critical_and_pii_is_high(rail):
    """Severity separates account takeover from a privacy problem.

    A leaked AWS key is an incident. A leaked email address is a privacy issue.
    Flattening both to the same rank makes the field useless for triage, which is
    the only thing severity is for.
    """
    assert rail.check("AKIAIOSFODNN7EXAMPLE").severity is Severity.CRITICAL
    assert rail.check("alice@example.com").severity is Severity.HIGH


def test_assigned_secret_is_detected_by_its_label(rail):
    """`password = "..."` is a secret because a human labelled it one.

    The value alone could be any string. The variable name is what carries the
    meaning, which is why this pattern keys on the assignment rather than on the
    shape of what follows.
    """
    result = rail.check('config: api_key = "abc123def456ghi789"')

    assert result.verdict is Verdict.BLOCK
    assert result.metadata["kind"] == "assigned_secret"


def test_jwt_is_detected(rail):
    result = rail.check(
        "Authorization header had eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQabcdefghijklmnop in it"
    )

    assert result.verdict is Verdict.BLOCK
    assert result.metadata["kind"] == "jwt"


# ---------------------------------------------------------------------------
# Payment cards — regex plus Luhn
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "number",
    [
        "4532015112830366",       # Visa
        "4532 0151 1283 0366",    # spaced
        "4532-0151-1283-0366",    # hyphenated
        "5425233430109903",       # Mastercard
        "374245455400126",        # Amex, 15 digits
    ],
)
def test_luhn_valid_cards_are_detected(rail, number):
    result = rail.check(f"my card is {number} thanks")

    assert result.verdict is Verdict.BLOCK
    assert result.metadata["kind"] == "payment_card"
    assert result.severity is Severity.CRITICAL


@pytest.mark.parametrize(
    "digits",
    [
        "1234567890123456",   # fails Luhn
        "1111111111111111",   # fails Luhn
    ],
)
def test_digit_runs_that_fail_luhn_are_not_cards(rail, digits):
    """Luhn is what makes the card pattern usable at all.

    "13 to 19 digits" also describes order numbers, phone numbers with country
    codes, tracking numbers, and millisecond timestamps. Luhn rejects about nine
    out of ten random digit strings, turning a noisy pattern into a precise one.
    """
    result = rail.check(f"order number {digits}")

    assert result.metadata.get("kind") != "payment_card"


def test_phone_number_is_not_flagged_as_a_card(rail):
    assert rail.check("call me on +1 415 555 2671").verdict is Verdict.ALLOW


# ---------------------------------------------------------------------------
# Layer 2 — entropy
# ---------------------------------------------------------------------------


def test_unknown_random_token_is_caught_by_entropy(rail):
    """The layer that catches credentials nobody wrote a regex for.

    No vendor prefix, no recognisable shape — just 32 characters that look
    random, which is what every secret looks like by construction.
    """
    result = rail.check("the token is aB3xK9mQ7pL2vN8wR4tY6uI0oP5sD1fG ok")

    assert result.verdict is Verdict.BLOCK
    assert result.metadata["kind"] == "high_entropy_blob"
    assert result.metadata["entropy"] >= 3.5


def test_entropy_hit_is_high_not_critical(rail):
    """A guess must not outrank a certainty.

    The known-shape layer knows what it found. This layer only knows the text
    looked random, and randomness merely correlates with secrecy. Ranking both
    CRITICAL would empty the word of meaning.
    """
    result = rail.check("the token is aB3xK9mQ7pL2vN8wR4tY6uI0oP5sD1fG ok")

    assert result.severity is Severity.HIGH


@pytest.mark.parametrize(
    "text",
    [
        "What is the capital of France?",
        "Summarize this article about renewable energy in three bullet points.",
        "Write a Python function that reverses a linked list in place.",
        "The quick brown fox jumps over the lazy dog near the riverbank.",
        "supercalifragilisticexpialidocious is a very long word indeed",
        "Please refactor get_user_by_email_address_or_username in the auth module.",
        "Deploy the staging environment configuration to the kubernetes cluster.",
    ],
)
def test_benign_prose_never_trips_the_entropy_check(rail, text):
    """Zero tolerance, same as InjectionRail's benign set, for the same reason.

    An entropy rail that flags ordinary sentences gets switched off within a
    week, after which it catches nothing. The long compound word and the long
    snake_case identifier are here deliberately — they are the realistic
    near-misses, and they pass because the rail requires a token to contain both
    letters and digits.
    """
    assert rail.check(text).verdict is Verdict.ALLOW


def test_uuid_is_not_treated_as_a_secret(rail):
    """UUIDs are random by design and printed in logs and docs all day.

    Excluded by shape before the entropy test runs, rather than by tuning the
    threshold — a UUID genuinely is high-entropy, so no threshold could separate
    it from a real secret. The right tool is a known-benign shape list.
    """
    result = rail.check("request id 550e8400-e29b-41d4-a716-446655440000 failed")

    assert result.verdict is Verdict.ALLOW


def test_letters_only_token_is_ignored_by_entropy(rail):
    """The letters-and-digits requirement is what makes the entropy layer usable.

    Long English words and long identifiers are letters-only; large numbers are
    digits-only. Real credentials are generated over a mixed alphabet and
    essentially always contain both.
    """
    assert rail.check("antidisestablishmentarianism").verdict is Verdict.ALLOW


def test_short_token_is_ignored_even_if_random(rail):
    """Below the minimum length, entropy per character is not informative.

    A short string cannot score high — too few characters to spread over the
    alphabet — while a short ordinary word can score deceptively high by having
    no repeated letters at all.
    """
    assert rail.check("id: a1B2c3").verdict is Verdict.ALLOW


def test_thresholds_are_configurable(rail):
    """The defaults are heuristics, so they must be tunable per deployment.

    A codebase full of hashes needs a higher threshold; a chat product handling
    only prose can afford a lower one.
    """
    strict = SecretsRail(entropy_threshold=1.0, min_token_length=8)

    # Note this token still has to contain both letters and digits — that filter
    # is structural, not a threshold, so lowering the threshold does not disable
    # it. Tuning changes sensitivity, not the shape of what counts as a candidate.
    assert strict.check("build id abcdefgh1234").verdict is Verdict.BLOCK
    assert strict.check("hello there everyone").verdict is Verdict.ALLOW


def test_invalid_configuration_is_rejected():
    """Constructor validation, same reasoning as LengthRail: fail at startup."""
    with pytest.raises(ValueError):
        SecretsRail(entropy_threshold=0)
    with pytest.raises(ValueError):
        SecretsRail(min_token_length=-5)


# ---------------------------------------------------------------------------
# The rail must not store what it finds
# ---------------------------------------------------------------------------


def test_result_never_contains_the_secret_value(rail):
    """The most important test in this file.

    InjectionRail records the text it matched, because seeing the attack is how
    you tune the pack. This rail must do the opposite: if a rail that detects API
    keys writes the key into the audit log, then the audit log becomes the
    largest collection of plaintext credentials in the system — assembled by the
    security tool, stored under different access controls, and very likely
    shipped to a log aggregator.

    Position and length are recorded instead, which answers "where in the
    payload was it?" without ever holding the value.
    """
    secret = "AKIAIOSFODNN7EXAMPLE"
    result = rail.check(f"my key is {secret}")

    serialized = repr(result)

    assert secret not in serialized
    assert result.metadata["kind"] == "aws_access_key"
    assert result.metadata["start"] == 10
    assert result.metadata["length"] == len(secret)


# ---------------------------------------------------------------------------
# Redaction (TRANSFORM)
# ---------------------------------------------------------------------------


def test_redaction_returns_transform_with_the_secret_removed(redacting):
    """The first real use of the third verdict.

    The user's actual question survives; only the credential is replaced. That is
    something a two-state allow/block design could not express, which is why
    TRANSFORM exists.
    """
    result = redacting.check("deploy with AKIAIOSFODNN7EXAMPLE please")

    assert result.verdict is Verdict.TRANSFORM
    assert "AKIAIOSFODNN7EXAMPLE" not in result.text
    assert "[REDACTED:aws_access_key]" in result.text
    assert "deploy with" in result.text
    assert "please" in result.text


def test_redaction_removes_every_occurrence_not_just_the_first(redacting):
    """Partial redaction is worse than none, because the log claims it was handled.

    The detector returns the first match. If redaction only replaced that one, a
    payload with three keys would pass two of them through inside text labelled
    "redacted" in the audit trail — a guardrail lying about having worked.
    """
    text = "keys: AKIAIOSFODNN7EXAMPLE and AKIAJ2VGH5EXAMPLE123 both"

    result = redacting.check(text)

    assert "AKIAIOSFODNN7EXAMPLE" not in result.text
    assert "AKIAJ2VGH5EXAMPLE123" not in result.text
    assert result.text.count("[REDACTED:aws_access_key]") == 2


def test_redaction_placeholder_names_the_kind_but_not_the_value(redacting):
    """A human reading the sanitised prompt later needs to know what was there.

    The category is useful context; the value is the thing being protected.
    """
    result = redacting.check("card 4532015112830366 on file")

    assert "[REDACTED:payment_card]" in result.text
    assert "4532015112830366" not in result.text


def test_redaction_handles_high_entropy_blobs(redacting):
    result = redacting.check("token aB3xK9mQ7pL2vN8wR4tY6uI0oP5sD1fG ok")

    assert result.verdict is Verdict.TRANSFORM
    assert "aB3xK9mQ7pL2vN8wR4tY6uI0oP5sD1fG" not in result.text
    assert "[REDACTED:high_entropy_blob]" in result.text


def test_redaction_removes_every_KIND_not_just_the_detected_one(redacting):
    """Regression: the real leak.

    Detection returns the first kind found. Redaction used to replace only that
    kind, so an AWS key beside an email produced TRANSFORM with the email intact
    — and since SecretsRail had already run, nothing re-checked it. The address
    reached the model under a log line claiming the payload was redacted, which
    is a guardrail lying about having worked.

    Redaction now loops until the text is clean.
    """
    result = redacting.check("key AKIAIOSFODNN7EXAMPLE and mail bob@example.com")

    assert "AKIAIOSFODNN7EXAMPLE" not in result.text
    assert "bob@example.com" not in result.text
    assert result.metadata["kinds"] == ["aws_access_key", "email"]
    assert result.metadata["count"] == 2


def test_redaction_reports_the_highest_severity_found(redacting):
    """An email (HIGH) beside an AWS key (CRITICAL) must report CRITICAL.

    Severity drives triage. Reporting the severity of whichever kind happened to
    be detected first would understate the incident.
    """
    result = redacting.check("mail bob@example.com and key AKIAIOSFODNN7EXAMPLE")

    assert result.severity is Severity.CRITICAL


def test_redaction_terminates_on_dense_multi_kind_input(redacting):
    """The pass loop is bounded and must still fully clean realistic input."""
    result = redacting.check(
        "key AKIAIOSFODNN7EXAMPLE mail a@b.com card 4532015112830366 "
        "token aB3xK9mQ7pL2vN8wR4tY6uI0oP5sD1fG"
    )

    assert "AKIAIOSFODNN7EXAMPLE" not in result.text
    assert "a@b.com" not in result.text
    assert "4532015112830366" not in result.text
    assert "aB3xK9mQ7pL2vN8wR4tY6uI0oP5sD1fG" not in result.text


def test_clean_text_allows_even_when_redacting(redacting):
    """No secret, no transform — a clean request is not rewritten for no reason."""
    result = redacting.check("What is the capital of France?")

    assert result.verdict is Verdict.ALLOW
    assert result.text is None


def test_block_is_the_default_not_redact():
    """Blocking is the honest default; redaction is an informed opt-in.

    Redaction is friendlier and more dangerous: the request still reaches the
    model, minus the part that was recognised. If detection was incomplete, the
    leak proceeds quietly with a reassuring "redacted" line in the audit log.
    """
    assert SecretsRail().redact is False


# ---------------------------------------------------------------------------
# Ordering and integration
# ---------------------------------------------------------------------------


def test_more_specific_vendor_prefix_wins(rail):
    """`sk-ant-...` must report as Anthropic, not OpenAI.

    Both vendors use an `sk-` prefix, and the OpenAI pattern is broad enough to
    swallow an Anthropic key whole. Pattern order is the only thing separating
    them — this genuinely failed on the first run, and the consequence is not
    cosmetic: during an incident, the wrong `kind` sends whoever is on call to
    rotate a credential at the wrong provider while the real one stays live.
    """
    result = rail.check("key sk-ant-api03-abcdefghij1234567890XYZ done")

    assert result.metadata["kind"] == "anthropic_key"


def test_known_shape_wins_over_entropy(rail):
    """An AWS key must be reported as an AWS key, not as "something random".

    Both layers would fire on it. Running known shapes first means the alert
    names the credential to rotate rather than describing its statistics.
    """
    result = rail.check("key AKIAIOSFODNN7EXAMPLE here")

    assert result.metadata["kind"] == "aws_access_key"


def test_empty_text_is_allowed(rail):
    assert rail.check("").verdict is Verdict.ALLOW


def test_rail_works_inside_a_pipeline():
    """End-to-end through the real pipeline, with a transform feeding downstream.

    Proves the TRANSFORM contract holds across the boundary: the rail rewrites,
    the pipeline adopts the rewrite, and `final_text` carries it out.
    """
    from llm_bouncer import Pipeline
    from llm_bouncer.rails.length import LengthRail

    pipeline = Pipeline([LengthRail(max_len=200), SecretsRail(redact=True)])

    outcome = pipeline.check("deploy with AKIAIOSFODNN7EXAMPLE now")

    assert outcome.blocked is False
    assert "AKIAIOSFODNN7EXAMPLE" not in outcome.final_text
    assert "[REDACTED:aws_access_key]" in outcome.final_text
