"""Tests for Pipeline.

The happy path here is nearly trivial, so it is not where the value is. The
tests that matter prove the two properties that are easy to get subtly wrong:

  1. A BLOCK genuinely stops execution — later rails are never called. Asserting
     the verdict alone would pass even if every rail still ran, so these tests
     count calls rather than trusting the returned value.
  2. A TRANSFORM's replacement text is what later rails actually see, and what
     `final_text` ends up as.

Fake rails are used for the transform and call-counting cases because no real
rail transforms yet, and because a fake makes the intent obvious: this test is
about the pipeline, not about injection heuristics.
"""

import pytest

from llm_bouncer.pipeline import Pipeline
from llm_bouncer.rails.base import Rail
from llm_bouncer.rails.length import LengthRail
from llm_bouncer.result import Severity, Verdict


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class _RecordingRail(Rail):
    """Always ALLOWs, and remembers every text it was handed.

    `seen` is what makes short-circuiting testable: if a rail after a BLOCK was
    skipped, its `seen` list stays empty. It also proves what a downstream rail
    observed after an upstream TRANSFORM.
    """

    def __init__(self, name="recorder"):
        self.name = name
        self.seen = []

    def check(self, text):
        self.seen.append(text)
        return self._allow()


class _AlwaysBlockRail(Rail):
    def __init__(self, name="blocker"):
        self.name = name

    def check(self, text):
        return self._block("always blocks", severity=Severity.HIGH)


class _UpperRail(Rail):
    """Rewrites text to upper case. A stand-in for a real redacting rail."""

    def __init__(self, name="upper"):
        self.name = name

    def check(self, text):
        return self._transform(text.upper(), "uppercased")


class _BrokenTransformRail(Rail):
    """Returns TRANSFORM but forgets the replacement text — a rail bug."""

    name = "broken"

    def check(self, text):
        from llm_bouncer.result import RailResult

        return RailResult(Verdict.TRANSFORM, self.name, reason="forgot text")


# ---------------------------------------------------------------------------
# All rails allow
# ---------------------------------------------------------------------------


def test_all_allow_returns_original_text_and_full_trace():
    a, b = _RecordingRail("a"), _RecordingRail("b")

    outcome = Pipeline([a, LengthRail(max_len=100), b]).check("hello")

    assert outcome.blocked is False
    assert outcome.final_text == "hello"
    assert outcome.blocking is None
    assert len(outcome.results) == 3
    assert all(r.verdict is Verdict.ALLOW for r in outcome.results)


def test_empty_pipeline_allows_everything():
    """No rails means no opinion — the text passes through untouched.

    Worth pinning as a deliberate choice rather than an accident: a pipeline
    configured with zero rails fails *open*. Anyone building config-driven
    setups needs to know an empty rail list is not a safe default.
    """
    outcome = Pipeline([]).check("anything at all")

    assert outcome.blocked is False
    assert outcome.final_text == "anything at all"
    assert outcome.results == []


def test_results_are_recorded_in_execution_order():
    outcome = Pipeline([_RecordingRail("first"), _RecordingRail("second")]).check("x")

    assert [r.rail for r in outcome.results] == ["first", "second"]


# ---------------------------------------------------------------------------
# Short-circuit on BLOCK — the property that actually matters
# ---------------------------------------------------------------------------


def test_block_stops_the_pipeline_and_later_rails_never_run():
    """The core short-circuit test.

    `after.seen` staying empty is the real assertion. Checking only
    `outcome.blocked` would pass even if every remaining rail had run, because
    the returned verdict would look identical either way.

    This is a security property, not a speed optimisation: once text is known
    hostile, running more rails means feeding attacker-controlled input through
    more regexes and more parsing for no benefit.
    """
    before = _RecordingRail("before")
    after = _RecordingRail("after")

    outcome = Pipeline([before, _AlwaysBlockRail(), after]).check("payload")

    assert outcome.blocked is True
    assert outcome.blocking.rail == "blocker"
    assert before.seen == ["payload"], "rail before the block should have run"
    assert after.seen == [], "rail after the block must NOT have run"
    assert len(outcome.results) == 2, "trace should end at the blocking rail"


def test_blocked_run_returns_no_final_text():
    """`final_text` is None when blocked, never the offending string.

    A safety property. If a blocked pipeline handed the text back, a caller who
    forgot to check `.blocked` would forward hostile input to the model anyway.
    None turns that mistake into a crash.
    """
    outcome = Pipeline([_AlwaysBlockRail()]).check("payload")

    assert outcome.blocked is True
    assert outcome.final_text is None


def test_blocking_result_is_the_last_entry_in_the_trace():
    """`blocking` is a convenience pointer, not separate data.

    It duplicates `results[-1]` so that error handling and log lines do not have
    to index into a list and reason about whether it is empty.
    """
    outcome = Pipeline([_RecordingRail("a"), _AlwaysBlockRail()]).check("payload")

    assert outcome.blocking is outcome.results[-1]


def test_first_block_wins_when_several_rails_would_block():
    """Order decides which rail gets credit, and only the first one runs."""
    outcome = Pipeline(
        [_AlwaysBlockRail("first_blocker"), _AlwaysBlockRail("second_blocker")]
    ).check("payload")

    assert outcome.blocking.rail == "first_blocker"
    assert len(outcome.results) == 1


def test_real_rail_blocks_and_short_circuits():
    """Same behaviour with a real rail, not just fakes.

    Fakes prove the pipeline's own logic; this proves the wiring against real
    code, so a mismatch between the base-class helpers and the pipeline cannot
    hide behind test doubles.
    """
    after = _RecordingRail("after")

    outcome = Pipeline([LengthRail(max_len=5), after]).check("x" * 50)

    assert outcome.blocked is True
    assert outcome.blocking.rail == "length"
    assert outcome.blocking.metadata == {"length": 50, "max_len": 5}
    assert after.seen == []


# ---------------------------------------------------------------------------
# TRANSFORM chaining
# ---------------------------------------------------------------------------


def test_transform_text_is_what_downstream_rails_see():
    """The rewrite propagates — later rails never see the original.

    This is the whole reason TRANSFORM exists as a third verdict, and the
    assertion on `downstream.seen` is what proves it. A pipeline that returned
    the rewritten text at the end but fed the *original* to later rails would
    pass a `final_text` check and still be broken.
    """
    downstream = _RecordingRail("downstream")

    outcome = Pipeline([_UpperRail(), downstream]).check("hello")

    assert downstream.seen == ["HELLO"]
    assert outcome.final_text == "HELLO"
    assert outcome.blocked is False


def test_transforms_accumulate_in_order():
    """Two transforms compose; the second operates on the first one's output."""

    class _ExclaimRail(Rail):
        name = "exclaim"

        def check(self, text):
            return self._transform(text + "!", "added bang")

    outcome = Pipeline([_UpperRail(), _ExclaimRail()]).check("hi")

    assert outcome.final_text == "HI!"


def test_transform_then_block_uses_the_transformed_text():
    """A rail after a transform judges the rewritten text, not the original.

    Concrete consequence: a 6-character input that a transform expands past the
    limit gets blocked on the *new* length. This is exactly why rail order is
    the caller's most consequential decision.
    """
    after = _RecordingRail("after")

    outcome = Pipeline([_UpperRail(), LengthRail(max_len=3), after]).check("hello")

    assert outcome.blocked is True
    assert outcome.blocking.metadata["length"] == 5
    assert after.seen == []


def test_transform_result_is_still_recorded_in_the_trace():
    """TRANSFORM is not a silent operation — it appears in `results` like any verdict."""
    outcome = Pipeline([_UpperRail(), _RecordingRail()]).check("hi")

    assert outcome.results[0].verdict is Verdict.TRANSFORM
    assert outcome.results[0].text == "HI"


def test_transform_without_replacement_text_raises():
    """A TRANSFORM verdict with `text=None` is a broken rail and must fail loudly.

    Treating it as a no-op ALLOW would be genuinely dangerous: a redacting rail
    whose replacement went missing would log "secret redacted" while passing the
    unredacted secret through to the model. That is a guardrail lying about
    having worked, which is worse than having no guardrail.
    """
    with pytest.raises(ValueError, match="TRANSFORM with text=None"):
        Pipeline([_BrokenTransformRail()]).check("hi")


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_non_rail_object_is_rejected_at_construction():
    """Fail at wiring time, not mid-request.

    A misconfigured pipeline should break at startup where someone is watching,
    rather than raising AttributeError on the first user request in production.
    """
    with pytest.raises(TypeError, match="check"):
        Pipeline([LengthRail(max_len=10), "not a rail"])


def test_duck_typed_rail_is_accepted():
    """Any object with a callable `check` works — no inheritance required.

    ADR-001 promises the base class is a convenience, not a gate. The pipeline
    duck-types and never runs an isinstance check, and this test holds it to
    that promise so a future "tidy-up" cannot quietly add one.
    """

    class NotARail:
        name = "duck"

        def check(self, text):
            from llm_bouncer.result import RailResult

            return RailResult(Verdict.ALLOW, "duck")

    outcome = Pipeline([NotARail()]).check("hi")

    assert outcome.blocked is False
    assert outcome.results[0].rail == "duck"


def test_pipeline_is_reusable_across_calls():
    """No state carried between runs — each check starts clean."""
    pipeline = Pipeline([LengthRail(max_len=5)])

    first = pipeline.check("x" * 50)
    second = pipeline.check("ok")

    assert first.blocked is True
    assert second.blocked is False
    assert len(second.results) == 1, "results must not accumulate across runs"


def test_repr_lists_rail_names():
    """Readable failure output when a pipeline shows up in a pytest diff."""
    assert "length" in repr(Pipeline([LengthRail(max_len=10)]))
