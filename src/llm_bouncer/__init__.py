"""llm-bouncer — drop-in guardrails for LLM and MCP apps.

    from llm_bouncer import Pipeline
    from llm_bouncer.rails.length import LengthRail

    pipeline = Pipeline([LengthRail(max_len=4000)])
    outcome = pipeline.check(user_input)
    if outcome.blocked:
        return "Sorry, I can't process that."
    send_to_model(outcome.final_text)

Rails are imported from llm_bouncer.rails.* rather than re-exported here, so
importing the package doesn't pull in every rail's dependencies. Design reasoning
lives in docs/design-notes.md.
"""

from llm_bouncer.pipeline import Pipeline
from llm_bouncer.rails.base import Rail
from llm_bouncer.result import PipelineResult, RailResult, Severity, Verdict

__all__ = ["Pipeline", "PipelineResult", "Rail", "RailResult", "Severity", "Verdict"]
__version__ = "0.0.1"
