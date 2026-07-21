"""llm-bouncer — drop-in guardrails for LLM and MCP apps.

A `Pipeline` runs an ordered list of `Rail` objects over user input. Each rail
returns ALLOW, BLOCK, or TRANSFORM; the pipeline stops on the first BLOCK and
carries rewrites forward from any TRANSFORM.

    from llm_bouncer import Pipeline
    from llm_bouncer.rails.length import LengthRail

    pipeline = Pipeline([LengthRail(max_len=4000)])
    outcome = pipeline.check(user_input)

    if outcome.blocked:
        return "Sorry, I can't process that."
    send_to_model(outcome.final_text)

Everything re-exported here is the supported public API. Anything reached
through a submodule path is internal and may move between versions.

Rails are deliberately NOT re-exported. Importing this package would otherwise
drag in every rail and its dependencies — PyYAML for the pattern pack, and
whatever later rails need — even for someone who only wants `LengthRail`. Import
them from `llm_bouncer.rails.*` instead.
"""

from llm_bouncer.pipeline import Pipeline
from llm_bouncer.rails.base import Rail
from llm_bouncer.result import PipelineResult, RailResult, Severity, Verdict

__all__ = [
    "Pipeline",
    "PipelineResult",
    "Rail",
    "RailResult",
    "Severity",
    "Verdict",
]

__version__ = "0.0.1"
