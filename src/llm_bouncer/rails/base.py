"""The `Rail` contract: one method, `check(text) -> RailResult`.

Abstract base class rather than Protocol so it can ship the `_allow`/`_block`/
`_transform` helpers that stamp `self.name` onto every result. The pipeline
duck-types, so inheriting is a convenience, not a requirement. Full reasoning:
docs/design-notes.md ("rails/base.py") and ADR-001.
"""

from abc import ABC, abstractmethod

from llm_bouncer.result import RailResult, Severity, Verdict


class Rail(ABC):
    """Base class for every guardrail check.

    Subclasses set `name` and implement `check`. Example::

        class ShoutRail(Rail):
            name = "shout"
            def check(self, text):
                if text.isupper():
                    return self._block("all caps")
                return self._allow()
    """

    name: str = "rail"

    @abstractmethod
    def check(self, text: str) -> RailResult:
        """Inspect `text`, return a verdict.

        Contract: never raise on hostile input (return BLOCK), never mutate the
        input (return a rewrite via TRANSFORM), be deterministic. Raise only for
        programmer error such as a bad constructor argument.
        """
        raise NotImplementedError

    # Result builders. Fill in `self.name` so rails don't hand-write it (a typo
    # there corrupts the audit trail without failing any verdict-based test).

    def _allow(self, reason: str = "", **metadata) -> RailResult:
        return RailResult(Verdict.ALLOW, self.name, reason=reason, metadata=metadata)

    def _block(self, reason: str, severity: Severity = Severity.LOW, **metadata) -> RailResult:
        return RailResult(
            Verdict.BLOCK, self.name, reason=reason, severity=severity, metadata=metadata
        )

    def _transform(
        self, text: str, reason: str, severity: Severity = Severity.LOW, **metadata
    ) -> RailResult:
        return RailResult(
            Verdict.TRANSFORM,
            self.name,
            reason=reason,
            severity=severity,
            text=text,
            metadata=metadata,
        )

    def __repr__(self) -> str:
        return f"<{type(self).__name__} name={self.name!r}>"
