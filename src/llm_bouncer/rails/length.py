"""LengthRail — caps input size. See docs/design-notes.md ("rails/length.py").

Blocks oversized input: cost control, context-flood defence (oversized input can
evict the system prompt), and DoS mitigation. Boundary is `>`, so `len ==
max_len` is allowed. Blocks rather than truncates (truncation changes meaning and
lets an attacker aim the cut). Counts characters, not bytes.
"""

from llm_bouncer.rails.base import Rail
from llm_bouncer.result import RailResult, Severity


class LengthRail(Rail):
    """Blocks text longer than `max_len` characters.

    Raises ValueError if `max_len` is not a positive int (bool rejected because
    bool subclasses int).
    """

    name = "length"

    def __init__(self, max_len: int) -> None:
        # Validate at construction: max_len=0 is a config error, not hostile
        # input, and would block every request.
        if isinstance(max_len, bool) or not isinstance(max_len, int):
            raise ValueError(f"max_len must be an int, got {type(max_len).__name__}")
        if max_len <= 0:
            raise ValueError(f"max_len must be positive, got {max_len}")
        self.max_len = max_len

    def check(self, text: str) -> RailResult:
        length = len(text)
        if length > self.max_len:
            return self._block(
                f"length {length} > max {self.max_len}",
                severity=Severity.LOW,
                length=length,
                max_len=self.max_len,
            )
        # Metadata on ALLOW too, so the audit log can show real traffic sizes.
        return self._allow(length=length, max_len=self.max_len)
