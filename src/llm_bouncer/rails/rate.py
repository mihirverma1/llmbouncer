"""RateRail — per-caller rolling-window rate limit.

The only rail that is stateful, needs caller identity, and ignores the text. Its
verdict depends on timing, so it is the one Week-1 rail that detects automation
rather than a single bad message. Per-process only (ADR-003). See
docs/design-notes.md ("rails/rate.py").
"""

import threading
import time
from collections import OrderedDict, deque

from llm_bouncer.rails.base import Rail
from llm_bouncer.result import RailResult, Severity

_DEFAULT_KEY = "__global__"


class RateRail(Rail):
    """Blocks a caller exceeding `limit` requests per `window_s` seconds.

    Args:
        limit: Requests allowed per window (positive int).
        window_s: Window length in seconds (positive).
        clock: Callable returning seconds. Defaults to time.monotonic
            (wall-clock jumps would break the window); injectable for tests.
        max_keys: Callers tracked at once; oldest evicted beyond this.
    Raises:
        ValueError: If any numeric argument is not positive.
    """

    name = "rate"
    wants_key = True  # opt in to receiving the caller key from Pipeline.check

    def __init__(self, limit: int, window_s: float, clock=time.monotonic, max_keys: int = 10_000) -> None:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise ValueError(f"limit must be a positive int, got {limit!r}")
        if window_s <= 0:
            raise ValueError(f"window_s must be positive, got {window_s!r}")
        if max_keys <= 0:
            raise ValueError(f"max_keys must be positive, got {max_keys!r}")
        self.limit = limit
        self.window_s = window_s
        self.clock = clock
        self.max_keys = max_keys
        # OrderedDict for O(1) LRU eviction; bounded so user-supplied keys can't
        # grow it without limit.
        self._hits: OrderedDict[str, deque] = OrderedDict()
        # Prune-count-append must be atomic, or two concurrent requests both read
        # len(hits) < limit and both append, exceeding the limit.
        # ponytail: one global lock; per-key locks if contention ever shows up.
        self._lock = threading.Lock()

    def check(self, text: str, key: str | None = None) -> RailResult:
        # text ignored — verdict is timing, not content. Missing key -> one
        # shared bucket (fails closed: more restrictive, not less).
        bucket_key = key if key is not None else _DEFAULT_KEY
        now = self.clock()

        with self._lock:
            hits = self._touch(bucket_key)

            # Slide the window: drop aged-out timestamps (O(1) popleft, oldest first).
            cutoff = now - self.window_s
            while hits and hits[0] <= cutoff:
                hits.popleft()

            over_limit = len(hits) >= self.limit
            if over_limit:
                # Do NOT record blocked attempts — else a retry loop pushes its
                # own reset outward forever (penalty box, not rate limit).
                retry_after = round(max(0.0, hits[0] + self.window_s - now), 3)
            else:
                hits.append(now)
                count = len(hits)

        if over_limit:
            return self._block(
                f"rate limit exceeded: {len(hits)}/{self.limit} in {self.window_s}s",
                severity=Severity.MEDIUM,
                key=bucket_key,
                limit=self.limit,
                window_s=self.window_s,
                retry_after=retry_after,
            )

        return self._allow(key=bucket_key, count=count, limit=self.limit, window_s=self.window_s)

    def _touch(self, key: str) -> deque:
        # LRU: evicting a key resets its allowance, so key pressure degrades
        # permissive (don't punish real users for an attacker's junk keys).
        if key in self._hits:
            self._hits.move_to_end(key)
            return self._hits[key]
        while len(self._hits) >= self.max_keys:
            self._hits.popitem(last=False)
        self._hits[key] = deque()
        return self._hits[key]

    def reset(self, key: str | None = None) -> None:
        """Clear one key's history, or all. For tests and operator unblocks."""
        with self._lock:
            if key is None:
                self._hits.clear()
            else:
                self._hits.pop(key, None)

    def __repr__(self) -> str:
        return f"<RateRail limit={self.limit}/{self.window_s}s tracking={len(self._hits)}>"
