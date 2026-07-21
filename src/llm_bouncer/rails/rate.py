"""RateRail — caps how many requests one caller may make in a rolling window.

Every other rail in this library judges a single piece of text in isolation.
This one is different in two ways that are worth naming up front, because they
drive every design decision below:

  - **It holds state.** A verdict depends on what happened before, so the rail
    remembers timestamps across calls. Every other rail is a pure function.
  - **It needs to know *who* is asking.** "Text" is not enough; the same request
    from two users is two requests, and from one user twice it is a rate
    violation. That identity comes from the caller via `Pipeline.check(text,
    key=...)`.

--------------------------------------------------------------------------
Why this is a separate rail and not part of LengthRail
--------------------------------------------------------------------------
The Week-1 spec grouped length and rate together, and this implementation splits
them. The reason is the two differences above: `LengthRail` is stateless, pure,
and needs no identity, while this rail is none of those. Merging them would drag
per-caller state and a clock into a class whose entire job is one integer
comparison, and it would mean you could not use a size cap without also opting
into a memory-resident timestamp table.

They also fail differently. An oversized request is one clumsy user; a rate
violation is a pattern, and it is the only rail here that can detect an
*automated* attacker rather than a single bad message.

Separate files, separate concerns. Noted in ADR-003.

--------------------------------------------------------------------------
Rolling window, not fixed buckets
--------------------------------------------------------------------------
A fixed-bucket limiter ("100 per calendar minute") is simpler and has a well
known hole: a caller sends 100 at 10:00:59 and 100 more at 10:01:00, landing 200
requests in two seconds while never breaking the stated limit.

A rolling window has no such edge. On every check, discard timestamps older than
`now - window`, then count what remains. The limit means the same thing at every
instant.
"""

import time
from collections import OrderedDict, deque

from llm_bouncer.rails.base import Rail
from llm_bouncer.result import RailResult, Severity

_DEFAULT_KEY = "__global__"


class RateRail(Rail):
    """Blocks a caller who exceeds `limit` requests per `window_s` seconds.

    Example::

        rail = RateRail(limit=5, window_s=60)
        pipeline = Pipeline([rail])
        pipeline.check(text, key="user-123")     # 6th call in a minute -> BLOCK

    Args:
        limit: Requests allowed per window. Must be positive.
        window_s: Window length in seconds. Must be positive.
        clock: Callable returning seconds as a float. Defaults to
            `time.monotonic`. Injectable so tests need no `sleep`.
        max_keys: Most callers tracked at once. Oldest are evicted beyond this.

    Raises:
        ValueError: If any numeric argument is not positive.
    """

    name = "rate"

    # Opt-in flag the pipeline checks. Without it, `Pipeline` calls
    # `rail.check(text)` like every other rail and this one would have no idea
    # whose request it was looking at. One explicit attribute beats introspecting
    # each rail's signature, which breaks the moment someone wraps `check` in a
    # decorator or accepts `**kwargs`.
    wants_key = True

    def __init__(
        self,
        limit: int,
        window_s: float,
        clock=time.monotonic,
        max_keys: int = 10_000,
    ) -> None:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise ValueError(f"limit must be a positive int, got {limit!r}")
        if window_s <= 0:
            raise ValueError(f"window_s must be positive, got {window_s!r}")
        if max_keys <= 0:
            raise ValueError(f"max_keys must be positive, got {max_keys!r}")

        self.limit = limit
        self.window_s = window_s

        # `time.monotonic`, not `time.time`.
        #
        # Wall-clock time can jump — NTP correction, a daylight-saving change, a
        # VM resuming from a snapshot, an operator setting the clock by hand. A
        # backwards jump makes old timestamps look like they are in the future,
        # so the window never expires and a caller stays blocked indefinitely. A
        # forward jump silently forgives everyone. `monotonic` only ever
        # increases and is defined for exactly this use.
        #
        # Injectable because the alternative is tests that `sleep`, which are
        # slow, flaky under load, and cannot test a 24-hour window at all.
        self.clock = clock
        self.max_keys = max_keys

        # OrderedDict, not a plain dict, so eviction can drop the
        # least-recently-used key in O(1) via `popitem(last=False)`.
        #
        # An unbounded dict here would be a memory leak with an attacker-facing
        # trigger: keys usually come from user input, so anyone able to vary a
        # user id or an IP could add entries indefinitely until the process dies.
        # A rate limiter that can be DoSed by making requests would be a poor
        # rate limiter.
        self._hits: OrderedDict[str, deque] = OrderedDict()

    def check(self, text: str, key: str | None = None) -> RailResult:
        """BLOCK if this key has already used its allowance in the current window.

        `text` is accepted and ignored — the signature is the `Rail` contract, and
        this rail's verdict depends on timing rather than content. It is the one
        rail here that never reads the message.

        Called with `key=None` (a bare `check(text)`, or a pipeline invoked
        without a key), every caller shares one global bucket. That is a
        deliberate, documented default rather than an error: it makes the rail
        usable as a crude global throttle, and it fails *closed* — sharing a
        bucket is more restrictive than not limiting at all, so a caller who
        forgets to pass a key gets over-limiting rather than a silently disabled
        guardrail.

        Severity is MEDIUM. Above LengthRail's LOW, because a rate violation is a
        pattern rather than one clumsy message and is the strongest signal here
        of automation. Below the HIGH of injection and secrets, because hitting a
        limit is often just an over-eager retry loop.
        """
        bucket_key = key if key is not None else _DEFAULT_KEY
        now = self.clock()

        hits = self._touch(bucket_key)

        # Slide the window: drop everything that has aged out.
        #
        # `popleft` on a deque is O(1), and timestamps are appended in order, so
        # the expired ones are always at the front. Filtering a list instead
        # would be O(n) per request.
        cutoff = now - self.window_s
        while hits and hits[0] <= cutoff:
            hits.popleft()

        if len(hits) >= self.limit:
            # Deliberately do NOT record this attempt.
            #
            # If blocked attempts extended the window, a caller hammering the
            # endpoint would keep pushing their own reset further out and stay
            # locked out indefinitely. That behaviour has a name — it is a
            # penalty box, not a rate limit — and it should be an explicit
            # choice, not an accident of where the append landed.
            retry_after = round(max(0.0, hits[0] + self.window_s - now), 3)

            return self._block(
                f"rate limit exceeded: {len(hits)}/{self.limit} in {self.window_s}s",
                severity=Severity.MEDIUM,
                key=bucket_key,
                limit=self.limit,
                window_s=self.window_s,
                # How long until one slot frees up. Lets a caller send a sensible
                # Retry-After header instead of leaving clients to guess and
                # retry in a tight loop.
                retry_after=retry_after,
            )

        hits.append(now)

        return self._allow(
            key=bucket_key,
            count=len(hits),
            limit=self.limit,
            window_s=self.window_s,
        )

    def _touch(self, key: str) -> deque:
        """Fetch this key's timestamps, marking it most-recently-used.

        Eviction is least-recently-used and only runs when the table is full.
        Evicting a key resets that caller's allowance, so under key pressure the
        limiter degrades toward permissive rather than locking out legitimate
        users — the deliberate choice, since the alternative is denying service
        to real callers because an attacker flooded the table with junk keys.
        """
        if key in self._hits:
            self._hits.move_to_end(key)
            return self._hits[key]

        while len(self._hits) >= self.max_keys:
            self._hits.popitem(last=False)

        self._hits[key] = deque()
        return self._hits[key]

    def reset(self, key: str | None = None) -> None:
        """Clear one key's history, or all of them.

        Exists for two real needs: tests that want a clean slate without building
        a new rail, and an operator unblocking a caller who was limited by
        mistake.
        """
        if key is None:
            self._hits.clear()
        else:
            self._hits.pop(key, None)

    def __repr__(self) -> str:
        return (
            f"<RateRail limit={self.limit}/{self.window_s}s "
            f"tracking={len(self._hits)}>"
        )
