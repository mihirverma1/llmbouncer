"""JSONL audit log — one line per pipeline check.

Why a guardrail needs an audit log at all: blocking an attack is only half the
job. The other half is being able to answer, afterwards, *what was tried, when,
how often, and by which rail was it caught*. Without that you cannot tell a
single confused user from a scripted campaign, and you cannot tune a pattern
pack because you have no idea what it is firing on.

--------------------------------------------------------------------------
Why the input is hashed and never stored
--------------------------------------------------------------------------
This is the single most important decision in the file, and it follows directly
from what a guardrail sees.

The text reaching this log is, by definition, enriched in exactly the material
you least want lying around: prompt-injection payloads, and — via `SecretsRail`
— API keys, payment cards, and email addresses. An audit log holding raw input
would become the highest-value plaintext store in the system, assembled by the
security tool, kept under different access controls from your database, with
longer retention, and very likely forwarded to a third-party log aggregator.

So the log stores `sha256(input)`. That preserves the property that actually
gets used — *identity*: the same input produces the same hash, so repeated
attacks correlate across time and users — while discarding the content.

**Honest limitation: a hash is not encryption.** For short or predictable input,
anyone holding the log can brute-force it. `sha256("yes")` is a lookup away.
Passing a `salt` turns the digest into an HMAC, which defeats offline
brute-forcing as long as the salt stays out of the log — and it does; only the
digest is written. The cost is that hashes are then comparable only within one
deployment, which is usually what you want anyway.

--------------------------------------------------------------------------
Why JSONL
--------------------------------------------------------------------------
One JSON object per line, newline-delimited. Append-only, so writing never
rewrites earlier bytes; streamable, so the Week-3 report can process a 2 GB log
without loading it; greppable with ordinary tools; and a truncated final line
from a crash costs you that one record rather than corrupting the file, which is
exactly what a single top-level JSON array would do.
"""

import hashlib
import hmac
import json
import warnings
from datetime import datetime, timezone
from pathlib import Path


class AuditLogger:
    """Appends one JSON line per pipeline check.

    Example::

        audit = AuditLogger("guardrails.jsonl")
        pipeline = Pipeline([LengthRail(max_len=4000)], audit=audit)
        pipeline.check(user_input)

    Produces::

        {"timestamp": "2026-07-22T10:15:00+00:00", "input_hash": "9f86d0…",
         "input_length": 42, "blocked": true, "final_verdict": "block",
         "blocking_rail": "injection",
         "rails": [{"rail": "length", "verdict": "allow", "severity": "low"}, …]}

    Args:
        path: File to append to. Parent directories are created.
        salt: Optional secret. When given, the digest is an HMAC instead of a
            plain hash, which prevents offline brute-forcing of short inputs.
        strict: If True, write failures raise. Default False — see `log`.
    """

    def __init__(self, path, salt: bytes | str | None = None, strict: bool = False):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

        if isinstance(salt, str):
            salt = salt.encode("utf-8")
        self.salt = salt
        self.strict = strict

    def hash_input(self, text: str) -> str:
        """Return the digest recorded for `text`.

        Plain SHA-256 by default; HMAC-SHA256 when a salt was supplied.

        `hmac.new` rather than `sha256(salt + text)` because the naive
        concatenation is vulnerable to length-extension: given a digest, an
        attacker can compute the digest of an *extended* message without knowing
        the salt. HMAC's nested construction is specifically designed to prevent
        that, and it costs nothing to use.
        """
        data = text.encode("utf-8")

        if self.salt is None:
            return hashlib.sha256(data).hexdigest()

        return hmac.new(self.salt, data, hashlib.sha256).hexdigest()

    def build_record(self, input_text: str, result) -> dict:
        """Assemble the record. Separated from writing so it can be tested directly.

        Everything here is either non-sensitive metadata or a digest. Note what is
        deliberately absent: the input text, and `RailResult.text` — the rewritten
        version a TRANSFORM produced. That rewrite is derived from the original
        and can carry just as much of it.

        `input_length` is kept because it is genuinely useful for tuning a length
        cap and reveals essentially nothing on its own.
        """
        return {
            # Timezone-aware UTC, ISO-8601. A naive local timestamp is unusable
            # the moment logs from two regions are merged, or the clocks cross a
            # daylight-saving boundary.
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "input_hash": self.hash_input(input_text),
            "input_length": len(input_text),
            "blocked": result.blocked,
            "final_verdict": "block" if result.blocked else "allow",
            "blocking_rail": result.blocking.rail if result.blocking else None,
            "rails": [
                {
                    # `.value` gives the lowercase string, which is why the enums
                    # carry string values — `"verdict": 2` is unreadable at 3 a.m.
                    "rail": r.rail,
                    "verdict": r.verdict.value,
                    "severity": r.severity.value,
                    "reason": r.reason,
                    # Rail metadata is included, and it is the one field that
                    # needs care from rail authors: whatever a rail puts in
                    # metadata lands here. `SecretsRail` records kind/start/length
                    # and never the secret itself precisely because of this line.
                    "metadata": r.metadata,
                }
                for r in result.results
            ],
        }

    def log(self, input_text: str, result) -> None:
        """Append one line for this check.

        **Write failures do not propagate by default**, and that is a real
        tradeoff rather than laziness. A full disk, a rotated-away directory, or
        a permissions change would otherwise take down every request that passes
        through the pipeline — the guardrail becoming the outage. Losing audit
        lines is bad; losing the whole service because logging broke is worse.

        The failure is not silent: it raises a `RuntimeWarning`, so it surfaces
        in test runs and in anything watching warnings.

        Deployments where a missing audit trail is itself a compliance failure
        should pass `strict=True` and get the opposite behaviour.

        Opened per call in append mode rather than holding the handle open, so
        an external log rotation cannot leave this object writing into a deleted
        inode.
        """
        record = self.build_record(input_text, result)

        try:
            with open(self.path, "a", encoding="utf-8") as handle:
                # ensure_ascii=False keeps non-Latin reasons readable rather than
                # escaped. separators drops the space after ": " — trivial per
                # line, meaningful across millions.
                handle.write(
                    json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
                )
        except OSError as exc:
            if self.strict:
                raise
            warnings.warn(
                f"audit log write failed ({self.path}): {exc}",
                RuntimeWarning,
                stacklevel=2,
            )

    def __repr__(self) -> str:
        return f"<AuditLogger path={str(self.path)!r} salted={self.salt is not None}>"
