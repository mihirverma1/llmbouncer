"""JSONL audit log — one line per pipeline check.

The input is hashed, never stored: a guardrail log is enriched in payloads and
credentials, so raw input would make it the highest-value plaintext store in the
system. See docs/design-notes.md ("audit.py") for the salt/HMAC, JSONL, and
write-failure reasoning.
"""

import hashlib
import hmac
import json
import warnings
from datetime import datetime, timezone
from pathlib import Path


class AuditLogger:
    """Appends one JSON line per pipeline check.

    Args:
        path: File to append to; parent dirs are created.
        salt: If given, the digest is HMAC instead of plain SHA-256, which
            prevents offline brute-forcing of short inputs. Never written to disk.
        strict: If True, write failures raise instead of warning.
    """

    def __init__(self, path, salt: bytes | str | None = None, strict: bool = False):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(salt, str):
            salt = salt.encode("utf-8")
        self.salt = salt
        self.strict = strict
        self._warned = False  # warn once, not once per request

    def hash_input(self, text: str) -> str:
        """SHA-256, or HMAC-SHA256 when salted (hmac.new avoids length-extension)."""
        data = text.encode("utf-8")
        if self.salt is None:
            return hashlib.sha256(data).hexdigest()
        return hmac.new(self.salt, data, hashlib.sha256).hexdigest()

    def build_record(self, input_text: str, result, error: str | None = None) -> dict:
        """Assemble the record. No raw input, no TRANSFORM text — only a digest
        and non-sensitive metadata."""
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),  # tz-aware UTC
            "input_hash": self.hash_input(input_text),
            "input_length": len(input_text),
            "blocked": result.blocked,
            "final_verdict": "block" if result.blocked else "allow",
            "blocking_rail": result.blocking.rail if result.blocking else None,
            "rails": [
                {
                    "rail": r.rail,
                    "verdict": r.verdict.value,
                    "severity": r.severity.value,
                    "reason": r.reason,
                    # Whatever a rail puts in metadata lands here — which is why
                    # SecretsRail never puts the secret in it.
                    "metadata": r.metadata,
                }
                for r in result.results
            ],
        }
        if error is not None:
            # A rail raised. This is the one event that must never be missing
            # from the log — it means the guardrail failed to run at all.
            record["error"] = error
        return record

    def log(self, input_text: str, result, error: str | None = None) -> None:
        """Append one line. Logging must never take the request down (unless
        strict), so this catches serialization failures as well as I/O ones:
        a rail putting a set in metadata would otherwise raise TypeError out of
        json.dumps and kill the request. Opened per call so log rotation can't
        leave us writing to a deleted inode."""
        try:
            record = self.build_record(input_text, result, error)
            # default=str so an exotic metadata value degrades to its repr
            # instead of failing the write.
            line = json.dumps(record, ensure_ascii=False, separators=(",", ":"), default=str)
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        except (OSError, TypeError, ValueError) as exc:
            if self.strict:
                raise
            if not self._warned:
                self._warned = True
                warnings.warn(
                    f"audit log write failed ({self.path}): {exc}. "
                    "Further failures from this logger are suppressed.",
                    RuntimeWarning,
                    stacklevel=2,
                )

    def __repr__(self) -> str:
        return f"<AuditLogger path={str(self.path)!r} salted={self.salt is not None}>"
