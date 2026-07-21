"""InjectionRail — detects prompt injection (OWASP LLM01).

A speed bump, not a wall: catches known phrasings, loses to paraphrase/encoding/
translation. The intelligence is data/injection_patterns.yaml; this module is a
loader and a loop. See docs/design-notes.md ("rails/injection.py").
"""

import re
from importlib.resources import files

import yaml

from llm_bouncer.rails.base import Rail
from llm_bouncer.result import RailResult, Severity

_DEFAULT_PACK = "injection_patterns.yaml"
_MAX_PACK_BYTES = 1_000_000


class InjectionRail(Rail):
    """Blocks text matching any known injection pattern.

    Args:
        patterns_path: Custom YAML pack; defaults to the bundled one.
    Raises:
        ValueError: If the pack is malformed or a regex is invalid.
    """

    name = "injection"

    def __init__(self, patterns_path=None) -> None:
        raw = self._load_pack(patterns_path)
        # Compile once (hot path), IGNORECASE applied centrally.
        self.patterns = []
        for entry in raw:
            try:
                compiled = re.compile(entry["regex"], re.IGNORECASE)
            except re.error as exc:
                raise ValueError(
                    f"pattern {entry.get('id', '?')!r} has an invalid regex: {exc}"
                ) from exc
            self.patterns.append(
                {
                    "id": entry["id"],
                    "regex": compiled,
                    "description": entry.get("description", "").strip(),
                }
            )

    @staticmethod
    def _load_pack(patterns_path):
        # Bundled pack via importlib.resources (works inside a zip/frozen build).
        if patterns_path is None:
            text = files("llm_bouncer").joinpath("data", _DEFAULT_PACK).read_text(
                encoding="utf-8"
            )
        else:
            # Size cap: a pattern pack is a small config file, and yaml.safe_load
            # on a multi-gigabyte file is an easy way to exhaust memory at import.
            with open(patterns_path, encoding="utf-8") as handle:
                text = handle.read(_MAX_PACK_BYTES + 1)
            if len(text) > _MAX_PACK_BYTES:
                raise ValueError(f"pattern pack exceeds {_MAX_PACK_BYTES} bytes: {patterns_path}")

        # safe_load, never load — load() can execute arbitrary Python.
        data = yaml.safe_load(text)
        if not isinstance(data, dict) or "patterns" not in data:
            raise ValueError("pattern pack must be a mapping containing 'patterns'")
        entries = data["patterns"]
        if not isinstance(entries, list) or not entries:
            raise ValueError("pattern pack 'patterns' must be a non-empty list")
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise ValueError(f"patterns[{index}] must be a mapping")
            if "id" not in entry or "regex" not in entry:
                raise ValueError(f"patterns[{index}] needs both 'id' and 'regex'")
        return entries

    def check(self, text: str) -> RailResult:
        # First match wins and stops. Matched span truncated — it is
        # attacker-controlled text about to enter the audit log.
        for pattern in self.patterns:
            match = pattern["regex"].search(text)
            if match:
                return self._block(
                    f"matched injection pattern: {pattern['id']}",
                    severity=Severity.HIGH,
                    pattern=pattern["id"],
                    matched=match.group(0)[:200],
                )
        return self._allow()

    def __repr__(self) -> str:
        return f"<InjectionRail patterns={len(self.patterns)}>"
