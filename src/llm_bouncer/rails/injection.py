"""InjectionRail — detects prompt-injection attempts. OWASP LLM01.

Prompt injection is the top item on the OWASP Top 10 for LLM applications, and
it has no clean fix. Instructions and data arrive through the same channel — a
model reads its system prompt and the user's text as one stream of tokens — so
there is no equivalent of a parameterised SQL query that separates the two. What
exists instead is defence in depth, and pattern matching is one layer of it.

Be honest about what this rail is: **a speed bump, not a wall.** It catches
known phrasings. A determined attacker rephrases, translates, encodes, or splits
the payload across turns, and walks straight past it. It is worth having anyway,
because it stops the copy-pasted attacks that make up the overwhelming majority
of real traffic, and because it produces the audit trail that tells you an attack
was attempted at all.

The intelligence lives in `data/injection_patterns.yaml`, not here. This module
is a loader and a loop.
"""

import re
from importlib.resources import files

import yaml

from llm_bouncer.rails.base import Rail
from llm_bouncer.result import RailResult, Severity

_DEFAULT_PACK = "injection_patterns.yaml"


class InjectionRail(Rail):
    """Blocks text matching any known prompt-injection pattern.

    Example::

        rail = InjectionRail()
        rail.check("what is the capital of France?")            # ALLOW
        rail.check("ignore all previous instructions")          # BLOCK

    Args:
        patterns_path: Optional path to a custom YAML pattern pack. Defaults to
            the bundled pack.

    Raises:
        ValueError: If the pack is malformed or contains an invalid regex.
    """

    name = "injection"

    def __init__(self, patterns_path=None) -> None:
        raw = self._load_pack(patterns_path)

        # Compile once, at construction. Compiling inside check() would re-parse
        # thirteen regexes on every single request — this rail sits in the hot
        # path of every user message, so that cost is real.
        #
        # IGNORECASE is applied centrally rather than left to pattern authors.
        # "IGNORE ALL PREVIOUS INSTRUCTIONS" and "ignore all previous
        # instructions" are the same attack, and expecting every contributor to
        # remember (?i) is how a pack ends up with inconsistent coverage.
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
        """Read and validate a pattern pack.

        The default pack is loaded with `importlib.resources`, not by building a
        path from `__file__`. The difference matters: a package can legitimately
        be installed inside a zip archive, a wheel that was never unpacked, or a
        frozen bundle, and in those cases there is no real directory for
        `__file__` to point into. `importlib.resources` asks the import system
        for the bytes and works in every case.
        """
        if patterns_path is None:
            text = files("llm_bouncer").joinpath("data", _DEFAULT_PACK).read_text(
                encoding="utf-8"
            )
        else:
            with open(patterns_path, encoding="utf-8") as handle:
                text = handle.read()

        # safe_load, never load. yaml.load() can instantiate arbitrary Python
        # objects from a document, which makes a malicious pattern pack into
        # remote code execution. A security library loading untrusted YAML
        # unsafely would be a genuinely embarrassing vulnerability.
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
        """BLOCK on the first matching pattern, otherwise ALLOW.

        **First match wins, and the rail stops there.** It does not collect every
        pattern that fires. One match is already sufficient to block, so
        continuing would burn CPU on attacker-controlled input to produce detail
        nobody acts on — the response is identical either way.

        Severity is HIGH, not CRITICAL. A pattern match means *someone tried*,
        which is worth waking up for; CRITICAL is reserved for the rails that
        prove something actually leaked, such as a live credential in
        `SecretsRail`. If every injection attempt were CRITICAL, the rank would
        stop carrying information — internet-facing apps see these constantly.

        The matched substring is recorded, not just the pattern id, because when
        tuning a pack the only useful question is "what text did this fire on?".
        Note the consequence: for a true positive that span is attacker-supplied
        text landing in your audit log. It is bounded to 200 characters below for
        exactly that reason.
        """
        for pattern in self.patterns:
            match = pattern["regex"].search(text)
            if match:
                return self._block(
                    f"matched injection pattern: {pattern['id']}",
                    severity=Severity.HIGH,
                    pattern=pattern["id"],
                    # Truncated. An attacker controls this string, and it is
                    # about to be written to a log that a human will read and a
                    # dashboard may render. No reason to let them choose how many
                    # kilobytes of it get stored.
                    matched=match.group(0)[:200],
                )

        return self._allow()

    def __repr__(self) -> str:
        return f"<InjectionRail patterns={len(self.patterns)}>"
