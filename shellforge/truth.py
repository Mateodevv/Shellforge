# shellforge/truth.py
"""The ground truth: what was planted, and what must stay quiet.

THIS FILE IS THE PRODUCT. The evidence is only the thing the ground truth
talks about. A generator that emits a webroot and a log is a fixture factory;
one that also states what a correct detector must say about them is a test
oracle, and only the second kind can produce a number.

TWO HALVES, AND THE SECOND IS THE ONE PEOPLE FORGET:

  `planted`       -- measures RECALL. Something is here, a rule must fire.
  `must_not_fire` -- measures PRECISION. Nothing is here, no rule may fire.

Shellhound's own fixtures have exactly one entry of the second kind
(`wp-includes/functions.php`). A rule change that reddens a thousand
legitimate plugin files would pass that suite untouched.

WHY `must_not_fire` NAMES RULES RATHER THAN JUST PATHS. Some quiet-looking
files legitimately trip a MEDIUM rule -- a backup plugin really does call
`shell_exec`, and `webshell.standalone_exec` really is supposed to say so.
Demanding total silence there would be demanding that Shellhound be wrong.
So an entry either forbids specific rule ids, or forbids everything when the
list is empty.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path

SCHEMA_VERSION = 1

SEVERITIES = ("high", "medium", "low", "info")


@dataclass
class Planted:
    """Something deliberately placed, with what a correct detector says."""
    kind: str                         # file | client | table | account
    ident: str                        # webroot-relative path, IP, table name
    expect_rules: list[str]           # rule ids that MUST fire
    expect_severity: str = "high"
    # Rules that MAY also fire on this object without counting as a false
    # positive. A dropped shell trips the location rule and a content rule;
    # which of the two is "the" detection is not worth arguing about, so the
    # scenario names the one it is testing and tolerates the rest.
    tolerate_rules: list[str] = field(default_factory=list)
    sha256: str = ""
    note: str = ""


@dataclass
class MustNotFire:
    """Something legitimate. An entry here failing is a false positive."""
    ident: str
    rules: list[str] = field(default_factory=list)   # empty = nothing at all
    reason: str = ""


@dataclass
class Event:
    """One step of the narrative, in wall-clock order.

    Written out so a human can read the case back without running anything,
    and so a chronology view has something to be checked against.
    """
    at: str                           # ISO 8601, UTC
    actor: str                        # IP or "editorial" / "system"
    act: str
    detail: str = ""


class GroundTruth:
    def __init__(self, *, seed: int, scenario: str, cms: str, cms_version: str):
        self.meta = {
            "schema": SCHEMA_VERSION,
            "seed": seed,
            "scenario": scenario,
            "cms": {"kind": cms, "version": cms_version},
        }
        self.planted: list[Planted] = []
        self.must_not_fire: list[MustNotFire] = []
        self.timeline: list[Event] = []
        # Free-form notes about what this case is FOR. They end up in the
        # JSON because six months later "why is there a 403 in here" is a
        # question somebody will have.
        self.notes: list[str] = []

    # --- recording ----------------------------------------------------------

    def plant(self, planted: Planted) -> Planted:
        for rule in planted.expect_rules:
            if "." not in rule:
                raise ValueError(f"not a rule id: {rule!r}")
        if planted.expect_severity not in SEVERITIES:
            raise ValueError(f"bad severity: {planted.expect_severity!r}")
        self.planted.append(planted)
        return planted

    def keep_quiet(self, ident: str, *, rules=(), reason: str = ""):
        self.must_not_fire.append(
            MustNotFire(ident=ident, rules=list(rules), reason=reason))

    def event(self, at, actor: str, act: str, detail: str = ""):
        stamp = at if isinstance(at, str) else at.strftime("%Y-%m-%dT%H:%M:%SZ")
        self.timeline.append(Event(at=stamp, actor=actor, act=act,
                                   detail=detail))

    def note(self, text: str):
        self.notes.append(text)

    # --- output -------------------------------------------------------------

    def expected_rule_ids(self) -> set[str]:
        out: set[str] = set()
        for p in self.planted:
            out |= set(p.expect_rules)
        return out

    def to_dict(self) -> dict:
        # Timeline sorted here rather than at every call site: the scenario
        # builds the narrative in the order it thinks about it, not in the
        # order it happened.
        return {
            **self.meta,
            "planted": [asdict(p) for p in self.planted],
            "must_not_fire": [asdict(m) for m in self.must_not_fire],
            "timeline": [asdict(e) for e in sorted(self.timeline,
                                                   key=lambda e: e.at)],
            "notes": self.notes,
        }

    def write(self, path: Path):
        path.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8")


def load(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))
