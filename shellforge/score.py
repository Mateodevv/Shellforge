# shellforge/score.py
"""Diff what Shellhound found against what was planted.

READS `case.db` DIRECTLY, not the HTTP API. The API would mean a running
server, a token and a browser-shaped handshake in a CI job that wants a
number; the coupling this buys instead is one table with six columns, and
`findings` is the most stable thing in that schema because its fingerprint
has to survive re-scans by design.

THREE NUMBERS, AND THE SECOND IS THE ONE THAT IS USUALLY MISSING:

  recall     of the planted objects, how many produced every rule they owed.
  precision  of everything reported, how much was about something planted.
  coverage   of the rules that exist, how many this case exercised at all.

A blanket assumption does the heavy lifting for precision: ANY finding on an
artifact that was not planted counts as a false positive. That is the only
honest default -- the alternative is enumerating several hundred clean files
in the ground truth and quietly forgiving whatever was forgotten.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

SEVERITY_NAME = {0: "high", 1: "medium", 2: "low", 3: "info"}
NAME_SEVERITY = {v: k for k, v in SEVERITY_NAME.items()}


@dataclass
class Result:
    hits: list = field(default_factory=list)          # planted, fully found
    misses: list = field(default_factory=list)        # planted, rule missing
    wrong_severity: list = field(default_factory=list)
    false_positives: list = field(default_factory=list)
    violations: list = field(default_factory=list)    # must_not_fire broken
    extras: list = field(default_factory=list)        # planted + unexpected rule
    fired_rules: set = field(default_factory=set)

    @property
    def recall(self) -> float:
        total = len(self.hits) + len(self.misses)
        return len(self.hits) / total if total else 1.0

    @property
    def precision(self) -> float:
        reported = len(self.hits) + len(self.misses) + len(self.false_positives)
        good = len(self.hits) + len(self.misses)
        return good / reported if reported else 1.0

    @property
    def ok(self) -> bool:
        return not (self.misses or self.false_positives or self.violations
                    or self.wrong_severity)


def read_findings(case_db: Path) -> list:
    """Every finding, as dicts. Read-only, so a live case can be scored.

    FILE ARTIFACTS ARE NORMALISED TO THE PATH INSIDE THE WEBROOT. Shellhound
    stores the absolute path on the analysis machine -- correct for it, since
    that is the file an analyst opens, and the interface re-derives a readable
    path from the evidence roots it ships alongside. But an absolute path is
    not something a ground truth written days earlier can predict: it contains
    a temp directory that did not exist yet. So the same conversion happens
    here, out of the same `evidence` table the interface reads.
    """
    uri = f"file:{Path(case_db).as_posix()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        conn.row_factory = sqlite3.Row
        roots = [r["path"] for r in conn.execute(
            "SELECT path FROM evidence WHERE kind = 'webroot'").fetchall()]
        rows = conn.execute(
            "SELECT rule_id, rule, source, severity, artifact_kind, "
            "artifact, line, evidence FROM findings").fetchall()
    finally:
        conn.close()
    out = []
    for row in rows:
        finding = dict(row)
        if finding["artifact_kind"] == "file":
            finding["artifact"] = site_path(finding["artifact"], roots)
        out.append(finding)
    return out


def site_path(absolute: str, roots) -> str:
    """`/` plus the path below whichever registered webroot contains it.

    Case-insensitive because Windows is, and separator-agnostic because a
    path can arrive spelled either way depending on which engine wrote it.
    """
    target = str(absolute).replace("\\", "/")
    for root in roots:
        base = str(root).replace("\\", "/").rstrip("/")
        if base and target.lower().startswith(base.lower() + "/"):
            return "/" + target[len(base) + 1:]
    return absolute


def score(truth: dict, findings: list) -> Result:
    result = Result()
    by_artifact: dict = {}
    for finding in findings:
        by_artifact.setdefault(finding["artifact"], []).append(finding)
        result.fired_rules.add(finding["rule_id"])

    planted_idents = set()

    for planted in truth.get("planted", []):
        ident = planted["ident"]
        planted_idents.add(ident)
        got = by_artifact.get(ident, [])
        got_rules = {f["rule_id"] for f in got}
        expected = set(planted["expect_rules"])
        tolerated = set(planted.get("tolerate_rules", []))

        missing = expected - got_rules
        if missing:
            result.misses.append({
                "ident": ident, "kind": planted["kind"],
                "missing": sorted(missing), "got": sorted(got_rules),
                "note": planted.get("note", ""),
            })
        else:
            result.hits.append({"ident": ident, "rules": sorted(expected)})
            # Severity is only checked once the rules are right; a severity
            # complaint about a rule that never fired is noise on top of the
            # real failure.
            #
            # AND ONLY WHEN SOMETHING WAS EXPECTED AT ALL. A plant with an
            # empty `expect_rules` asserts silence -- see the ghost-shell
            # scenario -- and silence has no severity. Comparing against one
            # turned a deliberate assertion into "expected high, got 99".
            want = NAME_SEVERITY.get(planted.get("expect_severity", "high"))
            worst = min((f["severity"] for f in got), default=99)
            if expected and want is not None and worst != want:
                result.wrong_severity.append({
                    "ident": ident,
                    "expected": SEVERITY_NAME.get(want),
                    "got": SEVERITY_NAME.get(worst, str(worst)),
                })

        surprise = got_rules - expected - tolerated
        if surprise:
            result.extras.append({"ident": ident, "rules": sorted(surprise)})

    # must_not_fire, checked before the blanket rule so a named assertion
    # reports as the specific promise it is rather than as anonymous noise.
    quiet_idents = set()
    for entry in truth.get("must_not_fire", []):
        ident = entry["ident"]
        quiet_idents.add(ident)
        forbidden = set(entry.get("rules", []))
        for finding in by_artifact.get(ident, []):
            if not forbidden or finding["rule_id"] in forbidden:
                result.violations.append({
                    "ident": ident, "rule": finding["rule_id"],
                    "severity": SEVERITY_NAME.get(finding["severity"]),
                    "reason": entry.get("reason", ""),
                    "evidence": (finding.get("evidence") or "")[:120],
                })

    # The blanket rule: anything reported about something nobody planted.
    for artifact, group in by_artifact.items():
        if artifact in planted_idents:
            continue
        for finding in group:
            if artifact in quiet_idents and any(
                    v["ident"] == artifact and v["rule"] == finding["rule_id"]
                    for v in result.violations):
                continue          # already reported as a named violation
            result.false_positives.append({
                "ident": artifact, "kind": finding["artifact_kind"],
                "rule": finding["rule_id"],
                "severity": SEVERITY_NAME.get(finding["severity"]),
                "evidence": (finding.get("evidence") or "")[:120],
            })
    return result


def check_clients(truth: dict, logindex_db: Path) -> dict:
    """Compare the indexed client list against the addresses generated.

    A SECOND ORACLE, FOR WHAT FINDINGS CANNOT SEE. Every assertion above is
    about a finding, and a finding needs a rule to fire. A parser that drops
    a line, or invents a client out of a stray byte, does neither: ordinary
    visitor traffic produces no findings whether it survives or not, so the
    whole class of "the index no longer describes the log" is invisible to
    the rest of this file.

    The client list is derived evidence and a statement about who touched the
    server. So:

        phantom   an address in the index that was never generated. The index
                  is claiming somebody was there who was not.
        missing   an address that was generated and did not arrive. Lines
                  were lost, and nobody would notice which.

    This reads `logindex.db`, which Shellhound derives from the logs and does
    not archive. Absent or unreadable, the check is skipped and says so
    rather than passing quietly.
    """
    path = Path(logindex_db)
    if not path.exists():
        return {"skipped": "no logindex.db"}
    generated = set(truth.get("clients") or [])
    if not generated:
        return {"skipped": "ground truth records no client list"}
    tolerated = set(truth.get("clients_tolerated") or [])
    uri = f"file:{path.as_posix()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        table = None
        for (name,) in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"):
            cols = [row[1] for row in conn.execute(f"PRAGMA table_info({name})")]
            if "ip" in cols:
                table = name
                break
        if table is None:
            return {"skipped": "logindex.db has no client table"}
        indexed = {row[0] for row in conn.execute(f"SELECT ip FROM {table}")}
    finally:
        conn.close()
    return {
        "phantom": sorted(indexed - generated - tolerated),
        "missing": sorted(generated - indexed - tolerated),
        "indexed": len(indexed), "generated": len(generated),
    }


def coverage(fired: set, all_rule_ids) -> dict:
    all_ids = set(all_rule_ids)
    return {
        "exercised": sorted(fired & all_ids),
        "never_fired": sorted(all_ids - fired),
        "unknown": sorted(fired - all_ids),
        "ratio": len(fired & all_ids) / len(all_ids) if all_ids else 0.0,
    }


def shellhound_rule_ids(shellhound_path: Path | None = None):
    """Ask Shellhound for its own catalogue, if it is importable.

    NOT A COPY OF THE LIST. A hardcoded catalogue here would drift the moment
    a rule is added, and would drift SILENTLY -- the coverage report would
    keep claiming full coverage of a set that has grown. If Shellhound cannot
    be imported the coverage section is skipped and says so, which is the
    honest answer to "I do not know what rules exist".
    """
    import sys
    if shellhound_path:
        sys.path.insert(0, str(Path(shellhound_path).resolve()))
    try:
        from server import rules
    except Exception:
        return None
    return {r["id"] for r in rules.catalogue()}


def clients_report(clients: dict | None) -> list:
    """The client-list section, or nothing when the check could not run."""
    if not clients or clients.get("skipped"):
        return []
    out = []
    if clients.get("phantom"):
        out.append(f"PHANTOM CLIENTS -- {len(clients['phantom'])} address(es) "
                   f"in the index that were never generated")
        for ip in clients["phantom"][:8]:
            out.append(f"  {ip!r}")
        out.append("")
    if clients.get("missing"):
        out.append(f"LOST CLIENTS -- {len(clients['missing'])} address(es) "
                   f"generated but not indexed; lines went missing")
        for ip in clients["missing"][:8]:
            out.append(f"  {ip}")
        out.append("")
    return out


def clients_ok(clients: dict | None) -> bool:
    if not clients or clients.get("skipped"):
        return True
    return not clients.get("phantom") and not clients.get("missing")


def report(result: Result, truth: dict, cov: dict | None,
           clients: dict | None = None) -> str:
    meta = f"{truth.get('scenario')} | seed {truth.get('seed')}"
    out = [f"SHELLFORGE SCORE -- {meta}", ""]
    planted_total = len(result.hits) + len(result.misses)
    out.append(f"  recall     {result.recall:6.1%}   "
               f"({len(result.hits)}/{planted_total} planted objects fully found)")
    out.append(f"  precision  {result.precision:6.1%}   "
               f"({len(result.false_positives)} findings about nothing planted)")
    if clients and not clients.get("skipped"):
        out.append(f"  clients    {clients['indexed']:>6}   "
                   f"(of {clients['generated']} generated; "
                   f"{len(clients['phantom'])} phantom, "
                   f"{len(clients['missing'])} lost)")
    if cov:
        out.append(f"  coverage   {cov['ratio']:6.1%}   "
                   f"({len(cov['exercised'])}/"
                   f"{len(cov['exercised']) + len(cov['never_fired'])} "
                   f"rules exercised by this case)")
    out.append("")

    if result.misses:
        out.append("MISSED -- planted, not reported")
        for miss in result.misses:
            out.append(f"  {miss['ident']}")
            out.append(f"      missing: {', '.join(miss['missing'])}")
            if miss["got"]:
                out.append(f"      but got: {', '.join(miss['got'])}")
            if miss["note"]:
                out.append(f"      planted as: {miss['note']}")
        out.append("")

    if result.violations:
        out.append("FALSE POSITIVE -- a named silence assertion broke")
        for bad in result.violations:
            out.append(f"  {bad['ident']}  ->  {bad['rule']} ({bad['severity']})")
            if bad["reason"]:
                out.append(f"      should have stayed quiet: {bad['reason']}")
        out.append("")

    if result.false_positives:
        out.append(f"FALSE POSITIVE -- {len(result.false_positives)} finding(s) "
                   f"about unplanted artifacts")
        shown: dict = {}
        for bad in result.false_positives:
            shown.setdefault(bad["rule"], []).append(bad["ident"])
        for rule, idents in sorted(shown.items(),
                                   key=lambda kv: -len(kv[1])):
            sample = ", ".join(sorted(idents)[:3])
            more = f" (+{len(idents) - 3} more)" if len(idents) > 3 else ""
            out.append(f"  {rule:28s} {len(idents):4d}x  {sample}{more}")
        out.append("")

    if result.wrong_severity:
        out.append("SEVERITY -- right rule, wrong weight")
        for bad in result.wrong_severity:
            out.append(f"  {bad['ident']}: expected {bad['expected']}, "
                       f"got {bad['got']}")
        out.append("")

    if result.extras:
        out.append("EXTRA -- planted object, additional rules fired")
        out.append("  (not a failure; a rule the scenario did not predict)")
        for extra in result.extras:
            out.append(f"  {extra['ident']}: {', '.join(extra['rules'])}")
        out.append("")

    if cov and cov["never_fired"]:
        out.append(f"NEVER EXERCISED -- {len(cov['never_fired'])} rule(s) no "
                   f"scenario in this run can fail on")
        for rule in cov["never_fired"]:
            out.append(f"  {rule}")
        out.append("")

    out += clients_report(clients)
    out.append("PASS" if result.ok and clients_ok(clients) else "FAIL")
    return "\n".join(out)


def load_truth(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))
