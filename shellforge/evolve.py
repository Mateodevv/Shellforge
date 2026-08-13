# shellforge/evolve.py
"""The same case, a week later: does a decision still mean anything?

SHELLHOUND MAKES A PROMISE NO TEST CHECKS. Its README states it plainly --
"Triage states survive re-scans; fingerprints are stable" -- and everything
about the way an analyst works depends on it. Evidence arrives in instalments:
a second webroot copy, another week of logs, a dump that was finally exported.
The case is re-scanned, and the two hundred decisions already made either
survive or they do not. If they do not, the work was for nothing, and nobody
finds out by reading the screen: an artifact that quietly went back to
undecided looks exactly like one nobody has got to yet.

WHY THIS NEEDS A NEW CAPABILITY. Every other check in this repository scores
ONE run against a ground truth. This one compares TWO runs of the same case to
each other, with a human decision in between:

    v1  generate -> analyse -> DECIDE (confirm, dismiss, review)
    v2  generate the same case with a second wave of activity, into the same
        directory, and re-scan the same case.db
    then: is every decision still on the artifact it was made about?

THE SECOND WAVE GOES INTO THE SAME DIRECTORY, deliberately. The fingerprint is
`source|rule|artifact|line`, and `artifact` is an absolute path -- so a case
written somewhere else would orphan every decision for a reason that has
nothing to do with Shellhound. What actually happens is that the analyst
re-copies the webroot into the case they already have, and that is what this
reproduces.

TWO SHAPES OF CHANGE, and the difference between them is the point:

    appended   a shell gains lines AFTER its payload. The finding keeps its
               line number, so the fingerprint holds and the decision should
               survive.
    prepended  a shell gains lines BEFORE its payload, so the same finding is
               now on a different line -- and `line` is part of the
               fingerprint. This is the sharp edge, and the case measures what
               happens rather than assuming it.

Nothing here reimplements a rule. It writes files, sets a triage column, and
reads the column back.
"""
from __future__ import annotations

import sqlite3
from datetime import timedelta
from pathlib import Path

#: What the analyst does between the two scans. Kept small and explicit so the
#: report can name each decision rather than counting them.
TRIAGE_PLAN = ("confirmed", "dismissed", "reviewed")

#: Rules about a file's LOCATION or NAME. They carry no line number -- the
#: engine passes `line=None` -- so their fingerprint cannot move when the file
#: is edited, and a case that prepended to one of these would think it had
#: tested the sharp edge while testing nothing.
#:
#: An expectation, not a detector: naming which rules are positional is the
#: same kind of knowledge as naming a rule id, which every plant already does.
LOCATIONAL = {"webshell.upload_php", "webshell.double_ext",
              "webshell.php_in_image", "webshell.too_large",
              "webshell.unreadable"}


def _roles(plants, client):
    """Assign the three roles from a list of (ident, expect_rules).

    ONE function, called from both sides. `second_wave` decides what to edit
    and `targets` decides what to decide about, and if those two ever pick
    different files the case passes while proving nothing -- which is the
    failure this whole module exists to catch elsewhere.
    """
    with_line = [ident for ident, rules in plants
                 if set(rules) - LOCATIONAL]
    any_php = [ident for ident, _rules in plants]
    return {
        # Only the log changes for this one; the artifact is untouched.
        "log_only": client,
        # Gains lines after its payload: the finding keeps its line.
        "appended": any_php[0] if any_php else None,
        # Gains lines BEFORE its payload, so a content finding moves. Must be
        # a file that has a content rule at all, or nothing moves.
        "prepended": next((i for i in with_line
                           if i != (any_php[0] if any_php else None)), None),
    }


def second_wave(case, rng):
    """Extend a finished case with a second round of attacker activity.

    A TRANSFORMATION, like a hostile axis -- the scenario is not consulted and
    does not need to know it can be continued. The ground truth grows: what
    the second wave adds is planted alongside what the first left.
    """
    from shellforge.render.accesslog import Request
    from shellforge.scenarios import common
    from shellforge.truth import Planted
    from shellforge import markers

    if not case.requests:
        return case
    last = max(r.when for r in case.requests)
    back = last + timedelta(days=rng.randint(4, 9))

    # Whoever it was, it is the same address: the second wave is the same
    # intrusion continuing, not a new one.
    attacker = next(
        (p.ident for p in case.truth.planted
         if p.kind == "client" and "logs.upload_php" in p.expect_rules),
        rng.ip("attacker"))

    roles = _roles(
        [(p.ident, p.expect_rules) for p in case.truth.planted
         if p.kind == "file" and p.ident.endswith(".php") and p.expect_rules],
        attacker)

    # --- 1. the old shell is used again -----------------------------------
    # Log only. No artifact changes, so every decision about them must hold.
    if roles["appended"]:
        rel = roles["appended"].lstrip("/")
        for i in range(rng.randint(3, 8)):
            case.requests.append(Request(
                when=back + timedelta(minutes=i * rng.randint(3, 30)),
                ip=attacker, method="GET", uri=f"/{rel}?cmd=id", status=200,
                size=rng.randint(40, 700), agent=common.QUIET_UA))
        case.truth.event(back, attacker, "returns",
                         f"the same address fetches /{rel} again")

    # --- 2. something new is dropped ---------------------------------------
    fresh = f"{case.site.upload_dir}/2026/01/session-store.php"
    case.files[fresh] = markers.EVAL_INPUT
    case.added_paths.append(fresh)
    case.truth.plant(Planted(
        kind="file", ident=f"/{fresh}",
        expect_rules=["webshell.upload_php", "webshell.eval_input"],
        expect_severity="high",
        note="dropped by the SECOND wave. It has to arrive undecided: a "
             "finding nobody has seen must not inherit a decision from a "
             "neighbour, and must not be hidden by one either"))
    case.truth.event(back + timedelta(minutes=40), attacker, "drop_shell",
                     fresh)
    case.evolved_new = [f"/{fresh}"]

    # --- 3. two existing shells change, in opposite ways -------------------
    case.evolved_appended, case.evolved_prepended = [], []
    if roles["appended"]:
        rel = roles["appended"].lstrip("/")
        body = case.files.get(rel)
        if isinstance(body, str):
            # APPENDED: the payload stays on its line, so the fingerprint of
            # every finding about it is untouched.
            case.files[rel] = body + "// staged 2026-01\n"
            case.evolved_appended.append(roles["appended"])
    if roles["prepended"]:
        rel = roles["prepended"].lstrip("/")
        body = case.files.get(rel)
        if isinstance(body, str) and body.startswith("<?php\n"):
            # PREPENDED: two lines go in above the payload, so a CONTENT
            # finding about this file is now two lines further down -- and
            # `line` is part of the fingerprint. This is the edge the case
            # exists to measure, which is why `_roles` insists this file has
            # a content rule at all: prepending to a file whose only finding
            # is positional moves nothing and proves nothing.
            case.files[rel] = ("<?php\n// cache warmer\n// build 41\n"
                               + body[len("<?php\n"):])
            case.evolved_prepended.append(roles["prepended"])

    case.truth.note(
        "SECOND WAVE. The same address returns, fetches the shell it left, "
        "drops another one, and edits two of the originals -- one by "
        "appending (the payload keeps its line) and one by prepending (the "
        "payload moves two lines down). Every decision made after the first "
        "scan has to still be attached to the artifact it was made about, "
        "and the new shell has to arrive undecided.")
    return case


# --- the human step ---------------------------------------------------------

def targets(truth: dict) -> dict:
    """Which artifacts the second wave will touch, computed from v1's truth.

    THE DECISIONS HAVE TO LAND ON THE ARTIFACTS THAT WILL CHANGE, or the case
    proves nothing. Picking the three worst findings and hoping they overlap
    with what the second wave edits is how a test passes while exercising
    none of its own sharp edges. `second_wave` chooses the first two PHP
    plants; the same list is derivable here, from the same file, before v2
    exists.
    """
    client = next((p["ident"] for p in truth.get("planted", [])
                   if p["kind"] == "client"
                   and "logs.upload_php" in p["expect_rules"]), None)
    return _roles(
        [(p["ident"], p["expect_rules"]) for p in truth.get("planted", [])
         if p["kind"] == "file" and p["ident"].endswith(".php")
         and p["expect_rules"]],
        client)


def decide(case_db: Path, artifacts: dict) -> dict:
    """Decide about named artifacts. `artifacts` is role -> ident.

    WRITES THE COLUMN DIRECTLY rather than going through the triage endpoint,
    and that is a deliberate narrowing. The endpoint also PROPAGATES a
    confirmation one step along proven links, which is its own behaviour with
    its own tests; what is under examination here is only whether a decision
    that exists still exists afterwards. Mixing the two would make a failure
    ambiguous between "the decision was lost" and "the propagation moved it".

    Idents are webroot-relative and the column holds absolute paths, so the
    match is done on the tail -- the same conversion `score.site_path` does
    in the other direction.
    """
    states = dict(zip(("log_only", "appended", "prepended"), TRIAGE_PLAN))
    conn = sqlite3.connect(case_db)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT DISTINCT artifact FROM findings").fetchall()
        decided = {}
        for role, ident in artifacts.items():
            if not ident:
                continue
            tail = ident.replace("\\", "/").lstrip("/").lower()
            for row in rows:
                got = str(row["artifact"]).replace("\\", "/").lower()
                if got == tail or got.endswith("/" + tail):
                    state = states.get(role, "confirmed")
                    conn.execute(
                        "UPDATE findings SET triage = ?, triage_note = ?, "
                        "triaged_at = datetime('now') WHERE artifact = ?",
                        (state, f"decided by shellforge before the re-scan "
                                f"({role})", row["artifact"]))
                    decided[row["artifact"]] = f"{state} [{role}]"
                    break
        conn.commit()
        # TWO DIFFERENT NOTHINGS. A scenario with no file artifacts at all --
        # `clean-baseline` has none by design -- simply cannot be evolved, and
        # the caller skips it. Targets that EXIST and were not found in the
        # case is a different matter: the comparison would run and prove
        # nothing, which is worse than not running.
        wanted = [ident for ident in artifacts.values() if ident]
        if wanted and not decided:
            raise RuntimeError(
                f"none of {wanted} were found among the case's artifacts, so "
                f"the comparison would prove nothing")
        return decided
    finally:
        conn.close()


def snapshot(case_db: Path) -> dict:
    """Everything the comparison needs, as plain data.

    `retired` mirrors SHELLHOUND's definition (case schema 5): a row whose
    engine has a completed run newer than the run that last reproduced the
    row is no longer a current statement. Read here with the same LEFT JOIN
    the server uses, so the check measures the mechanism rather than
    reimplementing it; against an older SHELLHOUND without the columns every
    row reads as current, which is exactly what that version believes."""
    uri = f"file:{Path(case_db).as_posix()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    try:
        try:
            rows = conn.execute(
                "SELECT f.fingerprint, f.artifact, f.rule_id, f.line, "
                "f.triage, f.triage_note, "
                "CASE WHEN done.value IS NULL OR f.seen_run >= "
                "CAST(done.value AS INTEGER) THEN 0 ELSE 1 END AS retired "
                "FROM findings f LEFT JOIN meta done "
                "ON done.key = 'engine_done:' || f.engine").fetchall()
        except sqlite3.OperationalError:
            rows = conn.execute(
                "SELECT fingerprint, artifact, rule_id, line, triage, "
                "triage_note, 0 AS retired FROM findings").fetchall()
    finally:
        conn.close()
    return {r["fingerprint"]: dict(r) for r in rows}


# --- the comparison ---------------------------------------------------------

def compare(before: dict, after: dict, decided: dict) -> dict:
    """What happened to the decisions across the re-scan."""
    kept, lost, changed = [], [], []
    for fp, row in before.items():
        state = row["triage"]
        if state == "new":
            continue
        now = after.get(fp)
        if now is None:
            # The finding is gone under this fingerprint. Either the artifact
            # vanished or something in `source|rule|artifact|line` moved.
            lost.append({"artifact": row["artifact"], "rule": row["rule_id"],
                         "line": row["line"], "was": state,
                         "artifact_still_present": any(
                             a["artifact"] == row["artifact"]
                             for a in after.values())})
        elif now["triage"] != state:
            changed.append({"artifact": row["artifact"], "rule": row["rule_id"],
                            "was": state, "now": now["triage"]})
        else:
            kept.append({"artifact": row["artifact"], "rule": row["rule_id"],
                         "state": state})

    fresh = [dict(row) for fp, row in after.items() if fp not in before]
    inherited = [r for r in fresh if r["triage"] != "new"]

    # SPLIT: the same rule on the same artifact, twice -- once carrying a
    # decision at the line it used to be on, once undecided at the line it is
    # on now. This is what editing a file ABOVE its payload does. Since
    # SHELLHOUND retires the rows a completed re-scan did not reproduce
    # (case schema 5), the split has an honest form and a broken one:
    # predecessor RETIRED means the case says "decided at line 2, not seen
    # again; new question at line 4" -- true, if annoying. Predecessor still
    # CURRENT means the case asserts a decided finding at a line that holds
    # nothing, beside its replacement -- the measured defect of issue #7.
    decided_by_key = {(r["artifact"], r["rule_id"]): r
                      for r in before.values() if r["triage"] != "new"}
    split = []
    for row in fresh:
        was = decided_by_key.get((row["artifact"], row["rule_id"]))
        if was and was["line"] != row["line"]:
            stale = after.get(was["fingerprint"])
            split.append({"artifact": row["artifact"],
                          "rule": row["rule_id"],
                          "decided_line": was["line"], "was": was["triage"],
                          "now_line": row["line"],
                          "predecessor_retired": bool(
                              stale and stale.get("retired"))})
    return {
        "decided_artifacts": decided,
        "kept": kept, "lost": lost, "changed": changed,
        "new": fresh, "inherited": inherited, "split": split,
        "before": len(before), "after": len(after),
    }


def ok(result: dict) -> bool:
    """A split now has a passing form and a failing one.

    The split itself is not a failure: the moved payload really is a new
    question, and SHELLHOUND states it while retiring the row it replaced.
    A split whose predecessor was NOT retired is the old defect standing --
    a decided finding asserted as current at a line that holds nothing --
    and since the retirement mechanic shipped, this check demands it."""
    stale_splits = [s for s in result["split"]
                    if not s.get("predecessor_retired")]
    return not (result["lost"] or result["changed"]
                or result["inherited"] or stale_splits)


def _short(artifact: str) -> str:
    """The last two path segments, or the address unchanged."""
    parts = str(artifact).replace("\\", "/").rstrip("/").split("/")
    return "/".join(parts[-2:]) if len(parts) > 1 else str(artifact)


def report(result: dict) -> str:
    out = ["SHELLFORGE EVOLUTION -- decisions across a re-scan", ""]
    out.append(f"  findings   {result['before']} before, "
               f"{result['after']} after ({len(result['new'])} new)")
    out.append(f"  decided    {len(result['decided_artifacts'])} artifact(s)")
    for artifact, state in result["decided_artifacts"].items():
        out.append(f"               {_short(artifact):<28} {state}")
    out.append(f"  survived   {len(result['kept'])} finding-level decision(s)")
    out.append("")

    if result["lost"]:
        out.append("LOST -- a decision no longer has a finding to sit on")
        for bad in result["lost"]:
            where = ("the artifact is still reported, so the fingerprint "
                     "moved" if bad["artifact_still_present"]
                     else "the artifact is gone from the case entirely")
            out.append(f"  {_short(bad['artifact'])}")
            out.append(f"      {bad['rule']} at line {bad['line']} "
                       f"was {bad['was']}")
            out.append(f"      {where}")
        out.append("")

    if result["changed"]:
        out.append("CHANGED -- a decision came back different")
        for bad in result["changed"]:
            out.append(f"  {_short(bad['artifact'])}: {bad['was']} -> {bad['now']}")
        out.append("")

    if result["inherited"]:
        out.append("INHERITED -- a NEW finding arrived already decided")
        out.append("  (nobody has looked at these; they must start at `new`)")
        for bad in result["inherited"]:
            out.append(f"  {_short(bad['artifact'])}: {bad['rule_id']} "
                       f"= {bad['triage']}")
        out.append("")

    if result.get("split"):
        out.append("SPLIT -- the payload moved and the finding moved with it")
        for bad in result["split"]:
            out.append(f"  {_short(bad['artifact'])}: {bad['rule']}")
            if bad.get("predecessor_retired"):
                out.append(f"      {bad['was']} at line "
                           f"{bad['decided_line']} was RETIRED -- kept, "
                           f"greyed, no longer asserted as current")
                out.append(f"      new and undecided at line "
                           f"{bad['now_line']}, where the payload actually "
                           f"is: an honest new question")
            else:
                out.append(f"      {bad['was']} at line "
                           f"{bad['decided_line']} STILL STANDS AS CURRENT, "
                           f"where there is now nothing -- FAIL")
                out.append(f"      new and undecided at line "
                           f"{bad['now_line']}: the case reports one "
                           f"problem as two")
        out.append("")

    out.append("PASS" if ok(result) else "FAIL")
    return "\n".join(out)
