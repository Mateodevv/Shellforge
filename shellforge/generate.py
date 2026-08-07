# shellforge/generate.py
"""Assemble a case on disk: evidence, ground truth, reference copy.

The layout is the one Shellhound expects to be pointed at, so registering a
generated case is three paths and no explanation:

    <out>/<slug>/
        webroot/          the compromised installation
        reference/        the same release, clean -- enables the webroot diff
        logs/             access.log[.N[.gz]], error.log
        dump.sql
        ground_truth.json what a correct detector must say about all of it
        hunt_patterns.json  patterns this case is meant to be searched with
        README.md         the case in prose, for whoever opens the directory
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from shellforge import evolve as evolve_mod
from shellforge import hostile as hostile_mod
from shellforge import scenarios
from shellforge.render import accesslog, errorlog, sqldump, webroot
from shellforge.rng import Rng
from shellforge.world import joomla, wordpress

WORLDS = {"wordpress": wordpress, "joomla": joomla}


def _slug(scenario: str, cms: str, seed: int, scale: str, hostile=()) -> str:
    # The CMS and the axes are in the name because the same scenario runs
    # against several profiles and shapes; without them, generating two into
    # one directory would have the second silently overwrite the first.
    tail = ("-" + "-".join(hostile)) if hostile else ""
    return f"{scenario}-{cms}-{scale}-{seed}{tail}"


def generate(*, scenario: str, cms: str = "wordpress", seed: int = 1,
             scale: str = "small", out: Path, log_format: str = "apache",
             rotate_days: int = 0, verify: bool = True,
             hostile=(), evolve: bool = False) -> dict:
    if cms not in WORLDS:
        raise KeyError(f"unknown cms {cms!r}; have: {', '.join(WORLDS)}")

    rng = Rng(seed)
    # The scenario is resolved BEFORE the world is built, so an unsupported
    # pairing fails immediately instead of after generating an installation
    # nobody will use.
    build_case = scenarios.get(scenario, cms)
    site = WORLDS[cms].build(rng.derive("world"), scale)
    case = build_case(rng.derive("scenario"), site, scale)

    # AFTER the scenario, and deliberately: an axis reshapes finished
    # evidence and must not get a say in what happened. The ground truth is
    # already complete at this point and the axes leave it alone -- which is
    # what makes "the shape must not change the answer" an assertion rather
    # than a hope.
    if hostile:
        hostile_mod.apply(list(hostile), case, rng.derive("hostile"))

    # The second wave comes LAST and reuses the same seed, so v1 and v2 share
    # a world byte for byte and differ only by what the attacker did next.
    # The slug deliberately does not mention it: v2 is written into the SAME
    # directory as v1, because that is what re-copying evidence into an
    # existing case looks like -- and because the fingerprint contains an
    # absolute path, so a second directory would orphan every decision for a
    # reason that has nothing to do with Shellhound.
    if evolve:
        evolve_mod.second_wave(case, rng.derive("evolve"))

    case_dir = Path(out) / _slug(scenario, cms, seed, scale, hostile)
    case_dir.mkdir(parents=True, exist_ok=True)

    # --- evidence -----------------------------------------------------------
    digests = webroot.write(case_dir / "webroot", case.files, verify=verify)

    # Permissions come off AFTER the verification pass, never before: the
    # check exists to catch a virus scanner eating evidence, and a file this
    # case made unreadable on purpose would look exactly like that. Order is
    # the whole trick -- write, prove it landed, then take the rights away.
    for rel in case.unreadable_paths:
        target = case_dir / "webroot" / rel
        try:
            os.chmod(target, 0)
        except OSError:
            # Windows ignores a mode of 0 for the owner. The scenario is
            # expected to have checked the platform and planted nothing.
            pass

    # The clean side of the diff: the same installation minus what the attack
    # added, with the originals restored where it overwrote something.
    clean = webroot.reference_copy(case.files, case.added_paths)
    clean.update(case.modified)
    webroot.write(case_dir / "reference", clean, verify=verify)

    log_files = accesslog.write(case_dir / "logs", case.requests,
                                fmt=log_format, rotate_days=rotate_days,
                                bom=case.log_bom, newline=case.log_newline,
                                encoding=case.log_encoding,
                                raw_lines=case.raw_log_lines)
    if case.error_lines:
        errorlog.write(case_dir / "logs", case.error_lines)
    sqldump.write(case_dir / "dump.sql", site, extra_rows=case.extra_rows)

    # --- ground truth -------------------------------------------------------
    # Digests are filled in AFTER writing, from what actually landed on disk.
    # A hash computed from the intended content would still be correct in a
    # case where the scanner ate the file, which is exactly when it matters.
    for planted in case.truth.planted:
        if planted.kind == "file":
            rel = planted.ident.lstrip("/")
            planted.sha256 = digests.get(rel, "")
    # EVERY ADDRESS THE GENERATOR EMITTED. The findings-based oracle cannot
    # see a parser that loses a line or invents a client: an ordinary
    # visitor's request produces no finding either way. The client list is
    # derived evidence and a statement about who touched the server, so a
    # phantom in it is a false statement -- and that is checkable against
    # exactly this set. See `score.check_clients`.
    case.truth.meta["clients"] = sorted({r.ip for r in case.requests})
    case.truth.write(case_dir / "ground_truth.json")

    (case_dir / "hunt_patterns.json").write_text(
        json.dumps({"patterns": case.hunt_patterns}, indent=2,
                   ensure_ascii=False) + "\n", encoding="utf-8")

    summary = {
        "case_dir": str(case_dir),
        "scenario": scenario, "cms": cms, "seed": seed, "scale": scale,
        "hostile": list(hostile),
        "evolved": bool(evolve),
        "files": len(case.files),
        "requests": len(case.requests),
        "error_lines": len(case.error_lines),
        "log_files": [p.name for p in log_files],
        "planted": len(case.truth.planted),
        "must_not_fire": len(case.truth.must_not_fire),
        "expected_rules": sorted(case.truth.expected_rule_ids()),
        # A fingerprint of the WHOLE case, logs and dump included -- not just
        # the webroot. Hashing only the files made every scenario that leaves
        # the installation alone (clean-baseline, bruteforce-admin,
        # db-only-spam, probe-wave) share one digest, so the determinism
        # check silently stopped covering their logs, which is the only
        # evidence those cases have.
        "digest": _case_digest(case_dir, digests),
    }
    (case_dir / "README.md").write_text(_readme(case, summary),
                                        encoding="utf-8")
    return summary


def _case_digest(case_dir: Path, webroot_digests: dict) -> str:
    """One value over every piece of evidence the case emitted.

    Reads the logs and the dump back off disk rather than hashing what was
    meant to be written: the point of the number is to prove that two runs
    produced the same BYTES, and bytes only exist on disk.
    """
    h = hashlib.sha256()
    for rel, digest in sorted(webroot_digests.items()):
        h.update(f"{rel}:{digest}\n".encode())
    for name in sorted(p.name for p in (case_dir / "logs").glob("*")):
        h.update(name.encode())
        h.update(hashlib.sha256(
            (case_dir / "logs" / name).read_bytes()).digest())
    dump = case_dir / "dump.sql"
    if dump.exists():
        h.update(hashlib.sha256(dump.read_bytes()).digest())
    return h.hexdigest()[:16]


def _readme(case, summary) -> str:
    truth = case.truth
    lines = [
        f"# {summary['scenario']} | seed {summary['seed']} | {summary['scale']}",
        "",
        "Generated by Shellforge. Everything in here is invented: addresses "
        "come from the documentation ranges of RFC 5737, domains end in "
        "`.test`, and every payload is an inert marker that carries a pattern "
        "and does nothing.",
        "",
        "## Register in Shellhound",
        "",
        "| Evidence | Path |",
        "|---|---|",
        f"| Webroot | `webroot/` |",
        f"| Access logs | `logs/` |",
        f"| SQL dump | `dump.sql` |",
        f"| Reference copy | `reference/` |",
        "",
        "## Size",
        "",
        f"- {summary['files']} files in the webroot",
        f"- {summary['requests']} log lines across "
        f"{len(summary['log_files'])} file(s)",
        f"- {summary['error_lines']} error-log lines",
        f"- case digest `{summary['digest']}` "
        f"(same seed must give the same value)",
        "",
        "## What a correct detector must say",
        "",
        f"{len(truth.planted)} planted objects, "
        f"{len(truth.must_not_fire)} silence assertions. Full detail in "
        "`ground_truth.json`; score a scanned case with:",
        "",
        "```bash",
        f"shellforge score --truth ground_truth.json --case <shellhound-case>/case.db",
        "```",
        "",
        "| Object | Must produce |",
        "|---|---|",
    ]
    for planted in truth.planted:
        lines.append(f"| `{planted.ident}` | "
                     f"{', '.join(planted.expect_rules)} |")
    lines += ["", "## Timeline", ""]
    for event in sorted(truth.timeline, key=lambda e: e.at):
        lines.append(f"- `{event.at}` **{event.act}** "
                     f"({event.actor}) {event.detail}")
    if truth.notes:
        lines += ["", "## Notes", ""]
        lines += [f"- {n}" for n in truth.notes]
    return "\n".join(lines) + "\n"
