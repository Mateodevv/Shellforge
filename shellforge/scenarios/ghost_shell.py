# shellforge/scenarios/ghost_shell.py
"""ghost-shell -- a shell that was deleted before the copy was taken.

THIS SCENARIO REPRODUCES A DISCREPANCY IN SHELLHOUND AND ENCODES THE CURRENT
BEHAVIOUR, NOT THE DOCUMENTED ONE.

`docs/rules.md`, on the error-log engine, says it catches what the access log
structurally cannot -- and names, as the last item on that list, "a file
deleted before the copy was taken", adding: "For that last one the log is the
only remaining evidence that the path existed at all."

Six lines further down, under *Restraint*, the same document says: "a path is
only written when it resolves to a file under a registered webroot."

Those two statements cannot both hold. `errorlog._resolver()` matches a logged
path against the webroot copy by tail and requires `os.path.isfile()`, so a
file that is gone resolves to nothing, is counted under `unresolved`, and
produces no finding. Measured, not inferred: a fatal naming a deleted file
yields `{'findings': 0, 'unresolved': 1}`.

So the ground truth here expects NOTHING for the ghost, and says why. Two
consequences worth understanding before changing it:

  * The case passes today. It is a reproduction, not a failing test -- a red
    CI would say "Shellforge is broken", which is the wrong sentence.
  * If Shellhound is fixed, the finding will appear and the scorer will
    report it under EXTRA. That is the notification: EXTRA is informational,
    so the fix does not turn the build red, but it does not go unnoticed
    either. When it happens, move the rule into `expect_rules` and delete
    this comment.

Whether the documentation or the code should change is not this repository's
call. The point is that the two disagree, and now there is a case that says so.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from shellforge import markers
from shellforge.render.accesslog import Request
from shellforge.render.errorlog import ErrorLine
from shellforge.scenarios import Case, common, register
from shellforge.truth import GroundTruth, Planted
from shellforge.world import SCALES


@register("ghost-shell")
def build(rng, site, scale: str = "small") -> Case:
    _p, _m, _po, days, per_day = SCALES[scale][:5]
    truth = GroundTruth(seed=rng.seed, scenario="ghost-shell",
                        cms=site.kind, cms_version=site.version)
    case = Case(site=site, truth=truth, files=dict(site.files))
    start = datetime(2026, 1, 5)
    attack_day = start + timedelta(days=int(days * 0.45))

    requests, editor_ip = common.baseline(rng.derive("baseline"), site, start,
                                          days, per_day)
    case.requests = requests + common.scanner_noise(rng.derive("scanners"),
                                                    start, days)

    upload_month = f"{site.upload_dir}/2026/01"
    ghost = f"{upload_month}/rt-cache.php"
    attacker = rng.ip("attacker")
    t0 = rng.moment(attack_day, 1, 3)

    # The shell existed: it was fetched successfully, several times, and it
    # crashed on its own payload. It is NOT written to the webroot -- the
    # attacker removed it before the copy was taken, which is the whole case.
    for i in range(rng.randint(5, 12)):
        case.requests.append(Request(
            when=t0 + timedelta(minutes=i * rng.randint(2, 14)), ip=attacker,
            method=rng.weighted([("GET", 3), ("POST", 1)]),
            uri=f"/{ghost}?cmd=id", status=200, size=rng.randint(50, 800),
            agent=common.QUIET_UA))
    case.error_lines.append(ErrorLine(
        when=t0 + timedelta(minutes=6), level="PHP Fatal error",
        message="Uncaught Error: Call to undefined function gzuncmpress()",
        path=f"{common.WEBROOT_ABS}/{ghost}", line=1, client=attacker))
    truth.event(t0, attacker, "use_shell",
                f"GET /{ghost}?cmd=id answered 200, repeatedly")
    truth.event(t0 + timedelta(hours=rng.randint(2, 20)), attacker,
                "cleanup", f"{ghost} removed before the webroot was copied")

    # THE LOG STILL CARRIES IT, and that half works: the access log rule is
    # about a URI and a status code and never touches the filesystem.
    truth.plant(Planted(
        kind="client", ident=attacker,
        expect_rules=["logs.upload_php"], expect_severity="high",
        note="requested PHP in an upload directory and was answered 2xx. "
             "This fires even though the file is gone, because the log rule "
             "reads the log -- it is the file-side half that cannot"))

    # The ghost itself. Expected: nothing. See the module docstring.
    truth.plant(Planted(
        kind="file", ident=f"/{ghost}",
        expect_rules=[], expect_severity="high",
        note="THE GHOST. A fatal in the error log names this path, and "
             "docs/rules.md says that case is exactly what the error-log "
             "engine is for. It produces no finding, because the resolver "
             "requires the path to resolve to an existing file. Expected "
             "rules are deliberately empty: this encodes what happens, not "
             "what is documented. If a finding ever appears here the scorer "
             "reports it under EXTRA, which is the signal that it was fixed"))
    truth.note(
        "DISCREPANCY REPRODUCED. docs/rules.md claims the error-log engine "
        "catches a file deleted before the copy was taken, and separately "
        "that a path is only written when it resolves to an existing file "
        "under a registered webroot. Both cannot hold. Measured behaviour: "
        "the fatal naming this path is counted under `unresolved` and no "
        "finding is written. The access-log side of the same compromise is "
        "unaffected and still reports.")

    # A second fatal, naming a file that IS present -- so the case proves the
    # engine is running at all. Without it, "no finding" would be
    # indistinguishable from "the engine never ran".
    survivor = f"{upload_month}/thumb-gen.php"
    case.files[survivor] = markers.CMD_INPUT
    case.added_paths.append(survivor)
    case.error_lines.append(ErrorLine(
        when=t0 + timedelta(minutes=9), level="PHP Fatal error",
        message="Uncaught Error: Call to undefined function shell_exe()",
        path=f"{common.WEBROOT_ABS}/{survivor}", line=2, client=attacker))
    truth.plant(Planted(
        kind="file", ident=f"/{survivor}",
        expect_rules=["webshell.upload_php", "webshell.cmd_input",
                      "errorlog.hard"],
        expect_severity="high",
        note="the shell the attacker forgot. It is here as a CONTROL: it "
             "proves the error-log engine ran and resolved paths in this "
             "case, so the ghost's silence is a property of the ghost and "
             "not of a job that never started"))

    noise, noisy_paths = common.warning_noise(rng.derive("errlog"), site,
                                              start, days)
    case.error_lines += noise
    common.plant_warnings(truth, noisy_paths)
    common.plant_scanners(truth, case.requests)
    common.plant_editor(truth, editor_ip, case.requests, site)
    common.plant_core_silence(truth, site)
    return case
