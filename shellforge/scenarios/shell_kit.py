# shellforge/scenarios/shell_kit.py
"""shell-kit -- a whole toolkit, not a single dropped file.

Real intrusions rarely leave one shell. A kit arrives: a loader, an uploader,
a couple of obfuscated stagers, and a persistence line in an `.htaccess` so
that removing the visible files changes nothing.

THE KIT HIDES IN THE THEME, NOT IN UPLOADS. That is realistic -- a theme
directory is writable on many installations, is full of PHP already, and is
the last place anybody looks. It also makes this case exercise something the
upload scenario cannot: the CONTENT rules on their own, without the location
rule firing alongside and doing the work for them. Each file below trips
exactly one content rule and nothing else.

Two files are the exception and belong in an upload directory, because the
rules they exercise are about location rather than about content:

    too_large   PHP over 5 MB where uploads land -- not assessed, but
                reported. An unexamined find must not be passed over.
    unreadable  something the scanner could not open at all. POSIX ONLY, via
                `chmod 000`; see the long comment at the plant for why no
                portable trick works and why Windows gets a note instead of
                a quiet gap.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta

from shellforge import markers
from shellforge.render.accesslog import Request
from shellforge.render.errorlog import ErrorLine
from shellforge.scenarios import Case, common, register
from shellforge.truth import GroundTruth, Planted
from shellforge.world import SCALES

#: rule id -> file name in the kit. One rule each; the marker module asserts
#: they stay single-rule probes.
KIT = [
    ("webshell.eval_input", "class-loader.php"),
    ("webshell.var_func", "class-dispatch.php"),
    ("webshell.create_function", "legacy-callback.php"),
    ("webshell.callback_input", "class-router.php"),
    ("webshell.upload_dest", "upload-handler.php"),
    ("webshell.dropper", "media-sync.php"),
    ("webshell.preg_e", "template-filter.php"),
    ("webshell.chr_concat", "i18n-strings.php"),
    ("webshell.goto", "route-table.php"),
    ("webshell.hex_octal", "charmap.php"),
    ("webshell.no_php", "kontoprufung.php"),
]


@register("shell-kit")
def build(rng, site, scale: str = "small") -> Case:
    _p, _m, _po, days, per_day = SCALES[scale]
    truth = GroundTruth(seed=rng.seed, scenario="shell-kit",
                        cms=site.kind, cms_version=site.version)
    case = Case(site=site, truth=truth, files=dict(site.files))
    start = datetime(2026, 1, 5)
    attack_day = start + timedelta(days=int(days * 0.55))

    requests, editor_ip = common.baseline(rng.derive("baseline"), site, start,
                                          days, per_day)
    case.requests = requests + common.scanner_noise(rng.derive("scanners"),
                                                    start, days)

    # `inc`, deliberately not `assets`: `assets` is one of the writable-upload
    # segments, and the point of this directory is that the location rule does
    # NOT fire here. The theme directory itself comes from the profile --
    # `wp-content/themes/x` in WordPress, `templates/x` in Joomla.
    kit_dir = f"{site.theme_dir}/inc"
    t0 = rng.moment(attack_day, 2, 4)

    for rule_id, name in KIT:
        body = markers.php_marker(rule_id)
        rel = f"{kit_dir}/{name}"
        case.files[rel] = body
        case.added_paths.append(rel)
        truth.plant(Planted(
            kind="file", ident=f"/{rel}",
            expect_rules=[rule_id],
            # NAMED, not derived. `create_function` was HIGH until it was
            # split and `callback_input` carved out of it; a set spelled as
            # "everything except the obfuscation ones" would have quietly
            # stayed wrong.
            expect_severity="high" if rule_id in {
                "webshell.eval_input", "webshell.var_func",
                "webshell.callback_input", "webshell.dropper",
                "webshell.preg_e"} else "medium",
            note=f"part of the kit; exists to trip {rule_id} and nothing "
                 f"else. Outside every upload directory, so the location "
                 f"rule stays out of it"))
    truth.event(t0, "unknown", "drop_kit",
                f"{len(KIT)} files into {kit_dir}")

    # --- persistence: the line that outlives the files ---------------------
    case.files[".htaccess"] = markers.HTACCESS_PREPEND
    case.added_paths.append(".htaccess")
    truth.plant(Planted(
        kind="file", ident="/.htaccess",
        expect_rules=["webshell.htaccess_prepend"], expect_severity="high",
        note="loads an extra file on EVERY request. Delete every shell in "
             "the kit and this still runs -- which is why it is the finding "
             "that decides whether remediation worked"))
    truth.event(t0 + timedelta(minutes=3), "unknown", "persistence",
                "auto_prepend_file at the webroot root")

    # --- the two location cases, in an upload directory --------------------
    upload_month = f"{site.upload_dir}/2026/01"

    big = f"{upload_month}/session-cache.php"
    # Just over the 5 MB limit. Padding is a comment, so nothing in it can
    # trip a content rule even if the size check were removed.
    case.files[big] = ("<?php\n$_GET;\n"
                       + "# padding, deliberately inert\n" * 190_000)
    case.added_paths.append(big)
    truth.plant(Planted(
        kind="file", ident=f"/{big}",
        expect_rules=["webshell.too_large"], expect_severity="high",
        note="over 5 MB in an upload directory: too large to inspect, so it "
             "is reported UNASSESSED rather than passed over. What could not "
             "be judged must not disappear"))

    # THE ONE RULE THAT CANNOT BE REACHED PORTABLY. It fires when the scanner
    # cannot open a file at all, which needs a real filesystem error, not a
    # contrived file:
    #
    #   a directory named `.php`  -- the walk yields FILES, so the directory
    #                                is never handed to the scanner. (This
    #                                looks like it works if you call
    #                                `scan_file` directly. It does not.)
    #   a dangling symlink        -- `is_file()` is False, so the walk skips
    #                                it, and Windows refuses to create one
    #                                without privileges anyway.
    #   chmod 000                 -- works on POSIX, and is what the field
    #                                case actually looks like.
    #
    # Windows has no equivalent that a generator can rely on, so the plant is
    # skipped there and the ground truth says so rather than quietly claiming
    # coverage this platform does not have.
    if os.name == "posix":
        unreadable = f"{upload_month}/thumb-cache.php"
        case.files[unreadable] = markers.CMD_INPUT
        case.added_paths.append(unreadable)
        case.unreadable_paths.append(unreadable)
        truth.plant(Planted(
            kind="file", ident=f"/{unreadable}",
            expect_rules=["webshell.unreadable"], expect_severity="high",
            note="PHP in an upload directory that could not be read at all. "
                 "In the field the usual cause is the virus scanner on the "
                 "analysis machine holding the file shut -- and it holds the "
                 "CLEAREST finds shut, so a case that dropped these silently "
                 "would lose exactly the evidence it needs"))
    else:
        truth.note(
            "webshell.unreadable is NOT exercised on this platform. The rule "
            "needs a genuine read error, and Windows offers no way for a "
            "generator to produce one reliably (chmod 0 is ignored for the "
            "owner; symlinks need privileges; a directory named .php is "
            "never handed to the scanner because the walk yields files). The "
            "rule is covered on POSIX, which is what CI runs.")

    # --- the kit gets used -------------------------------------------------
    loader = rng.ip("attacker")
    for i in range(rng.randint(4, 9)):
        case.requests.append(Request(
            when=t0 + timedelta(minutes=8 + i * rng.randint(2, 20)),
            ip=loader, method=rng.weighted([("POST", 3), ("GET", 1)]),
            uri=f"/{kit_dir}/class-loader.php", status=200,
            size=rng.randint(60, 1400), agent=common.QUIET_UA))
    truth.keep_quiet(
        loader, rules=["logs.upload_php"],
        reason="the kit sits in the THEME, not in an upload directory, so "
               "the log rule correctly says nothing. This case belongs to "
               "the webroot scanner, and the log cannot carry it")
    truth.event(t0 + timedelta(minutes=8), loader, "use_kit",
                f"POST /{kit_dir}/class-loader.php answered 200")

    # --- the error log, on a file that IS in the copy ----------------------
    case.error_lines.append(ErrorLine(
        when=t0 + timedelta(minutes=21), level="PHP Parse error",
        message="syntax error, unexpected end of file",
        path=f"{common.WEBROOT_ABS}/{kit_dir}/charmap.php", line=2,
        client=loader))
    # charmap.php now carries a content finding AND an error-log finding.
    for planted in truth.planted:
        if planted.ident.endswith("/charmap.php"):
            planted.expect_rules.append("errorlog.hard")
            planted.note += ("; also crashed on its own payload, so the error "
                             "log lands a second observation on it")

    noise, noisy_paths = common.warning_noise(rng.derive("errlog"), site,
                                              start, days)
    case.error_lines += noise
    common.plant_warnings(truth, noisy_paths)
    common.plant_scanners(truth, case.requests)
    common.plant_editor(truth, editor_ip, case.requests, site)
    common.plant_core_silence(truth, site)
    truth.note(
        "Every file in the kit trips exactly one content rule. If one of them "
        "starts producing two, either a rule widened or a marker drifted -- "
        "and the scorer reports it under EXTRA rather than as a failure, "
        "because a rule catching more is not automatically a rule going "
        "wrong.")
    return case
