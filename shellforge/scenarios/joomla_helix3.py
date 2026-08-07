# shellforge/scenarios/joomla_helix3.py
"""joomla-helix3 -- CVE-2026-49049, in the two shapes it actually takes.

JoomShaper's Helix3 template framework shipped an unauthenticated com_ajax
handler that allowed path-traversal file WRITE and DELETE plus overwriting
template parameters. Verified details are in `docs/cve-log-signatures.md`;
two of them matter here and are worth stating because the obvious guesses are
wrong:

  The routing parameter is `plugin=helix3`, NOT `helix=ajax`. Joomla's
  com_ajax dispatcher takes `option=com_ajax&plugin=<name>&format=json` and
  fires `onAjax<Name>` from the `ajax` plugin group, where Helix3 installs as
  `plugins/ajax/helix3/`.

  It is a WRITE primitive, not a file download. The obvious reading of "Helix3
  vulnerability" is an LFI. It is the opposite direction.

TWO VARIANTS, AND THE SECOND IS WHY THIS SCENARIO EXISTS:

  rce        `data[layoutName]=../../up.php` escapes the template directory,
             and Helix appends `.json` -- so what lands in the webroot is
             `up.php.json`. A double extension, which is a rule Shellhound
             has, on a file whose real extension is not the last one.

  defacement The payload goes into the DATABASE instead: custom JS in
             `#__template_styles.params`, which every page then serves.
             **NOTHING IS WRITTEN TO DISK.** The webroot is byte-identical to
             a clean installation, and the only evidence is one com_ajax POST
             in the access log plus one row in the dump.

The defacement variant is the case a file-centric scanner cannot see at all,
and the reason a DFIR tool reads three kinds of evidence rather than one.

THE EXPLOIT REQUEST ITSELF IS NOT A FINDING. `index.php` is not in an upload
directory and com_ajax answers 200 whether the call worked or not, so no
built-in rule fires on it and none should -- 200 here means "the handler
exists", not "it succeeded". That is what the hunt pattern shipped with the
case is for.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from shellforge import markers
from shellforge.render.accesslog import Request
from shellforge.render.errorlog import ErrorLine
from shellforge.scenarios import Case, common, register
from shellforge.truth import GroundTruth, Planted
from shellforge.world import Row, SCALES

#: The real routing URI. Fixed part is everything before the payload, which
#: travels in the POST body and is therefore invisible in the log.
AJAX = "/index.php?option=com_ajax&plugin=helix3&format=json"

#: Helix3 appends `.json` to the layout name, so `../../up.php` becomes
#: `up.php.json` in the webroot. The `.php` is not the last extension, which
#: is exactly what `webshell.double_ext` is about -- and it executes anyway
#: wherever Apache is configured with a multi-extension handler.
DROPPED = "up.php.json"

#: Observed in the defacement wave: a full-viewport overlay plus a title
#: rewrite. Inert here -- it is a string in a database column, and a string is
#: all it ever was.
DEFACE_JS = ('<script>document.title = "hacked by example";'
             'document.write("<div style=\\"position:fixed;inset:0;'
             'z-index:2147483647\\"></div>");</script>')


def _common_setup(rng, site, scale, name):
    _p, _m, _po, days, per_day = SCALES[scale]
    truth = GroundTruth(seed=rng.seed, scenario=name,
                        cms=site.kind, cms_version=site.version)
    case = Case(site=site, truth=truth, files=dict(site.files))
    start = datetime(2026, 1, 5)

    # The vulnerable framework has to actually be installed, or the case
    # describes an intrusion through something that is not there.
    tpl = "shaper_helix3"
    case.files[f"plugins/ajax/helix3/helix3.php"] = (
        "<?php\ndefined('_JEXEC') or die;\n\n"
        "class PlgAjaxHelix3 extends JPlugin\n{\n"
        "    public function onAjaxHelix3()\n    {\n"
        "        return array('status' => 'ok');\n    }\n}\n")
    case.files["plugins/ajax/helix3/helix3.xml"] = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<extension type="plugin" group="ajax" method="upgrade">\n'
        '\t<name>System - Helix3</name>\n\t<version>3.0.9</version>\n'
        '</extension>\n')
    if not any(r.table == "template_styles" and
               r.values.get("template") == tpl for r in site.rows):
        site.rows.append(Row(table="template_styles", values={
            "id": 9, "template": tpl, "client_id": 0, "home": "1",
            "title": "Helix3 - Default",
            "params": '{"logo":"images/logo.png","preset":"preset1"}'}))
    site.rows.append(Row(table="extensions", values={
        "extension_id": 30001, "name": "System - Helix3", "type": "plugin",
        "element": "helix3", "folder": "ajax", "client_id": 0, "enabled": 1,
        "manifest_cache": '{"name":"System - Helix3","version":"3.0.9"}',
        "params": "{}"}))
    truth.note(
        "Helix3 3.0.9 is installed as an ajax plugin and is inside the "
        "affected range of CVE-2026-49049 (1.0 to ~3.1.0, fixed in 3.1.1). "
        "The CMS inventory should name it; it is the reason the case is "
        "possible.")

    requests, editor_ip = common.baseline(rng.derive("baseline"), site, start,
                                          days, per_day)
    case.requests = requests + common.scanner_noise(rng.derive("scanners"),
                                                    start, days)

    case.hunt_patterns = [{
        "name": "JoomShaper Helix3 unauthenticated com_ajax (CVE-2026-49049)",
        "advisory": "CVE-2026-49049",
        "paths": [AJAX, "/index.php?option=com_ajax&plugin=helix3"],
        "match": "any",
        "description":
            "A request to Helix3's com_ajax handler. A hit proves the request "
            "was made and that the plugin was routed; it does NOT prove the "
            "call succeeded -- com_ajax answers 200 with JSON either way, so "
            "the status code settles nothing here. Check the Helix3 version "
            "in the CMS inventory, and look for a file with a double "
            "extension in the webroot or for changed custom JS in "
            "#__template_styles.",
    }]
    return case, truth, start, days, editor_ip


@register("joomla-helix3", cms=("joomla",))
def build_rce(rng, site, scale: str = "small") -> Case:
    case, truth, start, days, editor_ip = _common_setup(
        rng, site, scale, "joomla-helix3")
    attack_day = start + timedelta(days=int(days * 0.6))
    attacker = rng.ip("attacker")
    t0 = rng.moment(attack_day, 1, 4)

    # Recon: is the plugin routed at all? Same URI, harmless call.
    case.requests.append(Request(when=t0, ip=attacker, method="GET", uri=AJAX,
                                 status=200, size=27, agent=common.QUIET_UA))
    # The exploit. Payload (`data[action]=save`, `data[layoutName]=../../up.php`,
    # `data[content]=...`) is in the POST body and never appears in the log.
    case.requests.append(Request(when=t0 + timedelta(seconds=63), ip=attacker,
                                 method="POST", uri=AJAX, status=200,
                                 size=41, agent=common.QUIET_UA))
    truth.keep_quiet(
        attacker, rules=["logs.sqli", "logs.traversal"],
        reason="the traversal is in `data[layoutName]` in the POST body, not "
               "in the URI. A tool that reported a traversal here would be "
               "reading something the access log does not contain")
    truth.event(t0 + timedelta(seconds=63), attacker, "exploit",
                f"POST {AJAX} answered 200 (CVE-2026-49049)")

    # --- what landed --------------------------------------------------------
    # THE FILE SHELLHOUND CANNOT SEE. Measured against all three engines:
    #
    #   webshell.double_ext  DOUBLE_EXT_RE is
    #                        `\.(jpe?g|png|...|xml)\.(php\d?|phtml|phar|inc)$`
    #                        -- harmless extension THEN executable one. This
    #                        file is the other way round (`.php.json`), so it
    #                        does not match.
    #   content rules        `.json` is not in PHP_EXTS, so the file is never
    #                        opened for scanning at all.
    #   errorlog.hard        _PATH_RE stops the captured path at `.php`, so
    #                        the fatal resolves to `/var/www/html/up.php`,
    #                        which does not exist -- counted as `unresolved`.
    #
    # It is nonetheless executable: Apache's mod_mime dispatches on ANY
    # extension present in the name, which is exactly why the exploit chose
    # this shape. So a documented, in-the-wild artifact produces nothing from
    # any of the three engines. Expected rules are deliberately empty; this
    # encodes what happens, not what one would want. A fix will show up under
    # EXTRA, which is informational and will not turn a build red.
    case.files[DROPPED] = markers.CMD_INPUT
    case.added_paths.append(DROPPED)
    truth.plant(Planted(
        kind="file", ident=f"/{DROPPED}",
        expect_rules=[], expect_severity="high",
        note="THE INVISIBLE ARTIFACT. Helix3 appends `.json` to the layout "
             "name, so `../../up.php` arrives as `up.php.json`. The double- "
             "extension rule only matches harmless-then-executable, `.json` "
             "is not scanned for content, and the error-log parser truncates "
             "the path at `.php` and then cannot resolve it. Nothing fires"))
    truth.note(
        "DETECTION GAP REPRODUCED. `up.php.json` is invisible to all three "
        "engines at once -- the double-extension rule matches only "
        "harmless-then-executable names, `.json` is not in PHP_EXTS so the "
        "content rules never open the file, and the error-log path regex "
        "stops at `.php` and resolves to a file that does not exist. The "
        "file is still executable under mod_mime, which is why the exploit "
        "writes it in that shape.")
    truth.event(t0 + timedelta(seconds=66), attacker, "drop_shell", DROPPED)

    # --- the control, and the half that IS caught --------------------------
    # The same wave also used Helix3's image-upload sub-issue, which lands
    # under /images/. Without this the case would be "nothing was found",
    # which is indistinguishable from "the engines never ran".
    conventional = f"{site.upload_dir}/galerie/cache-idx.php"
    case.files[conventional] = markers.CMD_INPUT
    case.added_paths.append(conventional)
    truth.plant(Planted(
        kind="file", ident=f"/{conventional}",
        expect_rules=["webshell.upload_php", "webshell.cmd_input",
                      "errorlog.hard"],
        expect_severity="high",
        note="the conventionally-named shell from the same intrusion, in "
             "Joomla's images tree. It is here as a CONTROL: it proves every "
             "engine ran and resolved paths in this case, so the silence "
             "about up.php.json is a property of that file and not of a job "
             "that never started"))
    truth.event(t0 + timedelta(seconds=70), attacker, "drop_shell",
                conventional)
    for i in range(rng.randint(3, 7)):
        case.requests.append(Request(
            when=t0 + timedelta(minutes=5 + i * rng.randint(2, 11)),
            ip=attacker, method="GET", uri=f"/{conventional}?cmd=id",
            status=200, size=rng.randint(40, 600), agent=common.QUIET_UA))
    case.error_lines.append(ErrorLine(
        when=t0 + timedelta(minutes=19), level="PHP Fatal error",
        message="Uncaught Error: Call to undefined function shell_exe()",
        path=f"{common.WEBROOT_ABS}/{conventional}", line=2, client=attacker))

    for i in range(rng.randint(4, 10)):
        case.requests.append(Request(
            when=t0 + timedelta(minutes=3 + i * rng.randint(2, 13)),
            ip=attacker, method=rng.weighted([("GET", 3), ("POST", 1)]),
            uri=f"/{DROPPED}?cmd={rng.choice(['id', 'uname+-a', 'ls'])}",
            status=200, size=rng.randint(40, 700), agent=common.QUIET_UA))
    truth.plant(Planted(
        kind="client", ident=attacker,
        expect_rules=["logs.upload_php"], expect_severity="high",
        note="the log rule catches this intrusion through the SECOND shell, "
             "the one in the images tree. Requests for `up.php.json` at the "
             "webroot root produce nothing, because that path carries no "
             "upload segment -- so here the log is the only engine that sees "
             "the compromise at all"))
    truth.event(t0 + timedelta(minutes=3), attacker, "use_shell",
                f"GET /{DROPPED}?cmd=... answered 200")

    noise, noisy_paths = common.warning_noise(rng.derive("errlog"), site,
                                              start, days)
    case.error_lines += noise
    common.plant_warnings(truth, noisy_paths)

    common.plant_scanners(truth, case.requests)
    common.plant_editor(truth, editor_ip)
    common.plant_core_silence(truth, site)
    truth.note(
        "The exploit request produces NO finding, and must not: `index.php` "
        "is not an upload directory and com_ajax answers 200 either way. "
        "Finding it is the pattern library's job, and the case ships the "
        "pattern.")
    return case


@register("joomla-helix3-deface", cms=("joomla",))
def build_deface(rng, site, scale: str = "small") -> Case:
    case, truth, start, days, editor_ip = _common_setup(
        rng, site, scale, "joomla-helix3-deface")
    attack_day = start + timedelta(days=int(days * 0.6))
    attacker = rng.ip("attacker")
    t0 = rng.moment(attack_day, 2, 5)

    case.requests.append(Request(when=t0, ip=attacker, method="GET", uri=AJAX,
                                 status=200, size=27, agent=common.QUIET_UA))
    case.requests.append(Request(when=t0 + timedelta(seconds=41), ip=attacker,
                                 method="POST", uri=AJAX, status=200,
                                 size=39, agent=common.QUIET_UA))
    truth.event(t0 + timedelta(seconds=41), attacker, "exploit",
                f"POST {AJAX} answered 200 (CVE-2026-49049)")

    # --- the payload goes into the template style, not onto disk -----------
    style = next((r for r in case.site.rows
                  if r.table == "template_styles"
                  and r.values.get("template") == "shaper_helix3"), None)
    if style is None:
        style = next(r for r in case.site.rows if r.table == "template_styles")
    style.values["params"] = (
        '{"logo":"images/logo.png","preset":"preset1",'
        '"before_head":"' + DEFACE_JS.replace('"', '\\"') + '"}')
    # A SECOND style row carries the document.write on its own. The engine
    # reports one finding per rule per ROW, so a value containing both a
    # `<script` and a `document.write(` yields only the first -- the two
    # compete for the same row. Joomla installations really do have several
    # template styles, and an attacker overwriting all of them is the norm,
    # so splitting them is more faithful rather than less.
    case.site.rows.append(Row(table="template_styles", values={
        "id": 12, "template": "shaper_helix3", "client_id": 0, "home": "0",
        "title": "Helix3 - Landing",
        "params": '{"preset":"preset2","custom_js":'
                  '"document.write(unescape(\\"%3Cdiv%3E\\"));"}'}))
    truth.plant(Planted(
        kind="table", ident=case.site.table("template_styles"),
        expect_rules=["sqldb.script", "sqldb.document_write"],
        expect_severity="medium",
        note="custom JS written into the template styles' `params`, which "
             "Joomla renders into the head of EVERY page. This is the whole "
             "compromise -- there is no file to find"))
    truth.event(t0 + timedelta(seconds=44), attacker, "db_injection",
                "custom JS into #__template_styles.params")

    # The visible consequence: visitors keep arriving and keep being served
    # the injected page. Nothing in the log distinguishes those requests.
    truth.keep_quiet(
        attacker,
        rules=["logs.upload_php", "logs.sqli", "logs.traversal"],
        reason="two requests to a legitimate routing endpoint, both answered "
               "200. There is nothing else, and the log rules must not "
               "invent anything")

    common.plant_scanners(truth, case.requests)
    common.plant_editor(truth, editor_ip)
    common.plant_core_silence(truth, site)
    truth.note(
        "THE WEBROOT IS CLEAN. Not lightly touched -- byte-identical to a "
        "correct installation of this Joomla version. Any file finding in "
        "this case is a false positive, and the reference copy is here to "
        "make that checkable: a webroot diff must report nothing at all.")
    truth.note(
        "This is the variant a file-centric scanner cannot see. It is also "
        "the one that survives every remediation that only replaces files, "
        "which is why the database engine and the access log have to stand "
        "on their own.")
    return case
