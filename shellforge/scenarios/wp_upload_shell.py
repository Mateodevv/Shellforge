# shellforge/scenarios/wp_upload_shell.py
"""wp-upload-shell -- the standard case, modelled on CVE-2020-25213.

WHY THIS CVE AND NOT A PRETTIER ONE. WP File Manager 6.0-6.8 shipped an
elFinder example connector with no authentication. It is the only WordPress
case in `docs/cve-log-signatures.md` where all three of these are documented
from a primary source: a distinctive exploit request line, a distinctive
follow-up request, and a real drop directory. That means the whole chain
log -> webroot -> chronology can be made consistent without inventing the
middle of it.

THE SHAPE OF THE ATTACK, and what each step is here to test:

  1. Scanner noise, days before anything.        logs.scanner_ua -- INFO, and
                                                 a precision check: a flood of
                                                 these must not redden a list.
  2. POST to connector.minimal.php.              INVISIBLE to every built-in
                                                 rule -- the path is not in an
                                                 upload directory. Only a hunt
                                                 pattern finds it, which is
                                                 exactly the point of shipping
                                                 one with the case.
  3. The shell lands in .../lib/files/.          webshell.upload_php +
                                                 webshell.cmd_input.
  4. The shell is fetched, answered 200.         logs.upload_php -- the
                                                 strongest log trace there is.
  5. Further drops in wp-content/uploads.        double_ext, php_in_image,
                                                 obfuscation.
  6. An .htaccess makes .jpg executable.         htaccess_handler, and the
                                                 persistence half of the case.
  7. A fatal names the shell.                    errorlog.hard -- a THIRD
                                                 source landing on the same
                                                 artifact, which is what
                                                 artifact-level triage is for.
  8. An iframe is injected into a post.          sqldb.iframe -- and the code
                                                 survives cleaning the files.

WHAT IS DELIBERATELY LEFT QUIET. The backup plugin really does call
`shell_exec`, and `webshell.standalone_exec` really is supposed to say so at
MEDIUM. It is planted as an expected MEDIUM and simultaneously forbidden from
producing anything HIGH -- because "this rule is allowed to speak, but only
this loudly" is a claim worth testing and one that no fixture currently makes.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from shellforge import corpus, markers
from shellforge.render.accesslog import Request
from shellforge.render.errorlog import ErrorLine
from shellforge.scenarios import Case, register
from shellforge.world import Row, SCALES

#: The vulnerable plugin, at a version inside the affected range (6.0-6.8).
PLUGIN_DIR = "wp-content/plugins/wp-file-manager"
CONNECTOR = f"/{PLUGIN_DIR}/lib/php/connector.minimal.php"
DROP_DIR = f"{PLUGIN_DIR}/lib/files"

#: Documented in Unit 42's capture of a real intrusion. Kept because a name
#: an analyst has seen before is worth more than a novel one.
SHELL_NAME = "k.php"

WEBROOT_ABS = "/var/www/html"


def _file_manager_files(version: str) -> dict:
    """The vulnerable plugin as an installation, not as a single file."""
    return {
        f"{PLUGIN_DIR}/file_folder_manager.php":
            "<?php\n"
            "/**\n"
            " * Plugin Name: WP File Manager\n"
            " * Description: Dateiverwaltung im WordPress-Backend.\n"
            f" * Version: {version}\n"
            " */\n\n"
            "if (!defined('ABSPATH')) {\n    exit;\n}\n",
        f"{PLUGIN_DIR}/readme.txt":
            f"=== WP File Manager ===\nStable tag: {version}\n",
        # The unauthenticated example connector. Inert: it carries no
        # executable surface, because what made the real one dangerous was
        # the library behind it, and that is not something to reproduce.
        f"{PLUGIN_DIR}/lib/php/connector.minimal.php":
            "<?php\n// elFinder connector example.\n"
            "return array('roots' => array());\n",
        f"{PLUGIN_DIR}/lib/files/.gitkeep": "",
    }


def _baseline(rng, site, start: datetime, days: int, per_day: int) -> list:
    """Ordinary traffic: recurring visitors, crawlers, an editor.

    THIS IS THE EXPENSIVE HALF AND THE ONE THAT MATTERS. Findings against an
    empty log prove nothing; a case is only as good as the noise the signal
    had to be found in.
    """
    out = []
    regulars = [rng.ip("visitor") for _ in range(max(6, per_day // 20))]
    crawlers = [rng.ip("noise") for _ in range(3)]
    editor_ip = rng.ip("visitor")
    urls = [u for u, _ in site.urls]
    weights = [w for _, w in site.urls]

    for day_no in range(days):
        day = start + timedelta(days=day_no)
        for _ in range(rng.randint(int(per_day * 0.7), int(per_day * 1.3))):
            ip = rng.weighted([(rng.choice(regulars), 6),
                               (rng.ip("visitor"), 3),
                               (rng.choice(crawlers), 2)])
            uri = rng.weighted(list(zip(urls, weights)))
            agent = (rng.choice(corpus.CRAWLER_UAS) if ip in crawlers
                     else rng.choice(corpus.BROWSER_UAS))
            status, size = rng.weighted([
                ((200, rng.randint(1800, 42000)), 88),
                ((304, 0), 6),
                ((301, 240), 3),
                ((404, 1180), 3),
            ])
            out.append(Request(
                when=rng.moment(day, 6, 22), ip=ip, method="GET", uri=uri,
                status=status, size=size, agent=agent,
                referer=rng.weighted([("-", 5),
                                      ("https://www.example.test/", 3)])))

        # The editor works on weekdays. Their login is what a brute-force
        # scenario later has to be distinguished FROM.
        if day.weekday() < 5 and rng.chance(0.8):
            when = rng.moment(day, 8, 17)
            agent = corpus.BROWSER_UAS[0]
            out.append(Request(when=when, ip=editor_ip, method="POST",
                               uri="/wp-login.php", status=302, size=0,
                               agent=agent))
            for i in range(rng.randint(3, 12)):
                out.append(Request(
                    when=when + timedelta(minutes=i + 1), ip=editor_ip,
                    method=rng.weighted([("GET", 4), ("POST", 1)]),
                    uri=rng.choice(["/wp-admin/", "/wp-admin/edit.php",
                                    "/wp-admin/upload.php",
                                    "/wp-admin/admin-ajax.php",
                                    "/wp-admin/post.php"]),
                    status=200, size=rng.randint(3000, 28000), agent=agent))
    return out, editor_ip


def _scanner_noise(rng, start: datetime, days: int) -> list:
    """Scans, from several addresses, answered with 404 throughout.

    Every one of these is an `logs.scanner_ua` INFO finding and NOTHING else.
    If a scan that never got a 2xx produces anything above INFO, the
    outcome-gating has broken.
    """
    out = []
    probes = ["/wp-config.php.bak", "/.env", "/wp-admin/setup-config.php",
              "/xmlrpc.php", "/wp-content/debug.log", "/.git/config",
              "/administrator/", "/phpmyadmin/", "/wp-json/wp/v2/users"]
    for _ in range(rng.randint(3, 5)):
        ip = rng.ip("noise")
        agent = rng.choice(corpus.SCANNER_UAS)
        day = start + timedelta(days=rng.randint(0, max(0, days - 1)))
        when = rng.moment(day, 0, 23)
        for i, probe in enumerate(rng.shuffled(probes)[:rng.randint(4, 9)]):
            out.append(Request(when=when + timedelta(seconds=i * 3), ip=ip,
                               method="GET", uri=probe, status=404, size=1180,
                               agent=agent))
    return out


@register("wp-upload-shell")
def build(rng, site, scale: str = "small") -> Case:
    _parts, _media, _posts, days, per_day = SCALES[scale]
    from shellforge.truth import GroundTruth, Planted

    truth = GroundTruth(seed=rng.seed, scenario="wp-upload-shell",
                        cms="wordpress", cms_version=site.version)
    case = Case(site=site, truth=truth, files=dict(site.files))

    start = datetime(2026, 1, 5, 0, 0, 0)
    # The break-in sits about two thirds in, so there is baseline on BOTH
    # sides of it. A case whose log stops at the attack answers "when did it
    # start" for free and never has to answer "and then what".
    attack_day = start + timedelta(days=int(days * 0.65))

    # --- the vulnerable plugin exists before anything happens ---------------
    fm_version = rng.choice(["6.4", "6.7", "6.8"])
    case.files.update(_file_manager_files(fm_version))
    truth.note(
        f"WP File Manager {fm_version} is installed and inside the affected "
        f"range of CVE-2020-25213 (6.0-6.8). The CMS inventory should report "
        f"this version; it is the reason the case is possible.")

    # --- 1. baseline and noise ---------------------------------------------
    baseline, editor_ip = _baseline(rng.derive("baseline"), site, start, days,
                                    per_day)
    case.requests += baseline
    case.requests += _scanner_noise(rng.derive("scanners"), start, days)
    scanner_ips = sorted({r.ip for r in case.requests
                          if r.agent in corpus.SCANNER_UAS})
    for ip in scanner_ips:
        truth.plant(Planted(
            kind="client", ident=ip,
            expect_rules=["logs.scanner_ua"], expect_severity="info",
            note="named a scanning tool in its user agent and never got a 2xx"))
        # One assertion per address, not one listing all of them: the scorer
        # matches an assertion to an artifact by identity, and a comma-joined
        # list matches nothing while looking like it covers everything.
        truth.keep_quiet(
            ip,
            rules=["logs.upload_php", "logs.sqli", "logs.traversal",
                   "logs.login_success", "logs.login_flood"],
            reason="every scan was answered 404 -- outcome gating must hold "
                   "this at INFO")

    # --- 2. the exploit request --------------------------------------------
    attacker = rng.ip("attacker")
    t0 = rng.moment(attack_day, 2, 4)
    ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like " \
         "Gecko) Chrome/98.0.4758.102 Safari/537.36"
    # Recon: does the plugin exist at all?
    case.requests.append(Request(when=t0, ip=attacker, method="GET",
                                 uri=f"/{PLUGIN_DIR}/readme.txt", status=200,
                                 size=412, agent=ua))
    # The exploit itself. 200 means the connector was reachable.
    case.requests.append(Request(when=t0 + timedelta(seconds=48), ip=attacker,
                                 method="POST", uri=CONNECTOR, status=200,
                                 size=1453, agent=ua))
    truth.event(t0 + timedelta(seconds=48), attacker, "exploit",
                f"POST {CONNECTOR} answered 200 (CVE-2020-25213)")
    truth.note(
        "The exploit request is NOT in an upload directory, so no built-in "
        "rule sees it. That is not a gap -- it is the case for the pattern "
        "library, and the hunt pattern shipped alongside this case is what "
        "should find it.")

    # --- 3. the shell lands -------------------------------------------------
    t_drop = t0 + timedelta(seconds=51)
    shell_rel = f"{DROP_DIR}/{SHELL_NAME}"
    case.files[shell_rel] = markers.CMD_INPUT
    case.added_paths.append(shell_rel)
    truth.plant(Planted(
        kind="file", ident=f"/{shell_rel}",
        expect_rules=["webshell.upload_php", "webshell.cmd_input",
                      "errorlog.hard"],
        expect_severity="high",
        note="the dropped shell: unguarded PHP in a directory whose path "
             "carries a `files` segment, executing a request parameter, and "
             "named by a fatal in the error log"))
    truth.event(t_drop, attacker, "drop_shell", shell_rel)

    # --- 4. the shell is used ----------------------------------------------
    for i in range(rng.randint(5, 11)):
        case.requests.append(Request(
            when=t_drop + timedelta(minutes=2 + i * rng.randint(1, 9)),
            ip=attacker, method=rng.weighted([("GET", 3), ("POST", 1)]),
            uri=f"/{shell_rel}?cmd={rng.choice(['id', 'uname+-a', 'ls+-la', 'whoami'])}",
            status=200, size=rng.randint(60, 900), agent=ua))
    truth.plant(Planted(
        kind="client", ident=attacker,
        expect_rules=["logs.upload_php"], expect_severity="high",
        note="requested PHP in a directory with a `files` segment and was "
             "answered 2xx -- the shell was there and was delivered"))
    truth.event(t_drop + timedelta(minutes=2), attacker, "use_shell",
                f"GET /{shell_rel}?cmd=... answered 200")

    # --- 5. further drops in the uploads tree -------------------------------
    upload_month = f"{site.upload_dir}/2026/01"
    t_more = t_drop + timedelta(minutes=rng.randint(20, 90))

    disguised = f"{upload_month}/rechnung-2026.pdf.php"
    case.files[disguised] = markers.INERT_BODY
    case.added_paths.append(disguised)
    truth.plant(Planted(
        kind="file", ident=f"/{disguised}",
        expect_rules=["webshell.double_ext"], expect_severity="high",
        note="the name carries a harmless extension in front of the real "
             "one; the body has no executable surface on purpose, so the "
             "location rule books it inert and only the name fires"))

    in_image = f"{upload_month}/banner-neu.png"
    case.files[in_image] = markers.PHP_IN_IMAGE
    case.added_paths.append(in_image)
    truth.plant(Planted(
        kind="file", ident=f"/{in_image}",
        expect_rules=["webshell.php_in_image"], expect_severity="high",
        note="real PNG magic with a PHP tag behind it -- an upload smuggled "
             "past an image check"))

    packed = f"{upload_month}/cache-warm.php"
    case.files[packed] = markers.OBFUSCATION
    case.added_paths.append(packed)
    truth.plant(Planted(
        kind="file", ident=f"/{packed}",
        expect_rules=["webshell.upload_php", "webshell.obfuscation"],
        expect_severity="high",
        note="nested decoders in an upload directory"))

    for rel in (disguised, in_image, packed):
        truth.event(t_more, attacker, "drop_file", rel)
        case.requests.append(Request(
            when=t_more + timedelta(seconds=rng.randint(30, 400)), ip=attacker,
            method="GET", uri=f"/{rel}", status=200,
            size=rng.randint(40, 600), agent=ua))

    # --- 6. persistence -----------------------------------------------------
    htaccess = f"{upload_month}/.htaccess"
    case.files[htaccess] = markers.HTACCESS_HANDLER
    case.added_paths.append(htaccess)
    truth.plant(Planted(
        kind="file", ident=f"/{htaccess}",
        expect_rules=["webshell.htaccess_handler"], expect_severity="high",
        note="makes .jpg execute as PHP in the uploads tree -- the shell can "
             "now wear an image name"))
    truth.event(t_more + timedelta(minutes=5), attacker, "persistence",
                f"{htaccess} maps .jpg to the PHP handler")

    # --- 7. the error log, third source on the same artifact ---------------
    case.error_lines.append(ErrorLine(
        when=t_drop + timedelta(minutes=14),
        level="PHP Fatal error",
        message="Uncaught Error: Call to undefined function shell_exe()",
        path=f"{WEBROOT_ABS}/{shell_rel}", line=2, client=attacker))
    # Ordinary noise, so the error log is not a list of nothing but the shell.
    # THESE ARE EXPECTED FINDINGS, NOT NOISE TO BE FORGIVEN. A warning naming
    # a legitimate plugin file is exactly what `errorlog.soft` is for, and the
    # claim worth testing is that it stays at LOW: the rule earns its weight
    # only by landing on the same artifact as something else, which here it
    # does not. A run that promotes one of these has broken that promise.
    noisy = set()
    for _ in range(rng.randint(4, 10)):
        day = start + timedelta(days=rng.randint(0, days - 1))
        slug, _name, _v = rng.choice(site.plugins)
        rel = f"wp-content/plugins/{slug}/{slug}.php"
        noisy.add(rel)
        case.error_lines.append(ErrorLine(
            when=rng.moment(day, 6, 22), level="PHP Warning",
            message="Undefined array key \"cache_ttl\"",
            path=f"{WEBROOT_ABS}/{rel}",
            line=rng.randint(20, 180)))
    for rel in sorted(noisy):
        truth.plant(Planted(
            kind="file", ident=f"/{rel}",
            expect_rules=["errorlog.soft"], expect_severity="low",
            note="a legitimate plugin throwing an ordinary warning. Reported, "
                 "because the interpreter did execute this path -- but LOW, "
                 "because that is all it says"))
    truth.note(
        "The error log names the shell with a fatal, so file, log and error "
        "log all land on one artifact. That is the case artifact-level triage "
        "exists for: three observations, one decision.")

    # --- 8. the database ----------------------------------------------------
    victim = next((r for r in site.rows if r.table == "posts"), None)
    if victim is not None:
        victim.values["post_content"] += markers.DB_IFRAME
        truth.plant(Planted(
            kind="table", ident=site.table("posts"),
            expect_rules=["sqldb.iframe"], expect_severity="medium",
            note="a zero-sized off-site iframe appended to a published post; "
                 "it survives every cleanup that only touches files"))
        truth.event(t_more + timedelta(minutes=20), attacker, "db_injection",
                    f"iframe appended to {site.table('posts')} row "
                    f"{victim.values['ID']}")

    # --- the legitimate noisemaker -----------------------------------------
    # A real backup tool. It genuinely calls shell_exec, and Shellhound is
    # genuinely supposed to say so -- at MEDIUM, once, and no louder.
    backup = "wp-content/plugins/backup-werkzeug/includes/dump.php"
    case.files[backup] = markers.STANDALONE_EXEC
    truth.plant(Planted(
        kind="file", ident=f"/{backup}",
        expect_rules=["webshell.standalone_exec"], expect_severity="medium",
        note="a legitimate admin tool. It is SUPPOSED to be reported at "
             "MEDIUM -- this entry asserts the rule speaks, and the "
             "must_not_fire entry below asserts it does not shout"))
    truth.keep_quiet(
        f"/{backup}",
        rules=["webshell.upload_php", "webshell.cmd_input",
               "webshell.eval_input", "webshell.dropper"],
        reason="guarded with ABSPATH, outside every upload directory, and the "
               "command is a constant -- nothing here is request-driven")

    # --- what must stay silent ---------------------------------------------
    truth.keep_quiet(
        "/wp-includes/functions.php",
        reason="genuine core file: bootstrap guard present, nothing "
               "executable. The oldest false-positive guard there is")
    truth.keep_quiet(
        f"/{site.upload_dir}/.htaccess",
        reason="the .htaccess WordPress itself writes (`Options -Indexes`). "
               "Only the one in the dated subdirectory was replaced -- a rule "
               "that reddens both cannot tell persistence from housekeeping")
    truth.keep_quiet(
        f"/{site.upload_dir}/index.php",
        reason="the silence-is-golden stub a CMS scatters by the thousand. "
               "In an upload directory, and correctly booked inert")
    truth.keep_quiet(
        editor_ip,
        rules=["logs.login_success", "logs.login_flood"],
        reason="the editor logs in on most weekdays and is redirected each "
               "time. One login is not a flood; the threshold is 30")

    # --- the hunt pattern this case is meant to be searched with -----------
    case.hunt_patterns = [{
        "name": "WP File Manager unauthenticated connector (CVE-2020-25213)",
        "advisory": "CVE-2020-25213",
        "paths": [CONNECTOR, f"/{DROP_DIR}/"],
        "match": "any",
        "description":
            "A request to the elFinder example connector shipped by WP File "
            "Manager 6.0-6.8, or to the directory it writes into. A hit "
            "proves the request was made; the status code decides the rest. "
            "It does NOT prove the plugin was vulnerable at the time -- check "
            "the version in the CMS inventory.",
    }]

    truth.event(start, "system", "baseline_begins",
                f"{days} days of ordinary traffic")
    return case
