# shellforge/scenarios/common.py
"""Traffic and noise every scenario needs.

Extracted rather than copied, for the reason every duplicated fixture
eventually teaches: the baseline is the part that measures precision, and two
copies of it drift until one scenario is quietly testing a different site
from the other.

Nothing here knows about an attack. A scenario asks for a working site and
then does something to it.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from shellforge import corpus
from shellforge.render.accesslog import Request
from shellforge.render.errorlog import ErrorLine

WEBROOT_ABS = "/var/www/html"

#: A user agent that is a plain browser, for an attacker who is not announcing
#: themselves. Deliberately unremarkable: an attacker with a scanner UA is a
#: case the tool solves for free.
QUIET_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like "
            "Gecko) Chrome/98.0.4758.102 Safari/537.36")


def work_paths(site):
    """Admin paths that are NOT the login endpoint.

    IN JOOMLA THEY ARE THE SAME URL. `/administrator/index.php` is both the
    login form and the control panel, so "a few minutes of editing after
    signing in" was posting to the login endpoint and being counted as thirty
    more login attempts. WordPress hides the problem because `wp-login.php`
    and `wp-admin/` are different paths.

    That ambiguity is real and not the generator's to solve -- a Joomla
    access log genuinely cannot tell a login POST from a save-article POST by
    URI alone. What the generator CAN do is not manufacture it: real admin
    work goes to `index.php?option=com_...`, which is a distinct URI, and
    that is what these are.
    """
    return [p for p in site.admin_paths if p != site.login_path] \
        or site.admin_paths


def baseline(rng, site, start: datetime, days: int, per_day: int):
    """Ordinary traffic: recurring visitors, crawlers, an editor at work.

    Returns (requests, editor_ip). THIS IS THE EXPENSIVE HALF AND THE ONE
    THAT MATTERS -- findings against an empty log prove nothing; a case is
    only as good as the noise the signal had to be found in.
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

        # The editor works on weekdays. Their login is what a brute force has
        # to be distinguished FROM -- one redirect after one POST is a person
        # signing in, and must never reach the flood threshold.
        if day.weekday() < 5 and rng.chance(0.8):
            when = rng.moment(day, 8, 17)
            agent = corpus.BROWSER_UAS[0]
            out.append(Request(when=when, ip=editor_ip, method="POST",
                               uri=site.login_path, status=302, size=0,
                               agent=agent))
            for i in range(rng.randint(3, 12)):
                out.append(Request(
                    when=when + timedelta(minutes=i + 1), ip=editor_ip,
                    method=rng.weighted([("GET", 4), ("POST", 1)]),
                    uri=rng.choice(work_paths(site)),
                    status=200, size=rng.randint(3000, 28000), agent=agent))
    return out, editor_ip


def scanner_noise(rng, start: datetime, days: int):
    """Scans from several addresses, answered 404 throughout.

    Every one is a `logs.scanner_ua` INFO finding and NOTHING else. A scan
    that never got a 2xx producing anything above INFO means the outcome
    gating has broken -- which is why every scenario carries some.
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


def plant_scanners(truth, requests):
    """Record every scanner address as an expected INFO, and forbid more.

    One assertion per address, not one listing all of them: the scorer matches
    an assertion to an artifact by identity, and a comma-joined list matches
    nothing while looking like it covers everything.
    """
    from shellforge.truth import Planted
    ips = sorted({r.ip for r in requests if r.agent in corpus.SCANNER_UAS})
    for ip in ips:
        truth.plant(Planted(
            kind="client", ident=ip,
            expect_rules=["logs.scanner_ua"], expect_severity="info",
            note="named a scanning tool in its user agent and never got a 2xx"))
        truth.keep_quiet(
            ip,
            rules=["logs.upload_php", "logs.sqli", "logs.traversal",
                   "logs.login_success", "logs.login_flood"],
            reason="every scan was answered 404 -- outcome gating must hold "
                   "this at INFO")
    return ips


#: The documented threshold of `logs.login_flood` and `logs.login_success`:
#: thirty login POSTs from one address, plus a 3xx for the second rule.
#:
#: THIS IS AN EXPECTATION, NOT A DETECTOR. Shellforge does not decide who is
#: flooding; it counts what it generated so the ground truth can predict what
#: a correct run reports. Naming the number is the same kind of knowledge as
#: naming a rule id, which `expect_rules` does on every line.
LOGIN_THRESHOLD = 30


def login_rules_for(site, login_count: int):
    """Which brute-force rules a client with this many logins should produce.

    TWO CONDITIONS, AND THE SECOND IS CMS-DEPENDENT.

    `logs.login_flood` needs thirty login POSTs from one address. That is
    length-dependent and nothing else: an administrator signing in once every
    working morning crosses it after about six weeks.

    `logs.login_success` needs the flood PLUS a 2xx from the authenticated
    backend -- something an unauthenticated client cannot obtain. That
    condition replaced an earlier one ("plus a redirect") after real case data
    showed Joomla answering every login POST with a 303 regardless of whether
    the credentials were right, so a client with 121 failures was reported as
    a break-in. The replacement is correct.

    IT IS ALSO JOOMLA-SHAPED. `AUTHENTICATED_AREA_RE` matches
    `/administrator/index.php?...option=com_...` and nothing else, so no
    WordPress URL can satisfy it -- `/wp-admin/` is not recognised. On a
    WordPress case the flood half still fires and the success half cannot,
    which means the only HIGH log rule about a successful break-in is
    unreachable there. `Site.authenticated_area` is empty for exactly that
    reason, and this function reads it rather than assuming.
    """
    if login_count < LOGIN_THRESHOLD:
        return []
    rules = ["logs.login_flood"]
    if site is not None and site.authenticated_area:
        rules.append("logs.login_success")
    return rules


def plant_editor(truth, editor_ip, requests=(), site=None):
    """The site's own editor, and what happens to them on a long log.

    Counting rather than asserting: six days of traffic and the editor signs
    in a handful of times and stays silent, as they should; sixty days and
    the same person crosses thirty POSTs. A fixed assertion either way would
    pass at one scale and flip at another, which is how a suite becomes
    flaky. `long-tail-admin` reproduces the crossover on purpose.
    """
    from shellforge.truth import Planted
    login_path = getattr(site, "login_path", None)
    logins = [r for r in requests
              if r.ip == editor_ip and r.method == "POST"
              and (login_path is None or r.uri == login_path)]
    rules = login_rules_for(site, len(logins))

    if not rules:
        truth.keep_quiet(
            editor_ip,
            rules=["logs.login_success", "logs.login_flood"],
            reason=f"the editor signed in {len(logins)} times over the whole "
                   f"log. One login is not a flood; the threshold is "
                   f"{LOGIN_THRESHOLD}")
        return

    truth.plant(Planted(
        kind="client", ident=editor_ip,
        expect_rules=rules,
        expect_severity="high" if "logs.login_success" in rules else "medium",
        note=f"THE SITE'S OWN EDITOR. {len(logins)} logins over the length of "
             f"this log, one per working morning -- past the threshold of "
             f"{LOGIN_THRESHOLD} purely because the log is long. Nothing here "
             f"is an attack"))
    if "logs.login_success" not in rules:
        truth.keep_quiet(
            editor_ip, rules=["logs.login_success"],
            reason="no 2xx from a recognised authenticated backend area, so "
                   "the flood stays a flood. On this CMS that is not a "
                   "judgement about the traffic -- see the note")
    truth.note(
        f"SCALE-DEPENDENT THRESHOLD. `logs.login_flood` counts login POSTs "
        f"per address with no time window, so {LOGIN_THRESHOLD} is a function "
        f"of how long the log is. This editor made {len(logins)} ordinary "
        f"logins. On a six-day log the same behaviour is silent. See "
        f"`long-tail-admin`.")


def warning_noise(rng, site, start: datetime, days: int, count=(4, 10)):
    """Ordinary PHP warnings naming legitimate plugin files.

    NOT noise to be forgiven -- these are expected `errorlog.soft` findings,
    and the claim worth testing is that they stay at LOW. The rule earns its
    weight only by landing on the same artifact as something else, which here
    it does not.
    """
    lines, touched = [], set()
    for _ in range(rng.randint(*count)):
        day = start + timedelta(days=rng.randint(0, max(0, days - 1)))
        # The profile carries where its extensions live; spelling it out here
        # would make every scenario using this helper a WordPress scenario.
        _slug, _name, _v, rel = rng.choice(site.plugins)
        touched.add(rel)
        lines.append(ErrorLine(
            when=rng.moment(day, 6, 22), level="PHP Warning",
            message='Undefined array key "cache_ttl"',
            path=f"{WEBROOT_ABS}/{rel}", line=rng.randint(20, 180)))
    return lines, sorted(touched)


def plant_warnings(truth, paths):
    from shellforge.truth import Planted
    for rel in paths:
        truth.plant(Planted(
            kind="file", ident=f"/{rel}",
            expect_rules=["errorlog.soft"], expect_severity="low",
            note="a legitimate plugin throwing an ordinary warning. Reported, "
                 "because the interpreter did execute this path -- but LOW, "
                 "because that is all it says"))


def plant_core_silence(truth, site):
    """The false-positive guards every scenario shares.

    NAMED BY THE PROFILE, not spelled out here. `wp-includes/functions.php`
    does not exist in a Joomla installation, and a guard that silently applies
    to no file is worse than no guard: the assertion passes, and nobody
    notices it stopped asserting anything.
    """
    truth.keep_quiet(
        site.guarded_core,
        reason="genuine core file: bootstrap guard present, nothing "
               "executable. The oldest false-positive guard there is")
    for rel in site.quiet_upload_files:
        truth.keep_quiet(
            f"/{rel}",
            reason="ships with the CMS and lives in the upload tree. A rule "
                   "that reddens these cannot tell an installation from what "
                   "was put into it")
