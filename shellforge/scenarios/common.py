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

#: The site's own host name, for referers. Ends in `.test`
#: (RFC 6761) like every other domain this generator emits.
_HOST = "www.example.test"

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


#: Relative traffic per hour of the day. MEASURED SHAPE, not invented: two
#: real logs had a busiest-to-quietest ratio of 8.8x and 6.1x. This generator
#: used to emit nothing at all between 23:00 and 06:00, giving a ratio of 204x
#: -- a night floor of zero, which no site on the internet has, and which
#: would let any quiet-window detector look brilliant here and fail in the
#: field.
_HOURLY = [
    0.24, 0.19, 0.17, 0.16, 0.18, 0.28,      # 00-05
    0.35, 0.62, 0.85, 0.95, 1.00, 0.98,      # 06-11
    0.90, 0.92, 0.95, 0.93, 0.88, 0.80,      # 12-17
    0.75, 0.72, 0.66, 0.55, 0.40, 0.26,      # 18-23
]

#: Query strings a real page view carries. Deliberately harmless: nothing here
#: may resemble an injection or a traversal, or the baseline would start
#: producing the findings the scenarios are trying to measure.
_QUERIES = ["?utm_source=newsletter&utm_medium=email", "?page=2", "?page=3",
            "?s=werkzeug", "?s=oeffnungszeiten", "?ref=partnerseite",
            "?fbclid=IwAR2xQ", "?gclid=Cj0KCQjw", "?lang=de", "?print=1"]


def _page_status_size(rng):
    """A status and a size for a page view, in the proportions real logs have.

    `None` means the server wrote `-`. That is a THIRD STATE, not zero: 12-13%
    of lines in two real logs carry it, on one of them for `200` responses
    too. A generator that always writes a number makes an entire class of
    reasoning -- anything that compares response sizes -- untestable, and
    makes it look easier than it is.
    """
    return rng.weighted([
        ((200, rng.randint(2600, 48000)), 62),
        ((200, rng.randint(48000, 320000)), 6),     # a fat page, they exist
        ((200, None), 5),                            # 200 and no size logged
        ((301, None), 9),
        ((302, None), 4),
        ((404, rng.randint(900, 4200)), 5),
        ((304, None), 4),
        ((429, 552), 2),                             # rate limiting, real
        ((403, 1180), 1),
        ((500, rng.randint(600, 9000)), 2),
    ])


def _asset_status_size(rng, uri):
    """Mostly small, occasionally not.

    CALIBRATED, and the first attempt was wrong in a way worth recording: it
    drew asset sizes uniformly from 9 KB to 420 KB, which put the median
    response of a whole generated log at 80 KB against 4-18 KB measured. Real
    asset sizes are not uniform -- they are a pile of small files with a few
    photographs on top, and it is the pile that sets the median.
    """
    if uri.endswith((".jpg", ".png", ".webp")):
        body = rng.weighted([(rng.randint(3000, 40000), 7),
                             (rng.randint(40000, 160000), 3),
                             (rng.randint(160000, 900000), 1)])
    elif uri.endswith((".css", ".js")):
        body = rng.weighted([(rng.randint(700, 14000), 7),
                             (rng.randint(14000, 90000), 3)])
    elif uri.endswith(".woff2"):
        body = rng.randint(18000, 74000)
    else:
        body = rng.randint(300, 4000)
    return rng.weighted([((200, body), 84), ((304, None), 12),
                         ((404, 1180), 3), ((200, None), 1)])


def _one_shots(rng, site, start: datetime, days: int, count: int, agents):
    """Addresses that appear once and are never seen again.

    MEASURED, AND NOT WHAT I EXPECTED. These are 32% and 53% of all clients
    in two real logs -- and only 2% and 7% of the LINES. A great many
    addresses, almost no traffic: a link followed once, a feed reader, an
    uptime probe, somebody's phone on a different cell. Ninety percent carry
    no referer, and three quarters are answered 200.

    They are what sets the median requests-per-client to one, which is the
    single number this generator was furthest from. Adding sessions could
    never have produced it: a session is a browser, and a browser fetches a
    dozen files.
    """
    out = []
    extras = ["/robots.txt", "/sitemap.xml", "/impressum", "/preisliste.pdf",
              "/anfahrt", "/feed", "/datenschutz", "/prospekt-2026.pdf",
              "/apple-touch-icon.png"]
    pages = [u for u, _ in site.urls] + extras
    for _ in range(count):
        day = start + timedelta(days=rng.randint(0, max(0, days - 1)))
        hour = rng.weighted(list(enumerate(_HOURLY)))
        status, size = rng.weighted([
            ((200, rng.randint(1200, 42000)), 73),
            ((301, None), 11),
            ((404, rng.randint(900, 4200)), 8),
            ((429, 552), 5),
            ((304, None), 3),
        ])
        out.append(Request(
            when=day.replace(hour=hour, minute=rng.randint(0, 59),
                             second=rng.randint(0, 59)),
            ip=rng.ip("crowd"),
            method=rng.weighted([("GET", 98), ("HEAD", 2)]),
            uri=rng.choice(pages), status=status, size=size,
            agent=rng.choice(agents),
            referer="-" if rng.chance(0.9) else f"https://{_HOST}/"))
    return out


def baseline(rng, site, start: datetime, days: int, per_day: int):
    """Ordinary traffic, shaped like the real thing.

    Returns (requests, editor_ip). THIS IS THE EXPENSIVE HALF AND THE ONE
    THAT MATTERS -- findings against an empty log prove nothing; a case is
    only as good as the noise the signal had to be found in.

    REWRITTEN AGAINST MEASUREMENTS. Two real hoster logs were compared with
    what this function used to emit, and it lost on nearly every axis:

        requests per client   real median 1-2, half seen exactly once
                              generated median 21, nobody seen once
        distinct user agents  real 134 and 361; generated 12
        static assets         real 45-48% of lines; generated 14%
        URIs with a query     real 22-36%; generated 0.1%
        night floor           real quietest hour ~1/7 of busiest; generated 0

    So the model is now a SESSION rather than a request. Somebody arrives,
    reads a page or two, and each page drags a dozen static files along --
    which is where the assets, the referers and the bursts within a few
    seconds all come from at once. Most sessions belong to an address that is
    never seen again, which is what makes the long tail.
    """
    out = []
    agents = corpus.browser_agents(rng.derive("agents"), 320)
    # A handful of people who come back, and a crowd who do not. The regulars
    # produce the head of the distribution and the one-shots the tail; real
    # logs are roughly one distinct client per ten lines.
    regulars = [rng.ip("visitor") for _ in range(max(5, per_day // 60))]
    regular_agent = {ip: rng.choice(agents) for ip in regulars}
    crawlers = [rng.ip("noise") for _ in range(3)]
    editor_ip = rng.ip("visitor")
    pages = [u for u, _ in site.urls]
    weights = [w for _, w in site.urls]
    assets = site.assets or ["/favicon.ico"]

    # A session is one page plus its assets, so this many sessions land near
    # the caller's requested line count.
    per_session = 1 + len(assets) * 0.6
    sessions = max(1, int(per_day / per_session))

    for day_no in range(days):
        day = start + timedelta(days=day_no)
        for _ in range(rng.randint(int(sessions * 0.7), int(sessions * 1.3))):
            hour = rng.weighted(list(enumerate(_HOURLY)))
            when = day.replace(hour=hour, minute=rng.randint(0, 59),
                               second=rng.randint(0, 59))
            crawler = rng.chance(0.08)
            if crawler:
                ip = rng.choice(crawlers)
                agent = rng.choice(corpus.CRAWLER_UAS)
            elif rng.chance(0.18):
                ip = rng.choice(regulars)
                agent = regular_agent[ip]
            else:
                # THE TAIL. Most visitors are seen once and never again.
                ip = rng.ip("crowd")
                agent = rng.choice(agents)

            for view in range(rng.randint(1, 3) if not crawler else 1):
                uri = rng.weighted(list(zip(pages, weights)))
                if rng.chance(0.28):
                    uri += rng.choice(_QUERIES)
                method = rng.weighted([("GET", 96), ("HEAD", 3),
                                       ("OPTIONS", 1)])
                status, size = _page_status_size(rng)
                referer = (f"https://{_HOST}{rng.choice(pages)}"
                           if rng.chance(0.42) else "-")
                when = when + timedelta(seconds=rng.randint(0, 40))
                out.append(Request(when=when, ip=ip, method=method, uri=uri,
                                   status=status, size=size, agent=agent,
                                   referer=referer))
                # A browser fetches the page's furniture; a crawler does not.
                if crawler or status != 200 or method != "GET":
                    continue
                page_ref = f"https://{_HOST}{uri}"
                # A THIRD of a page's furniture, not all of it: a browser has
                # a cache, and the generator drawing every asset on every view
                # put static files at 74% of all lines against 45-48%
                # measured.
                for asset in rng.sample(
                        assets, rng.randint(2, max(3, len(assets) // 2))):
                    a_status, a_size = _asset_status_size(rng, asset)
                    # `?ver=` is where most of a real log's query strings come
                    # from -- every CMS appends one for cache busting, and
                    # measured query rates of 22-36% are mostly this, not
                    # visitors typing parameters.
                    ref = asset
                    if rng.chance(0.42) and not asset.endswith(".ico"):
                        ref += f"?ver={site.version}"
                    out.append(Request(
                        when=when + timedelta(seconds=rng.randint(0, 4)),
                        ip=ip, method="GET", uri=ref, status=a_status,
                        size=a_size, agent=agent,
                        referer=page_ref if rng.chance(0.86) else "-"))

        # The editor works on weekdays. Their login is what a brute force has
        # to be distinguished FROM -- one redirect after one POST is a person
        # signing in, and must never reach the flood threshold.
        if day.weekday() < 5 and rng.chance(0.8):
            when = rng.moment(day, 8, 17)
            agent = agents[0]
            out.append(Request(when=when, ip=editor_ip, method="POST",
                               uri=site.login_path, status=302, size=0,
                               agent=agent))
            for i in range(rng.randint(3, 12)):
                out.append(Request(
                    when=when + timedelta(minutes=i + 1), ip=editor_ip,
                    method=rng.weighted([("GET", 4), ("POST", 1)]),
                    uri=rng.choice(work_paths(site)),
                    status=200, size=rng.randint(3000, 28000), agent=agent))

    # Roughly as many one-request addresses as there are session clients, so
    # about half of all clients are seen exactly once -- measured at 32% and
    # 53%. They cost only a few percent of the lines, which is also measured.
    session_clients = len({r.ip for r in out})
    out += _one_shots(rng.derive("oneshots"), site, start, days,
                      int(session_clients * 1.1), agents)
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
