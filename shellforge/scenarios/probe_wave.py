# shellforge/scenarios/probe_wave.py
"""probe-wave -- injection and traversal, answered two different ways.

THIS SCENARIO IS ABOUT OUTCOME GATING AND NOTHING ELSE. Shellhound's stated
principle is that a probe becomes a finding only when at least one of those
requests was answered 2xx: an attack repelled with 404 stays a counter on the
actor and must not redden the work list. That principle is easy to state, easy
to break, and impossible to notice breaking without a case built to catch it.

So two addresses send the SAME probes:

    answered 200 throughout   -> logs.sqli and logs.traversal.  MEDIUM.
    answered 404 throughout   -> nothing above INFO. Ever.

Both halves are asserted. Only checking the first would leave a tool that
reports everything scoring perfectly.

WHAT A HIT DOES AND DOES NOT MEAN. `answered` is not `worked`. A 200 to a
`union select` says the server returned a page, not that the injection
succeeded -- which is exactly why the rule is MEDIUM and why the case also
carries the database findings such a query would have produced if it had.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from shellforge.render.accesslog import Request
from shellforge.scenarios import Case, common, register
from shellforge.truth import GroundTruth, Planted
from shellforge.world import SCALES

#: Injection probes. Each carries one of the patterns Shellhound looks for.
SQLI = [
    "/shop/index.php?id=1'+UNION+SELECT+1,2,3--",
    "/shop/index.php?id=1+AND+1=1+UNION+SELECT+table_name+FROM+information_schema.tables--",
    "/index.php?p=9'+or+1=1--+-",
    "/shop/artikel.php?id=1+AND+sleep(5)--",
    "/shop/artikel.php?id=1+UNION+SELECT+concat(user_login,0x3a,user_pass)+FROM+wp_users--",
    "/index.php?cat=1+AND+benchmark(2000000,md5(now()))--",
]

#: Traversal probes. The rule wants at least two `../`, in any encoding.
TRAVERSAL = [
    "/index.php?f=../../../../etc/passwd",
    "/download.php?file=..%2f..%2f..%2fwp-config.php",
    "/index.php?tpl=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fshadow",
    "/wp-content/plugins/bildergalerie-lite/dl.php?img=../../../../wp-config.php",
]


def _wave(rng, ip, when, agent, status, size_for):
    out = []
    for i, uri in enumerate(rng.shuffled(SQLI + TRAVERSAL)):
        out.append(Request(when=when + timedelta(seconds=i * rng.randint(3, 40)),
                           ip=ip, method="GET", uri=uri, status=status,
                           size=size_for(uri), agent=agent))
    return out


@register("probe-wave")
def build(rng, site, scale: str = "small") -> Case:
    _p, _m, _po, days, per_day = SCALES[scale]
    truth = GroundTruth(seed=rng.seed, scenario="probe-wave",
                        cms="wordpress", cms_version=site.version)
    case = Case(site=site, truth=truth, files=dict(site.files))
    start = datetime(2026, 1, 5)
    day = start + timedelta(days=int(days * 0.5))

    requests, editor_ip = common.baseline(rng.derive("baseline"), site, start,
                                          days, per_day)
    case.requests = requests + common.scanner_noise(rng.derive("scanners"),
                                                    start, days)

    # --- answered ----------------------------------------------------------
    through = rng.ip("attacker")
    t0 = rng.moment(day, 4, 6)
    case.requests += _wave(rng.derive("through"), through, t0, common.QUIET_UA,
                           200, lambda u: rng.randint(2400, 38000))
    truth.plant(Planted(
        kind="client", ident=through,
        expect_rules=["logs.sqli", "logs.traversal"],
        expect_severity="medium",
        note="injection and traversal patterns in the URI, answered 2xx "
             "throughout. MEDIUM because answered is not worked -- the "
             "database findings are what would settle it"))
    truth.event(t0, through, "probe_answered",
                "SQLi and traversal patterns, every one answered 200")

    # --- repelled ----------------------------------------------------------
    blocked = rng.ip("attacker")
    t1 = rng.moment(day + timedelta(days=1), 4, 6)
    case.requests += _wave(rng.derive("blocked"), blocked, t1,
                           common.QUIET_UA, 404, lambda u: 1180)
    truth.keep_quiet(
        blocked,
        rules=["logs.sqli", "logs.traversal", "logs.upload_php"],
        reason="THE HALF THAT IS USUALLY MISSING. The identical probes, "
               "answered 404 every time. Outcome gating must hold these at "
               "nothing -- a repelled wave that reddens the work list is how "
               "an analyst learns to stop reading it")
    truth.event(t1, blocked, "probe_repelled",
                "the same patterns, every one answered 404")

    # --- what a working injection would have left behind -------------------
    # The URI says a query ran; only the dump can say what it did. Put both in
    # so the two halves of the case can be compared, which is the whole reason
    # the log rule is MEDIUM rather than HIGH.
    posts = [r for r in site.rows if r.table == "posts"]
    if posts:
        posts[0].values["post_content"] += (
            '<iframe src="//zaehler.example.test/t.js" width="0" '
            'height="0"></iframe>')
        truth.plant(Planted(
            kind="table", ident=site.table("posts"),
            expect_rules=["sqldb.iframe"], expect_severity="medium",
            note="what the answered injection actually accomplished. The log "
                 "says a query was answered; this says what came of it. "
                 "Neither is conclusive alone, which is the point"))

    common.plant_scanners(truth, case.requests)
    common.plant_editor(truth, editor_ip)
    common.plant_core_silence(truth, site)
    truth.note(
        "Two addresses, identical payloads, different answers. If both "
        "produce findings, outcome gating is broken. If neither does, the "
        "patterns stopped matching. The case fails loudly either way.")
    return case
