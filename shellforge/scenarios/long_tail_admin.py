# shellforge/scenarios/long_tail_admin.py
"""long-tail-admin -- nothing happened, for long enough that it looks like it did.

THIS SCENARIO IS A BUG REPORT WITH EVIDENCE ATTACHED.

`logs.login_flood` triggers on thirty login POSTs from one address, and
`logs.login_success` on thirty plus at least one 3xx. Neither counts within a
time window. So the threshold is not a statement about behaviour -- it is a
statement about how long somebody kept their logs.

One administrator, one office address, one login every working morning, each
answered with the redirect that a successful login produces:

    after 6 weeks    ~30 logins   -> flood.  MEDIUM.
    after 8 weeks    ~40 logins   -> "possible successful brute-force". HIGH.

Nothing about the site changed. Nobody attacked it. The finding appeared
because the case covers a longer period, and it lands at the top of the work
list with the wording an analyst reads as a confirmed compromise.

THE CASE IS CONSTRUCTED SO IT CANNOT BE ARGUED WITH:

  * There is no attacker in it at all. No dropped file, no injected row, no
    probe answered 2xx. The webroot is a clean installation and the database
    is untouched.
  * The logins are spaced one per working day, at office hours, from a single
    address, with an ordinary browser user agent, each followed by a few
    minutes of editing. That is the least brute-force-shaped traffic that can
    still be thirty logins.
  * A second administrator with the same habit but FEWER days present stays
    below the threshold, so the case shows the crossover rather than just the
    far side of it.

WHAT THE GROUND TRUTH SAYS. It expects the findings, because that is what a
correct run of the current rules produces, and a scenario that expected
silence would just be a red build blaming Shellforge. The judgement is in the
notes. If the rules gain a time window, these plants stop firing and the
scorer reports the change as a MISS -- which is the right way round: somebody
then edits this file deliberately.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from shellforge import corpus
from shellforge.render.accesslog import Request
from shellforge.scenarios import Case, common, register
from shellforge.truth import GroundTruth, Planted
from shellforge.world import SCALES

#: Enough working days to cross the threshold regardless of `--scale`. The
#: point of the case is the crossover, and a case that only demonstrates it at
#: `large` would be a case nobody runs.
WORKING_DAYS = 46

#: The second administrator, deliberately below it.
QUIET_DAYS = 12


def _daily_logins(rng, site, ip, start, days, agent):
    """One login per working morning, then a few minutes of actual work."""
    out = []
    day = start
    done = 0
    while done < days:
        if day.weekday() < 5:
            when = rng.moment(day, 7, 10)
            out.append(Request(when=when, ip=ip, method="POST",
                               uri=site.login_path, status=302, size=0,
                               agent=agent))
            for i in range(rng.randint(4, 14)):
                out.append(Request(
                    when=when + timedelta(minutes=i + 1), ip=ip,
                    method=rng.weighted([("GET", 5), ("POST", 1)]),
                    uri=rng.choice(site.admin_paths), status=200,
                    size=rng.randint(4000, 26000), agent=agent))
            done += 1
        day += timedelta(days=1)
    return out


@register("long-tail-admin")
def build(rng, site, scale: str = "small") -> Case:
    _p, _m, _po, days, per_day = SCALES[scale]
    truth = GroundTruth(seed=rng.seed, scenario="long-tail-admin",
                        cms=site.kind, cms_version=site.version)
    case = Case(site=site, truth=truth, files=dict(site.files))
    start = datetime(2026, 1, 5)

    # Ordinary visitor traffic for the same period, so the case is a site and
    # not a login log. `common.baseline` brings its own editor; this scenario
    # needs a longer-running one, so the two are kept apart.
    span = max(days, WORKING_DAYS * 7 // 5 + 4)
    requests, baseline_editor = common.baseline(
        rng.derive("baseline"), site, start, span, per_day)
    case.requests = requests + common.scanner_noise(rng.derive("scanners"),
                                                    start, span)

    agent = corpus.BROWSER_UAS[0]

    # --- the administrator who has simply been here a while ----------------
    admin_ip = rng.ip("visitor")
    logins = _daily_logins(rng.derive("admin"), site, admin_ip, start,
                           WORKING_DAYS, agent)
    case.requests += logins
    count = sum(1 for r in logins if r.method == "POST"
                and r.uri == site.login_path)
    truth.plant(Planted(
        kind="client", ident=admin_ip,
        expect_rules=["logs.login_flood", "logs.login_success"],
        expect_severity="high",
        note=f"the site's own administrator. {count} logins, one per working "
             f"morning at office hours, from one address, each answered with "
             f"the redirect a successful login produces, each followed by a "
             f"few minutes of editing. Reported as a possible successful "
             f"brute-force at HIGH. NOTHING ATTACKED THIS SITE"))
    truth.event(start, admin_ip, "daily_work",
                f"{count} logins over {WORKING_DAYS} working days")

    # --- the same habit, fewer days, and therefore silent ------------------
    quiet_ip = rng.ip("visitor")
    case.requests += _daily_logins(rng.derive("quiet"), site, quiet_ip,
                                   start + timedelta(days=span - QUIET_DAYS - 2),
                                   QUIET_DAYS, agent)
    truth.keep_quiet(
        quiet_ip,
        rules=["logs.login_flood", "logs.login_success"],
        reason=f"the SECOND administrator, with identical habits and "
               f"{QUIET_DAYS} working days instead of {WORKING_DAYS}. Stays "
               f"silent. The two of them differ in nothing except how long "
               f"they have been in the log, which is the whole point")

    common.plant_scanners(truth, case.requests)
    common.plant_editor(truth, baseline_editor, case.requests, site)
    common.plant_core_silence(truth, site)

    truth.note(
        "NO ATTACK IS PRESENT IN THIS CASE. The webroot is a clean "
        "installation, the database is untouched, and every probe in the log "
        "was answered 404. Two administrators do ordinary work. One of them "
        "is reported at HIGH as a possible successful brute-force, and the "
        "only thing separating them is the number of days each appears in "
        "the log.")
    truth.note(
        "SUGGESTED SHAPE OF A FIX, for whoever picks this up: the rules "
        "already know the timestamps. A flood is thirty attempts in a "
        "WINDOW, not thirty attempts. A second discriminator that costs "
        "nothing: a brute force produces many failures before its redirect, "
        "and this administrator produced none -- every single POST here was "
        "answered 302 on the first try.")
    return case
