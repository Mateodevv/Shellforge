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
                    uri=rng.choice(common.work_paths(site)), status=200,
                    size=rng.randint(4000, 26000), agent=agent))
            done += 1
        day += timedelta(days=1)
    return out


@register("long-tail-admin")
def build(rng, site, scale: str = "small") -> Case:
    _p, _m, _po, days, per_day = SCALES[scale][:5]
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
    # They also do their job, which on a CMS with a recognisable backend
    # means a 2xx out of it -- the same signal a successful intruder leaves,
    # because it IS the same signal. That is the residue of the problem after
    # the redirect-based version was fixed: the discriminator now works, and
    # a legitimate administrator still matches it, because they legitimately
    # logged in.
    if site.authenticated_area:
        case.requests.append(Request(
            when=start + timedelta(days=2, hours=9), ip=admin_ip,
            method="GET", uri=site.authenticated_area, status=200,
            size=19800, agent=agent))
    # One login per working morning: the busiest 24 hours hold one or
    # two. That is the number SHELLHOUND now reads, and the reason
    # this scenario no longer expects a break-in finding.
    burst = common.busiest_window(case.requests, admin_ip,
                                  site.login_path)
    rules = common.login_rules_for(site, count, burst)
    truth.plant(Planted(
        kind="client", ident=admin_ip,
        expect_rules=rules,
        expect_severity="high" if "logs.login_success" in rules else "medium",
        note=f"the site's own administrator. {count} logins, one per working "
             f"morning at office hours, from one address, each followed by a "
             f"few minutes of editing. NOTHING ATTACKED THIS SITE, and the "
             f"only thing that put them over the threshold is how long they "
             f"have been in the log"))
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
        "WHAT IS LEFT AFTER THE REDIRECT FIX. `logs.login_success` used to "
        "accept a redirect as proof of a successful login, which Joomla "
        "hands out for every attempt regardless; it now requires a 2xx from "
        "the authenticated backend, which is right. This administrator "
        "produces that signal too -- because they really did log in. So the "
        "remaining question is not the discriminator but the COUNT: thirty "
        "login POSTs with no time window is a threshold on the length of the "
        "log, not on anybody's behaviour.")
    truth.note(
        "SUGGESTED SHAPE OF A FIX, for whoever picks this up: the index "
        "already knows the timestamps. A flood is thirty attempts in a "
        "WINDOW, not thirty attempts. A second discriminator that costs "
        "nothing is already being counted -- `login_statuses`: a brute force "
        "produces a long tail of failures before it succeeds, and this "
        "administrator produced none. Every POST here was answered on the "
        "first try.")
    return case
