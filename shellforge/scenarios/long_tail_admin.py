# shellforge/scenarios/long_tail_admin.py
"""long-tail-admin -- nothing happened, for long enough that it looks like it did.

THIS SCENARIO WAS A BUG REPORT WITH EVIDENCE ATTACHED. THE BUG IS FIXED;
THE SCENARIO STAYS AS THE GUARD AGAINST ITS RETURN.

The report: `logs.login_flood` triggered on thirty login POSTs from one
address and `logs.login_success` on the flood plus a 2xx from the
authenticated backend, and neither counted within a time window. So the
threshold was not a statement about behaviour -- it was a statement about
how long somebody kept their logs. One administrator, one office address,
one login every working morning, and after eight weeks the case reported a
"possible successful brute-force" at HIGH.

The fix (SHELLHOUND 0.2.0): the HIGH now requires the flood to be a BURST --
thirty login POSTs inside one 24 h window -- and this administrator's
busiest 24 hours hold one or two. The MEDIUM flood deliberately kept its
plain count: on real logs, a window there silences slow credential-stuffing
campaigns (80-plus failures spread over days), which in count-per-window
terms are indistinguishable from an administrator. Its sentence carries the
rate, so it refutes itself on a long-lived administrator.

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

WHAT THE GROUND TRUTH SAYS. The long administrator still expects the MEDIUM
flood -- that is what a correct run of the current rules produces -- and
expects NO break-in finding: `common.login_rules_for` reads the busiest
window, exactly as SHELLHOUND does. If the HIGH ever loses its burst gate,
the administrator is accused again and the scorer reports the extra finding
-- which is the right way round: somebody then edits this file deliberately.
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
        "was answered 404. Two administrators do ordinary work. The "
        "longer-serving one still collects the MEDIUM login-flood -- a plain "
        "count crossed by longevity, with the self-refuting rate in its own "
        "sentence -- and the only thing separating the two administrators is "
        "the number of days each appears in the log.")
    truth.note(
        "WHY THERE IS NO HIGH FINDING HERE ANY MORE. `logs.login_success` "
        "first required a redirect (which Joomla hands out for every attempt "
        "regardless), then a 2xx from the authenticated backend (which the "
        "administrator produces too, because they really did log in). Since "
        "SHELLHOUND 0.2.0 it also requires the flood to be a BURST -- thirty "
        "login POSTs inside one 24 h window. This administrator's busiest "
        "24 hours hold one or two, so the accusation no longer fires; an "
        "actual guessing campaign concentrates far more than that.")
    truth.note(
        "WHY THE MEDIUM KEPT ITS PLAIN COUNT. A window on the flood itself "
        "would silence slow credential stuffing -- real campaigns of 80-plus "
        "failed POSTs spread over days look exactly like an administrator in "
        "count-per-window terms. The flood therefore stays a count and says "
        "its own rate; the burst gate sits only on the accusation.")
    return case
