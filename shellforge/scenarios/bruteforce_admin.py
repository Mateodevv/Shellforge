# shellforge/scenarios/bruteforce-admin.py
"""bruteforce-admin -- a compromise with no file artifact at all.

THE WEBROOT IS CLEAN. Nobody dropped anything; somebody guessed a password
and logged in. Every fixture that plants a shell and finds it proves the
webshell scanner works, and proves nothing about the case where the only
evidence is a log and a database export.

The case turns on ONE discriminator, and it is the point of the scenario:

    many login POSTs                    -> a flood.        MEDIUM.
    many login POSTs AND a redirect     -> somebody got in. HIGH.

So two addresses do almost the same thing. One is answered 200 every time and
must stay MEDIUM. The other gets a 302 on its last attempt and must go HIGH.
A rule that cannot tell them apart turns every failed attack into an incident,
which is how a work list stops being read.

The rogue account in the dump is deliberately NOT planted as a finding.
`docs/rules.md` is explicit that account observations are a sorting aid and
not findings -- a dump cannot say an account is malicious, only what stands
out about it. Asserting a finding here would be asserting Shellhound should
be wrong.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from shellforge import corpus
from shellforge.render.accesslog import Request
from shellforge.scenarios import Case, common, register
from shellforge.truth import GroundTruth, Planted
from shellforge.world import Account, SCALES


@register("bruteforce-admin")
def build(rng, site, scale: str = "small") -> Case:
    _p, _m, _po, days, per_day = SCALES[scale]
    truth = GroundTruth(seed=rng.seed, scenario="bruteforce-admin",
                        cms=site.kind, cms_version=site.version)
    case = Case(site=site, truth=truth, files=dict(site.files))
    start = datetime(2026, 1, 5)
    attack_day = start + timedelta(days=int(days * 0.6))

    requests, editor_ip = common.baseline(rng.derive("baseline"), site, start,
                                          days, per_day)
    case.requests = requests + common.scanner_noise(rng.derive("scanners"),
                                                    start, days)

    # --- the one that got in ------------------------------------------------
    winner = rng.ip("attacker")
    t0 = rng.moment(attack_day, 1, 3)
    tries = rng.randint(38, 90)
    for i in range(tries):
        case.requests.append(Request(
            when=t0 + timedelta(seconds=i * rng.randint(2, 20)), ip=winner,
            method="POST", uri=site.login_path, status=200, size=4180,
            agent=common.QUIET_UA))
    # The redirect. This single line is the difference between MEDIUM and HIGH.
    breakthrough = t0 + timedelta(seconds=tries * 20 + 11)
    case.requests.append(Request(
        when=breakthrough, ip=winner, method="POST", uri=site.login_path,
        status=302, size=0, agent=common.QUIET_UA))
    # What somebody does once they are in. The paths come from the profile:
    # this is a story about logins, not about WordPress.
    for i in range(rng.randint(6, 15)):
        case.requests.append(Request(
            when=breakthrough + timedelta(minutes=1 + i * 2), ip=winner,
            method=rng.weighted([("GET", 3), ("POST", 1)]),
            uri=rng.choice(site.admin_paths),
            status=200, size=rng.randint(9000, 30000), agent=common.QUIET_UA))
    truth.plant(Planted(
        kind="client", ident=winner,
        expect_rules=["logs.login_flood", "logs.login_success"],
        expect_severity="high",
        note="tried the login several dozen times and was then REDIRECTED -- "
             "which is what a successful login looks like. Followed "
             "immediately by user administration"))
    truth.event(t0, winner, "bruteforce_begins", f"{tries} POSTs to "
                                                 f"{site.login_path}")
    truth.event(breakthrough, winner, "login_success",
                "302 after the flood, then user administration")

    # --- the one that did not ----------------------------------------------
    loser = rng.ip("attacker")
    t1 = rng.moment(attack_day + timedelta(days=1), 2, 4)
    for i in range(rng.randint(34, 70)):
        case.requests.append(Request(
            when=t1 + timedelta(seconds=i * rng.randint(1, 9)), ip=loser,
            method="POST", uri=site.login_path, status=200, size=4180,
            agent=rng.choice(corpus.BROWSER_UAS)))
    truth.plant(Planted(
        kind="client", ident=loser,
        expect_rules=["logs.login_flood"], expect_severity="medium",
        note="the same flood without a redirect. THE DISCRIMINATOR OF THIS "
             "SCENARIO: it must stay MEDIUM"))
    truth.keep_quiet(
        loser, rules=["logs.login_success"],
        reason="never received a 3xx, so nothing suggests a login worked. "
               "Promoting this would make every repelled attack an incident")
    truth.event(t1, loser, "bruteforce_fails", "flood without a redirect")

    # --- the account that appeared -----------------------------------------
    # Registered hours after the successful login, and never signed in since.
    # Shellhound lists it under account observations, which is a sorting aid
    # and not a finding -- so nothing is planted for it.
    # The hash SHAPE is taken from an existing account rather than invented,
    # so a Joomla dump gets bcrypt and a WordPress dump gets phpass. A rogue
    # account whose hash format does not match the rest of the table would be
    # a giveaway no real attacker leaves.
    like = site.accounts[0].password_hash if site.accounts else "$P$B"
    site.accounts.append(Account(
        login="cms-support", display="Support",
        email="cms-support@example.test", role="administrator",
        registered=(breakthrough + timedelta(hours=2)).strftime(
            "%Y-%m-%d %H:%M:%S"),
        password_hash=like[:7] + rng.hexs(max(0, len(like) - 7))))
    truth.note(
        "An administrator account named `cms-support` was registered two "
        "hours after the successful login and has never signed in. It is NOT "
        "planted as a finding: docs/rules.md is explicit that account "
        "observations are a sorting aid, because a dump cannot say an account "
        "is malicious. What the case asserts is that the log finding and the "
        "account line can be put side by side -- the registration timestamp "
        "falls inside the window the log says somebody was logging in.")

    common.plant_scanners(truth, case.requests)
    common.plant_editor(truth, editor_ip, case.requests, site)
    common.plant_core_silence(truth, site)
    truth.note(
        "The webroot is untouched. If any file in this case produces a "
        "finding, it is a false positive -- there is nothing wrong with the "
        "installation, only with who is using it.")
    return case
