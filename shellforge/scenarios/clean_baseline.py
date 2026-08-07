# shellforge/scenarios/clean_baseline.py
"""clean-baseline -- nothing happened here.

THE MOST IMPORTANT SCENARIO AND THE ONE EVERY FIXTURE SUITE SKIPS. A detector
is only worth its recall if its precision holds, and precision cannot be
measured on a case where everything is a finding. This case is a working
WordPress site with real traffic, real crawlers, real scans bouncing off it,
and nothing wrong.

The only thing that may be reported is INFO about the scanners, because they
did announce themselves. Everything else -- every core file, every plugin,
every visitor, every table -- is covered by the scorer's blanket rule: a
finding on an artifact nobody planted is a false positive. So this scenario
asserts, in one line, that several hundred legitimate objects stay silent.

If a rule change reddens ordinary WordPress, this is what goes red first.
"""
from __future__ import annotations

from datetime import datetime

from shellforge.scenarios import Case, common, register
from shellforge.truth import GroundTruth
from shellforge.world import SCALES


@register("clean-baseline")
def build(rng, site, scale: str = "small") -> Case:
    _p, _m, _po, days, per_day = SCALES[scale]
    truth = GroundTruth(seed=rng.seed, scenario="clean-baseline",
                        cms=site.kind, cms_version=site.version)
    case = Case(site=site, truth=truth, files=dict(site.files))
    start = datetime(2026, 1, 5)

    requests, editor_ip = common.baseline(rng.derive("baseline"), site, start,
                                          days, per_day)
    case.requests = requests + common.scanner_noise(rng.derive("scanners"),
                                                    start, days)
    common.plant_scanners(truth, case.requests)
    common.plant_editor(truth, editor_ip)
    common.plant_core_silence(truth, site)

    # No error log at all. A site that is not on fire does not need one to
    # prove it, and leaving it out keeps this case about the webroot, the
    # traffic and the database only.
    truth.event(start, "system", "baseline_begins",
                f"{days} days of ordinary traffic, nothing else")
    truth.note(
        "Expected result: INFO findings about the scanners, and NOTHING "
        "else. Every file, table and visitor in this case is legitimate. Any "
        "finding above INFO is a false positive by definition, and the "
        "scorer will report it as one without the ground truth having to "
        "enumerate several hundred clean files.")
    truth.note(
        "The scans are answered 404 throughout. They are here to prove that "
        "outcome gating holds: an attack that was repelled must stay a "
        "counter on the actor and must not redden the work list.")
    return case
