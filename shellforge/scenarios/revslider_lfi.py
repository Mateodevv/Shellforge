# shellforge/scenarios/revslider_lfi.py
"""revslider-lfi -- CVE-2015-1579, where the status code cannot help.

Slider Revolution before 3.0.96 read any file the query string named:

    /wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php

The whole exploit is in the request line, which normally makes a case easy.
This one is not easy, and the reason is the point of the scenario.

**admin-ajax.php ANSWERS 200 WHETHER IT WORKED OR NOT.** A successful read
returns the contents of `wp-config.php` -- database host, user, password,
the authentication salts. A failed one returns a few bytes: the plugin is
absent, or patched, or the path did not resolve. Both are `200`.

Shellhound's outcome gating is a status code. Its stated principle -- a probe
becomes a finding only when at least one of those requests was answered 2xx --
is right, and here it separates nothing: every request in this case is 2xx.
The discriminator that does exist is the RESPONSE SIZE, which the combined
log format carries in a column nothing currently reads.

So the case contains two addresses sending the SAME requests:

    exfiltrated   answered 200 with 3-5 KB. The credentials left the server.
    repelled      answered 200 with 41 bytes. Nothing left the server.

A correct run today reports them identically, and the ground truth says so
rather than pretending otherwise. What the case asserts is that this is
CURRENT behaviour; what it documents is that one column would tell them
apart.

THE SECOND HALF OF THE STORY IS WHERE THE PLUGIN LIVES. Slider Revolution was
bundled inside dozens of commercial themes, so the victims did not know they
had it and could not update it -- the theme vendor had to. This case models
that: `revslider` sits under the THEME, not under `wp-content/plugins`, which
is what made the CVE spread as far as it did.

THE PRODUCT IS NAMED, deliberately, as with `wp-file-manager` and
`shaper_helix3`. A CVE is about a specific piece of software and the path IS
the evidence; renaming it would produce a case describing a vulnerability in
nothing. Everything else here is invented as usual.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from shellforge.render.accesslog import Request
from shellforge.scenarios import Case, common, register
from shellforge.truth import GroundTruth, Planted
from shellforge.world import SCALES

#: The fixed part. Everything before the traversal is what a hunt pattern
#: matches on; the target after `img=` is the attacker's choice.
ENDPOINT = "/wp-admin/admin-ajax.php?action=revslider_show_image&img="

#: What gets asked for, in the order somebody actually asks. `wp-config.php`
#: first, because it is the one that ends the engagement.
TARGETS = [
    "../wp-config.php",
    "../../wp-config.php",
    "../../../wp-config.php",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../wp-config-sample.php",
    "../../../../home/web/.bash_history",
]

#: A failed read. `admin-ajax.php` returns this and a 200.
EMPTY_ANSWER = 41


def _wave(rng, ip, when, agent, sizes):
    return [Request(when=when + timedelta(seconds=i * rng.randint(4, 50)),
                    ip=ip, method="GET", uri=ENDPOINT + target,
                    status=200, size=sizes(target), agent=agent)
            for i, target in enumerate(TARGETS)]


@register("revslider-lfi", cms=("wordpress",))
def build(rng, site, scale: str = "small") -> Case:
    _p, _m, _po, days, per_day = SCALES[scale]
    truth = GroundTruth(seed=rng.seed, scenario="revslider-lfi",
                        cms=site.kind, cms_version=site.version)
    case = Case(site=site, truth=truth, files=dict(site.files))
    start = datetime(2026, 1, 5)
    day = start + timedelta(days=int(days * 0.55))

    # --- the plugin nobody installed ---------------------------------------
    bundled = f"{site.theme_dir}/includes/revslider"
    case.files[f"{bundled}/revslider.php"] = (
        "<?php\n"
        "/**\n"
        " * Plugin Name: Slider Revolution\n"
        " * Description: Responsive slider.\n"
        " * Version: 3.0.95\n"
        " */\n\n"
        "if (!defined('ABSPATH')) {\n    exit;\n}\n")
    case.files[f"{bundled}/readme.txt"] = (
        "=== Slider Revolution ===\nStable tag: 3.0.95\n")
    truth.note(
        "Slider Revolution 3.0.95 is BUNDLED INSIDE THE THEME, at "
        f"`{bundled}`, not under `wp-content/plugins`. That is how this CVE "
        "actually spread: dozens of commercial themes shipped the slider, so "
        "the site owner did not know they had it and could not update it if "
        "they had. Affected range is everything before 3.0.96.")
    truth.note(
        "AND THE INVENTORY DOES NOT SEE IT. Measured: the CMS inventory for "
        "this case lists the theme and five plugins, and no Slider "
        "Revolution -- it reads `wp-content/plugins/*` and the theme's own "
        "`style.css`, and a plugin nested inside a theme is neither. That is "
        "not obviously a bug: an inventory that walked every directory "
        "looking for plugin headers would find a great deal it cannot vouch "
        "for. But it means the advice 'check the version in the inventory' "
        "does not work for exactly the class of vulnerability that made this "
        "one famous, and the hunt pattern shipped with this case says so "
        "instead of repeating it.")

    requests, editor_ip = common.baseline(rng.derive("baseline"), site, start,
                                          days, per_day)
    case.requests = requests + common.scanner_noise(rng.derive("scanners"),
                                                    start, days)

    # --- the read that worked ----------------------------------------------
    got_it = rng.ip("attacker")
    t0 = rng.moment(day, 2, 4)
    case.requests += _wave(
        rng.derive("through"), got_it, t0, common.QUIET_UA,
        lambda target: (rng.randint(2900, 5200) if "wp-config" in target
                        else rng.randint(1400, 2600)))
    truth.event(t0, got_it, "exfiltration",
                "wp-config.php read through the revslider LFI, answered 200 "
                "with several kilobytes")

    # --- the identical attempt that did not ---------------------------------
    missed = rng.ip("attacker")
    t1 = rng.moment(day + timedelta(days=1), 2, 4)
    case.requests += _wave(rng.derive("blocked"), missed, t1, common.QUIET_UA,
                           lambda _target: EMPTY_ANSWER)
    truth.event(t1, missed, "probe_failed",
                "the same requests, answered 200 with 41 bytes each -- "
                "nothing was read")

    # --- what a correct run reports today -----------------------------------
    # Both. Identically. Four of the seven targets carry two or more `../`,
    # and every request was answered 2xx, so the traversal rule fires on both
    # addresses at the same weight.
    for ip, what in ((got_it, "read the credentials"),
                     (missed, "read nothing at all")):
        truth.plant(Planted(
            kind="client", ident=ip,
            expect_rules=["logs.traversal"], expect_severity="medium",
            note=f"traversal patterns answered 2xx. This address {what}, and "
                 f"the finding is the same either way -- every request in "
                 f"this case is a 200, so the outcome gate has nothing to "
                 f"gate on"))

    truth.meta["byte_counts"] = {
        got_it: "2900-5200 per request (the file came back)",
        missed: f"{EMPTY_ANSWER} per request (nothing came back)",
    }
    truth.note(
        "THE TWO ADDRESSES ARE INDISTINGUISHABLE BY ANY RULE IN THE TOOL, "
        "and one of them walked off with the database credentials. Outcome "
        "gating on the status code is right in general and useless here: "
        "`admin-ajax.php` answers 200 whether the read worked or not, which "
        "is exactly why this CVE was worth having. The discriminator is the "
        "RESPONSE SIZE -- kilobytes against 41 bytes -- and the combined log "
        "format has carried it all along, in a column nothing reads. The "
        "ground truth records the sizes under `byte_counts` so a future rule "
        "has something to be checked against.")
    truth.note(
        "NOTHING WAS DROPPED. This is a read, not a write: the webroot is "
        "untouched and the database export is clean. Any file finding in "
        "this case is a false positive. What the attacker took is not in the "
        "evidence at all -- it left in a response body, and a response body "
        "is the one thing an access log never keeps.")

    case.hunt_patterns = [{
        "name": "Slider Revolution arbitrary file read (CVE-2015-1579)",
        "advisory": "CVE-2015-1579",
        "paths": [ENDPOINT.rstrip("="), "revslider_show_image"],
        "match": "any",
        "description":
            "A request to the Slider Revolution image handler with a path "
            "parameter. A hit proves the request was made. It does NOT prove "
            "the read succeeded, and the status code will not tell you: this "
            "endpoint answers 200 either way. Compare the response SIZES -- "
            "a few kilobytes means the file came back, a few dozen bytes "
            "means it did not. Do NOT expect the CMS inventory to confirm "
            "the slider is installed: on most affected sites it was bundled "
            "inside a commercial theme, and the inventory reads "
            "wp-content/plugins. Look for the directory instead, under the "
            "active theme.",
    }]

    common.plant_scanners(truth, case.requests)
    common.plant_editor(truth, editor_ip, case.requests, site)
    common.plant_core_silence(truth, site)
    return case
