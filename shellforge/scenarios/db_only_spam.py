# shellforge/scenarios/db_only_spam.py
"""db-only-spam -- the files are clean, the database is not.

The case that survives the usual remediation. Somebody restores the webroot
from a backup, declares the site clean, and the injected code is still there,
because a CMS renders what is in its tables.

WHY THE SAME PATTERN IS PLANTED IN ONE TABLE AND TOLERATED IN ANOTHER. A
`<script>` in a data field is genuinely ambiguous: it is what an injection
looks like and also what an embedded tracking snippet looks like. Shellhound
reports it at MEDIUM and says the context decides. So this case contains both
-- an injected one in the posts, and a legitimate analytics snippet in the
options -- and asserts only that the rule speaks at MEDIUM about both. A tool
that could tell them apart from the value alone would be guessing.

Obfuscation is the opposite. In a file it is a shade of grey (MEDIUM); in a
data column there is no innocent reading, and Shellhound rates it HIGH. This
case is where that difference is exercised.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from shellforge import markers
from shellforge.render.accesslog import Request
from shellforge.scenarios import Case, common, register
from shellforge.truth import GroundTruth, Planted
from shellforge.world import Row, SCALES


@register("db-only-spam")
def build(rng, site, scale: str = "small") -> Case:
    _p, _m, _po, days, per_day = SCALES[scale]
    truth = GroundTruth(seed=rng.seed, scenario="db-only-spam",
                        cms=site.kind, cms_version=site.version)
    case = Case(site=site, truth=truth, files=dict(site.files))
    start = datetime(2026, 1, 5)
    hit_day = start + timedelta(days=int(days * 0.5))

    requests, editor_ip = common.baseline(rng.derive("baseline"), site, start,
                                          days, per_day)
    case.requests = requests + common.scanner_noise(rng.derive("scanners"),
                                                    start, days)

    # --- injected into published content -----------------------------------
    # The table and the column come from the profile: `posts.post_content` in
    # WordPress, `content.introtext` in Joomla. Naming either one here would
    # make this a scenario about one CMS instead of about injected content.
    body = site.content_column
    posts = [r for r in site.rows if r.table == site.content_table]
    victims = rng.sample(posts, min(3, len(posts)))
    victims[0].values[body] += markers.DB_IFRAME
    if len(victims) > 1:
        victims[1].values[body] += markers.DB_SCRIPT
    if len(victims) > 2:
        # NO `<script>` WRAPPER AROUND THIS ONE, deliberately. Written the
        # obvious way -- `<script>document.write(...)</script>` -- the value
        # matches `sqldb.script` as well, and the engine reports one finding
        # per rule per ROW, so the two compete for the same row and only the
        # first is recorded. The document.write therefore goes in a value
        # that carries no script tag, which is also how it usually arrives:
        # appended to an existing inline handler.
        victims[2].values[body] += (
            '<div onload=\'document.write(unescape("%3Cdiv%3E"))\'></div>')
    truth.plant(Planted(
        kind="table", ident=site.table(site.content_table),
        expect_rules=["sqldb.iframe", "sqldb.script", "sqldb.document_write"],
        expect_severity="medium",
        note="a zero-sized off-site iframe, an off-site script and a "
             "document.write, appended to published posts. All MEDIUM: each "
             "of them can also be editorial, and the table says which"))

    # --- injected into the settings table -----------------------------------
    # Where a real infection hides, because settings are loaded on every page
    # and nobody reads them. The row SHAPE comes from the profile -- WordPress
    # needs four columns, Joomla nine.
    injected = [
        ("shellforge_widget_cache", markers.DB_PHP_TAG, "sqldb.php_tag"),
        ("recent_transient_a1", "eval(base64_decode($k));",
         "sqldb.eval_input"),
        ("recent_transient_b2", markers.DB_OBFUSCATION, "sqldb.obfuscation"),
        ("theme_mod_backup", "shell_exec('uname -a')", "sqldb.cmd_call"),
        ("legacy_callback", "create_function('$a', 'return $a;')",
         "sqldb.create_function"),
    ]
    next_id = 30100
    for name, value, _rule in injected:
        site.rows.append(Row(table=site.config_table,
                             values=site.config_row(next_id, name, value)))
        next_id += 1
    truth.plant(Planted(
        kind="table", ident=site.table(site.config_table),
        expect_rules=[rule for _n, _v, rule in injected],
        expect_severity="high",
        note="executable code in the settings table -- it is read on every "
             "page view and survives restoring the webroot from backup. HIGH "
             "throughout: in a data column, obfuscation has no innocent "
             "reading, which is why it outranks the same pattern in a file"))

    # A legitimate analytics snippet, in the same table as the injections.
    # It trips `sqldb.script` too, and it is SUPPOSED to -- the rule reports,
    # the analyst decides. Nothing here can be forbidden without demanding
    # that Shellhound guess.
    site.rows.append(Row(
        table=site.config_table,
        values=site.config_row(next_id, "analytics_snippet",
                               markers.DB_SCRIPT)))
    truth.note(
        "`analytics_snippet` in the settings table is a legitimate tracking "
        "tag and trips `sqldb.script` exactly like the injected one. That is "
        "correct behaviour, not a false positive: the rule states that "
        "JavaScript sits in a data field, and whether it belongs there is a "
        "question about the table, not about the value. This case exists "
        "partly to keep that honest -- a future rule that suppressed one of "
        "the two would be guessing.")

    # --- what the log shows, which is almost nothing -----------------------
    # Injection through an application bug leaves no distinctive request line.
    # A couple of ordinary POSTs is all there is, and that is the point.
    t0 = rng.moment(hit_day, 3, 5)
    injector = rng.ip("attacker")
    for i in range(rng.randint(2, 5)):
        case.requests.append(Request(
            when=t0 + timedelta(seconds=i * 37), ip=injector, method="POST",
            uri="/wp-comments-post.php", status=302, size=0,
            agent=common.QUIET_UA))
    truth.keep_quiet(
        injector,
        reason="the injection went through an ordinary POST to an ordinary "
               "endpoint. NOTHING in the access log distinguishes it, and a "
               "tool that claimed otherwise would be inventing evidence. The "
               "database findings are the whole case")
    truth.event(t0, injector, "db_injection",
                "ordinary POSTs; the payload never appears in a request line")

    common.plant_scanners(truth, case.requests)
    common.plant_editor(truth, editor_ip, case.requests, site)
    common.plant_core_silence(truth, site)
    truth.note(
        "The webroot is untouched and the access log is unremarkable. If a "
        "file in this case produces a finding it is a false positive. The "
        "case is here to prove the database engine stands on its own.")
    return case
