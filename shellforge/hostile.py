# shellforge/hostile.py
"""The axes along which evidence is shaped like the cases that break things.

AN AXIS IS A TRANSFORMATION OF A FINISHED CASE, NOT A DIFFERENT SCENARIO.
That is the whole design. `wp-upload-shell` describes an intrusion; whether
the log arrived with a byte-order mark, in Latin-1, with five hundred clients
in it, or from a server whose clock disagreed with the database's, is a
property of the EVIDENCE and not of what happened. So the axes compose with
every scenario and every CMS profile, and adding one covers the whole
catalogue at once.

THE ORACLE IS ONE SENTENCE: **the axis must not change the answer.**

The ground truth is generated before the axis is applied and stays exactly as
it was. Same planted objects, same rules, same silence assertions. A UTF-8
BOM does not make a web shell less of a web shell, and five hundred visitors
do not make the attacker's request for it disappear. So `--hostile` needs no
new assertions at all: it re-runs the existing ones over a harder shape, and
anything that drops out is a parser losing evidence rather than a detector
disagreeing.

That also makes the failures legible. If `logs.upload_php` stops firing under
`encoding` but holds under `broken-lines`, the report says which shape broke
it, and there is exactly one difference to look at.

WHAT THIS DOES NOT DUPLICATE. Shellhound's own `tests/fixtures_hostile.py`
already covers time-zone offsets in the log line, two log files sharing a
basename, two dumps, mixed-case paths, a truncated head and 250 clients --
each as a small hand-built case with hand-written assertions. The axes here
are the ones it does not have, applied to realistic cases at realistic size:
a quarter of a million lines rather than a dozen, with the answer known.
"""
from __future__ import annotations

from datetime import timedelta

AXES = {}


def axis(name, summary):
    def wrap(fn):
        AXES[name] = (fn, summary)
        return fn
    return wrap


def apply(names, case, rng):
    """Apply each named axis to a finished case, in the order given."""
    unknown = [n for n in names if n not in AXES]
    if unknown:
        raise KeyError(f"unknown hostile axis/axes: {', '.join(unknown)}; "
                       f"have: {', '.join(sorted(AXES))}")
    for name in names:
        fn, summary = AXES[name]
        fn(case, rng.derive(f"hostile/{name}"))
        case.truth.meta.setdefault("hostile", []).append(name)
        case.truth.note(f"HOSTILE AXIS `{name}`: {summary} The ground truth "
                        f"is unchanged -- the shape of the evidence is not "
                        f"supposed to change what is in it.")


def names():
    return sorted(AXES)


# --- clock ------------------------------------------------------------------

@axis("clock-skew",
      "the database server's clock runs two hours ahead of the log server's.")
def clock_skew(case, rng):
    """Shift every DATABASE timestamp relative to the log.

    THE FEATURE THIS AIMS AT. Shellhound lets an analyst set a clock offset
    per source and states in the chronology that it was applied -- because
    two machines in one incident routinely disagree, and an ordering derived
    from the disagreement is worse than no ordering. The correction exists;
    what has been missing is a case where the true answer is known, so that
    "the chronology now reads correctly" can be checked rather than eyeballed.

    Only the DUMP moves. The log is left alone, so the skew is a property of
    one source and the offset that reconciles them is a single number the
    ground truth carries. Findings must not move at all: every rule here is
    about one artifact, and no rule compares a database timestamp with a log
    timestamp. If a finding does change, something is deriving a decision
    from an ordering it should not trust.
    """
    seconds = 2 * 3600
    case.clock_skew = seconds
    delta = timedelta(seconds=seconds)

    def shift(text):
        from datetime import datetime
        try:
            when = datetime.strptime(str(text), "%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            return text
        return (when + delta).strftime("%Y-%m-%d %H:%M:%S")

    for account in case.site.accounts:
        account.registered = shift(account.registered)
        if account.last_login:
            account.last_login = shift(account.last_login)
    for row in case.site.rows:
        for key, value in list(row.values.items()):
            low = key.lower()
            if any(mark in low for mark in
                   ("date", "created", "registered", "publish", "modified",
                    "lastvisit")):
                row.values[key] = shift(value)

    case.truth.meta["clock_skew_seconds"] = seconds
    case.truth.note(
        f"THE DUMP'S CLOCK RUNS {seconds // 3600} HOURS AHEAD OF THE LOG'S. "
        f"Every timestamp in the database export is shifted by +{seconds}s "
        f"relative to the access log; the log is untouched. To read this case "
        f"correctly an analyst sets the dump offset to -{seconds} seconds, "
        f"and the chronology has to say that it did. The timeline in this "
        f"file is the TRUE one, on the log's clock.")


# --- what the hoster actually wrote -----------------------------------------

@axis("hoster-fields",
      "the log carries Plesk's two trailing fields, the way a real shared "
      "host writes it.")
def hoster_fields(case, rng):
    """Write the log in a format a hoster uses rather than the textbook one.

    THIS IS THE AXIS THAT SHOULD HAVE EXISTED FIRST. Two real access logs
    from different hosters were measured against what this generator emits,
    and NEITHER was plain Combined:

        hoster A   ... 200 18020 www.example.test "ref" "ua" "-"
        hoster B   ... 200 -     "ref" "ua" "Traffic IN:820 OUT:3256" "ReqTime:0 sec"
        generated  ... 200 19156 "ref" "ua"

    A carries an unquoted vhost token between the size and the referer; B
    carries two trailing quoted fields. Shellhound's `LOG_PATTERN` has an
    explicit branch for each -- `(?:[^"\\s]\\S* )?` and `(?:\\s.*)?$` -- and
    the comment beside them says these are years of real-webhost quirks and
    that removing one "would silently drop exactly the attacker lines the
    index exists to answer about".

    Nothing generated here had ever exercised either branch. The most
    load-bearing part of the parser was the one part the test data never
    touched.

    The axis picks the Plesk shape; `--log-format vhost` writes the other,
    and `check --all --hostile all` covers both because the axis runs on
    every scenario.
    """
    case.log_format = "plesk"
    case.truth.note(
        "THE LOG IS WRITTEN THE WAY A SHARED HOST WRITES IT: Combined plus "
        "`\"Traffic IN:… OUT:…\"` and `\"ReqTime:… sec\"`. Measured against "
        "real evidence -- neither of two real hoster logs was plain "
        "Combined, and the parser branch that handles this had no test data "
        "behind it. Not one finding may change: the trailing fields are not "
        "part of any rule.")


# --- encoding ---------------------------------------------------------------

@axis("encoding",
      "a byte-order mark, Latin-1 bytes, CRLF line endings and an over-long "
      "URI in the access log.")
def encoding(case, rng):
    """Make the log a file rather than a string.

    Four things at once, because they arrive together on real hosts and each
    one is a place a reader can be wrong:

      BOM       `open_text_auto` opens with `encoding="utf-8"`, not
                `utf-8-sig`. A byte-order mark therefore survives decoding as
                `\\ufeff` at the start of the first line -- and `\\ufeff` is
                not whitespace, so the Combined pattern's `^(?P<ip>\\S+)`
                swallows it into the CLIENT ADDRESS. The prediction this axis
                makes is precise: the first line of the log is attributed to
                an address that does not exist.
      Latin-1   a referrer or user agent with an umlaut in cp1252 is not
                valid UTF-8. `errors="replace"` should keep the line; a
                stricter reader loses it.
      CRLF      logs copied through Windows arrive with `\\r\\n`.
      long URI  a request line of several kilobytes, which is what a real
                injection attempt looks like.

    None of it may cost a finding, which is what the unchanged ground truth
    asserts.
    """
    case.log_bom = True
    case.log_newline = "\r\n"
    # THE FILE IS LATIN-1, not merely its content. Writing umlauts as UTF-8
    # would test nothing -- they would decode cleanly. A cp1252 access log is
    # what a German shared host actually produces, and it is not valid UTF-8,
    # so `errors="replace"` is the thing under test: the line has to survive
    # carrying a replacement character, not be dropped.
    case.log_encoding = "latin-1"

    # Latin-1 in fields that travel verbatim into the index.
    visitors = [r for r in case.requests if r.status == 200][:40]
    for i, req in enumerate(rng.shuffled(visitors)[:12]):
        req.referer = f"https://www.beispiel-grün.test/seite-{i}"
        if i % 3 == 0:
            req.agent = req.agent + " (Büro-Rechner; Größe: groß)"

    # One request line of several kilobytes. Long, and legitimate-looking:
    # the point is that the reader survives it, not that it is an attack.
    if case.requests:
        model = case.requests[len(case.requests) // 2]
        case.requests.append(type(model)(
            when=model.when + timedelta(seconds=7), ip=model.ip,
            method="GET",
            uri="/index.php?q=" + ("suchbegriff+" * 400) + "ende",
            status=200, size=18000, agent=model.agent))

    # THE PHANTOM THIS PRODUCES, NAMED IN ADVANCE. The mark lands on whichever
    # request sorts first, so the axis can say exactly which address will be
    # invented -- and tolerating it keeps a KNOWN bug from reading as a
    # regression, the same convention `ghost-shell` uses. Delete these two
    # lines when `open_text_auto` switches to `utf-8-sig`, and the check will
    # confirm the fix instead of the bug.
    if case.requests:
        from shellforge.render.accesslog import Request
        first = min(case.requests, key=Request.sort_key)
        case.truth.meta.setdefault("clients_tolerated", []).append(
            "﻿" + first.ip)
        case.truth.meta["bom_phantom_client"] = "﻿" + first.ip

    case.truth.note(
        "THE LOG CARRIES A UTF-8 BOM, AND IT INVENTS A CLIENT. "
        "`open_text_auto` opens with `encoding=\"utf-8\"` rather than "
        "`utf-8-sig`, so the mark survives decoding as U+FEFF at the head of "
        "the first line. It is not whitespace, and the Combined pattern reads "
        "the client address with `^(\\S+)` -- so the first line is attributed "
        "to `\\ufeff` plus the real address. Measured: 158 clients indexed "
        "where 157 exist, one of them an address nobody used, and one real "
        "visitor's first request charged to it. Every log ever opened in a "
        "Windows editor has this mark. The fix is one word.")


# --- broken lines -----------------------------------------------------------

@axis("broken-lines",
      "malformed lines interleaved with good ones, including an error-log "
      "line inside the access log.")
def broken_lines(case, rng):
    """Damage that does not announce itself.

    A log with a corrupt HEAD is easy: the reader fails at line one and
    somebody notices. The dangerous shape is damage in the MIDDLE, because a
    reader that abandons the file, or silently skips to the end, loses
    exactly the lines nobody knew to look for -- and the case then reports
    less than it should while looking complete.

    So these go between good lines and none of them is a finding: a truncated
    line, one with a missing field, one with a NUL byte, an Apache error-log
    line that wandered into the access log, and a bare newline.
    """
    case.raw_log_lines = [
        # Cut off mid-request, the way a rotation that raced the writer does.
        '192.0.2.51 - - [07/Jan/2026:11:04:12 +0000] "GET /kontakt/ HTT',
        # A field short.
        '192.0.2.52 - - [07/Jan/2026:11:04:13 +0000] "GET /impressum/" 200',
        # A NUL, which is what a half-flushed buffer leaves behind.
        '192.0.2.53 - - [07/Jan/2026:11:04:14 +0000] "GET /\x00 HTTP/1.1" 200 12',
        # An error-log line in the access log. Shellhound recognises error
        # logs as whole FILES; a single line of one inside an access log is
        # the case that recognition does not cover.
        '[Wed Jan 07 11:04:15.000000 2026] [php:error] [pid 7001] '
        'PHP Warning:  Undefined variable $x in /var/www/html/index.php on line 9',
        # Nothing at all.
        '',
        # A date nobody can parse.
        '192.0.2.54 - - [never] "GET / HTTP/1.1" 200 12',
    ]
    # WHETHER A CORRUPT LINE PARSES IS THE THING UNDER OBSERVATION, so the
    # addresses in them are tolerated rather than asserted either way. What
    # is asserted is that no GOOD line was lost, which is what the client
    # check compares against.
    case.truth.meta.setdefault("clients_tolerated", []).extend(
        ["192.0.2.51", "192.0.2.52", "192.0.2.53", "192.0.2.54"])
    case.truth.note(
        "SIX MALFORMED LINES SIT BETWEEN GOOD ONES: truncated, a field "
        "short, a NUL byte, an Apache error-log line that wandered in, an "
        "empty line, and an unparsable date. None of them is a finding, and "
        "none of them may cost one either -- a reader that gives up in the "
        "middle of a file loses precisely the lines nobody knew to look for, "
        "and the case then reports less than it should while looking "
        "complete.")


# --- scale ------------------------------------------------------------------

@axis("many-actors",
      "five hundred and twenty distinct clients, well over the 200-client cap.")
def many_actors(case, rng):
    """More clients than the actor list is allowed to show.

    Shellhound caps the actor list at two hundred. Under that cap the cap
    cannot be seen; over it, the question is whether what gets cut is chosen
    or merely whatever came last. The attacker in this case is one address
    among five hundred and twenty, is not the busiest, and must still be
    reported -- a work list that drops a confirmed intruder because a page
    was full is worse than a slow one.
    """
    from shellforge.render.accesslog import Request
    from shellforge import corpus

    if not case.requests:
        return
    span_start = min(r.when for r in case.requests)
    span_days = max(1, (max(r.when for r in case.requests)
                        - span_start).days or 1)
    urls = [u for u, _ in case.site.urls] or ["/"]

    added = 0
    for _ in range(520):
        # `crowd`, not `visitor`: the visitor block is a /24 and holds 254
        # addresses, so five hundred draws out of it collapse to about two
        # hundred and fifty and the axis silently stops being about scale.
        ip = rng.ip("crowd")
        when = span_start + timedelta(
            days=rng.randint(0, span_days),
            seconds=rng.randint(0, 86399))
        for _ in range(rng.randint(1, 4)):
            case.requests.append(Request(
                when=when + timedelta(seconds=rng.randint(0, 900)), ip=ip,
                method="GET", uri=rng.choice(urls), status=200,
                size=rng.randint(1800, 30000),
                agent=rng.choice(corpus.BROWSER_UAS)))
            added += 1
    case.truth.note(
        f"FIVE HUNDRED AND TWENTY MORE CLIENTS ({added} extra requests), all "
        f"ordinary visitors. The actor list caps at two hundred, so the cap "
        f"now cuts. The attacker is one address among them and is not the "
        f"busiest; every finding in this case must survive the crowd.")
