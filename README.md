# SHELLFORGE

**Synthetic CMS incident evidence, with a statement of what a correct
detector must make of it.**

Shellforge generates the four kinds of evidence
[SHELLHOUND](../shellhound) reads — a webroot, access logs, an error log and a
database export — and, next to them, a `ground_truth.json` saying what was
planted where and which rule owes a finding on it. That second file is the
product. The evidence is only what it talks about.

| | |
|---|---|
| **Output** | A case directory Shellhound can be pointed at, plus ground truth |
| **Measures** | Recall, precision, and which of the 34 rules a case exercises at all |
| **Dependencies** | None. Standard library only, like Shellhound's own tests |
| **Payloads** | Inert markers in the spirit of an EICAR file. Never working code |

```bash
python -m shellforge check --all --shellhound ../shellhound
```

```
scenario                 cms          recall  precision  rules   result
------------------------------------------------------------------------
bruteforce-admin         joomla      100.0%     100.0%      3   ok
clean-baseline           joomla      100.0%     100.0%      1   ok
db-only-spam             joomla      100.0%     100.0%      9   ok
false-guard              joomla      100.0%     100.0%      4   ok
ghost-shell              joomla      100.0%     100.0%      6   ok
joomla-helix3            joomla      100.0%     100.0%      6   ok
joomla-helix3-deface     joomla      100.0%     100.0%      3   ok
probe-wave               joomla      100.0%     100.0%      4   ok
shell-kit                joomla      100.0%     100.0%     13   ok
bruteforce-admin         wordpress   100.0%     100.0%      3   ok
...
wp-upload-shell          wordpress   100.0%     100.0%     12   ok

COMBINED COVERAGE  100.0%  (34/34 rules exercised by the catalogue)

PASS
```

---

## Why this is a separate tool

Shellhound's own fixtures are deliberately minimal: one tiny file per rule, so
a failure names the broken rule instead of pointing at a large blob. That is
the right design for what they are, and they stay. But they leave three things
unmeasured, and all three are the ones that bite in a real case:

**Precision.** The current suite has exactly one false-positive guard
(`wp-includes/functions.php`). A rule change that reddens a thousand
legitimate plugin files would pass it untouched. Shellforge generates a full
installation, so every file that is not planted is a silent assertion that
nothing may be reported about it.

**Cross-consistency.** Anybody can drop a suspicious file in a directory and
watch a scanner find it. What makes evidence plausible is that the file was
requested in the log *after* it appeared, by an address that did something
else first, and that the account in the dump was registered in the window the
log says somebody was logging in. A case whose four evidence kinds disagree
tests nothing except whether the tool notices they disagree.

**Scale.** 55,000 log lines per second is a claim. It needs a million lines to
be one.

### The rule that makes the number mean something

**Shellforge never imports, copies or mirrors Shellhound's detection code.**
It calls `scan()` and reads the `findings` table afterwards. A generator that
knew how the rules worked would generate exactly the data those rules already
pass, and the score would measure nothing but its own assumptions. Shellforge
says independently what was planted; Shellhound says independently what it
sees; the diff is the test.

## Install

```bash
pip install -e .
```

Or run it out of the directory with `python -m shellforge`.

## Commands

```bash
shellforge gen    --scenario wp-upload-shell --seed 42 --scale medium
shellforge score  --truth <case>/ground_truth.json --case <case.db>
shellforge check  --shellhound ../shellhound          # generate + analyse + score
shellforge check  --all --shellhound ../shellhound    # every scenario, combined coverage
shellforge scenarios
```

`check` exits non-zero on a regression, so it drops into CI as one line.

| Option | Meaning |
|---|---|
| `--seed N` | Same seed, same bytes. A failure is reproducible or it is a rumour |
| `--scale small\|medium\|large` | Roughly 900 / 19,000 / 250,000 log lines |
| `--rotate-days N` | Split the log into `access.log`, `.1`, `.2.gz`, … |
| `--log-format apache\|nginx` | |
| `--no-verify-readable` | Skip reading every file back. See *Virus scanners* below |

## What a case looks like

```
wp-upload-shell-small-42/
  webroot/            the compromised installation
  reference/          the same release, clean — the other half of a diff
  logs/               access.log[.N[.gz]], error.log
  dump.sql
  ground_truth.json   what a correct detector must say
  hunt_patterns.json  the CVE pattern this case is meant to be searched with
  README.md           the case in prose, with its timeline
```

`reference/` is worth pointing out: a clean release of exactly the right
version, byte for byte, is normally impossible to obtain for a real case. Here
both sides come out of the same generator, so the webroot diff has perfect
ground truth for free.

## Ground truth

```json
{
  "planted": [
    { "kind": "file",
      "ident": "/wp-content/plugins/wp-file-manager/lib/files/k.php",
      "expect_rules": ["webshell.upload_php", "webshell.cmd_input",
                       "errorlog.hard"],
      "expect_severity": "high",
      "sha256": "…",
      "note": "the dropped shell: unguarded PHP in a directory whose path
               carries a `files` segment, executing a request parameter,
               and named by a fatal in the error log" }
  ],
  "must_not_fire": [
    { "ident": "/wp-content/uploads/.htaccess",
      "reason": "the .htaccess WordPress itself writes. Only the one in the
                 dated subdirectory was replaced — a rule that reddens both
                 cannot tell persistence from housekeeping" }
  ],
  "timeline": [ { "at": "…", "actor": "203.0.113.42", "act": "drop_shell" } ]
}
```

`planted` measures recall. `must_not_fire` measures precision, and it names
rules rather than only paths — because some quiet-looking files legitimately
trip a MEDIUM rule. A backup plugin really does call `shell_exec`, and
`webshell.standalone_exec` really is supposed to say so. Demanding total
silence there would be demanding that Shellhound be wrong. So an entry either
forbids specific rule ids, or forbids everything when the list is empty.

Beyond that, a blanket assumption does the heavy lifting: **any finding on an
artifact that was not planted is a false positive.** The alternative is
enumerating several hundred clean files and quietly forgiving whatever was
forgotten.

## Scenarios

Ten scenarios across two CMS profiles — 17 valid pairings, together
exercising all 34 of Shellhound's rules.

| Scenario | CMS | What it is for |
|---|---|---|
| `wp-upload-shell` | WordPress | The standard case, modelled on CVE-2020-25213 |
| `joomla-helix3` | Joomla | CVE-2026-49049, RCE variant. **Reproduces a detection gap** — see below |
| `joomla-helix3-deface` | Joomla | The same CVE, database variant: the webroot stays byte-identical to a clean install |
| `shell-kit` | both | A whole toolkit in the theme directory — the content rules on their own, without the location rule doing their work |
| `bruteforce-admin` | both | No file artifact at all. Two floods: one gets a redirect and must go HIGH, one does not and must stay MEDIUM |
| `db-only-spam` | both | Webroot clean, code in the database — the case that survives restoring from backup |
| `probe-wave` | both | Identical SQLi and traversal payloads, one address answered 200 and one answered 404. Outcome gating, both halves |
| `false-guard` | both | A forged guard string in a comment. The documented limitation, pinned from both sides |
| `ghost-shell` | both | Shell deleted before the copy was taken. **Reproduces a discrepancy** — see below |
| `revslider-lfi` | WordPress | CVE-2015-1579. Two addresses, identical requests, both answered 200 — one took the database credentials. **Outcome gating has nothing to gate on** |
| `long-tail-admin` | both | No attack at all, for long enough that it looks like one. **Reproduces a scale-dependent false positive** — see below |
| `clean-baseline` | both | A working site where nothing happened. Expectation: INFO about the scanners and nothing else |

Most scenarios name no CMS at all, and that is the point of separating world
from narrative: `bruteforce-admin` is a story about logins, not about
WordPress. A scenario that names one is doing so deliberately —
`wp-upload-shell` models a specific WordPress plugin's CVE, and running it
against Joomla would produce a case that could not have happened, so the
registry refuses the pairing rather than generating it.

## Case evolution: does a decision still mean anything?

Shellhound promises that "triage states survive re-scans; fingerprints are
stable", and everything about how an analyst works depends on it. Evidence
arrives in instalments — a second webroot copy, another week of logs — the
case is re-scanned, and the decisions already made either survive or they do
not. If they do not, nobody finds out by reading the screen: an artifact that
quietly went back to undecided looks exactly like one nobody has got to yet.

```bash
python -m shellforge evolve --scenario wp-upload-shell --shellhound ../shellhound
```

This is the only check here that does not score findings against a ground
truth. It compares **two runs of the same case** with a human decision in
between: generate v1 → analyse → decide (confirm, dismiss, review) → generate
v2 with a second wave **into the same directory** → re-scan the same
`case.db` → is every decision still attached to what it was made about?

The decisions land on exactly the artifacts the second wave will touch,
worked out from v1's own ground truth. Three roles, and the difference
between them is the point:

| Role | What happens to it | Expected |
|---|---|---|
| `log_only` | the attacker returns and fetches the shell again; the file is untouched | decision holds |
| `appended` | the shell gains lines *after* its payload | line unchanged, fingerprint holds |
| `prepended` | the shell gains lines *before* its payload | the finding **moves** |

### What it found

```
SPLIT -- the decision survived, what it describes did not
  01/cache-warm.php: webshell.obfuscation
      reviewed at line 2, where there is now nothing
      new and undecided at line 4, where the payload actually is
```

The fingerprint is `source|rule|artifact|line`. Edit a file *above* its
payload and every content finding in it moves — so the old finding keeps the
decision while describing a line that no longer holds, and the real one comes
back undecided. The analyst is asked twice and the case reports one problem as
two. Positional rules (`upload_php`, `double_ext`) are stored with `line=None`
and are unaffected, which is why the check insists the prepended file has a
content rule at all.

`SPLIT` is reported every run and does not fail the build — the same
convention `ghost-shell` uses for a reproduced, already-documented defect.

## Hostile axes

An axis reshapes **finished evidence**. `wp-upload-shell` describes an
intrusion; whether the log arrived with a byte-order mark, in Latin-1, with
six hundred clients in it, or from a server whose clock disagreed with the
database's, is a property of the evidence and not of what happened. So the
axes compose with every scenario and every profile.

```bash
python -m shellforge check --all --hostile all --shellhound ../shellhound
```

**The oracle is one sentence: the axis must not change the answer.** The
ground truth is built before the axis is applied and stays exactly as it was,
so `--hostile` needs no new assertions — it re-runs the existing ones over a
harder file. Anything that drops out is a reader losing evidence rather than a
detector disagreeing. And because each axis runs on its own, a failure has
exactly one difference to explain.

| Axis | What it does to the file |
|---|---|
| `hoster-fields` | Writes the log the way a shared host does — Combined plus Plesk's `"Traffic IN:… OUT:…"` and `"ReqTime:… sec"`. See *Calibrated against real evidence* below |
| `encoding` | UTF-8 BOM, a genuinely Latin-1 log, CRLF line endings, a multi-kilobyte request line |
| `broken-lines` | Truncated, field-short, NUL-bearing, undated and empty lines *between* good ones, plus an Apache error-log line that wandered in |
| `many-actors` | 677 distinct clients, well past the 200-client cap. The attacker is one of them and is not the busiest |
| `clock-skew` | Every database timestamp two hours ahead of the log's. Only the dump moves |

### A second oracle: the client list

Findings cannot see a reader that loses a line or invents a client — ordinary
visitor traffic produces no findings either way. So the ground truth records
**every address the generator emitted**, and the score compares it against the
indexed client list:

```
clients       158   (of 157 generated; 1 phantom, 0 lost)
```

*phantom* is an address the index claims and nobody used; *lost* means lines
went missing and nobody would notice which.

### encoding found a live one

`open_text_auto` opens logs with `encoding="utf-8"` rather than `utf-8-sig`,
so a byte-order mark survives decoding as `﻿` at the head of the first
line. It is not whitespace, and the Combined pattern reads the client with
`^(\S+)` — so the first line is attributed to `﻿` plus the real address.

Measured: **158 clients indexed where 157 exist**, one of them an address
nobody used, and one real visitor's first request charged to it. Every log
ever opened in a Windows editor carries that mark. The fix is one word.

## Calibrated against real evidence

The generated logs were compared with two real hoster access logs from
unrelated incidents. Statistics only — nothing from them is in this
repository, and none of it ever will be. The first comparison was
uncomfortable:

| | real A / real B | before | now |
|---|---|---|---|
| trailing fields | vhost + 3 quoted / 4 quoted | 2 quoted | all three shapes |
| size field is `-` | 12.1% / 13.0% | 0% | 15% |
| size median | 18,020 / 4,024 | 19,156 | 17,407 |
| requests per client (median) | 2 / 1 | 21 | 1 |
| clients seen exactly once | 32% / 53% | 0% | 56% |
| distinct user agents | 680 / 230 | 12 | 327 |
| URIs with a query | 21.6% / 35.6% | 0.1% | 34% |
| static assets | 45–48% | 14% | ~53% |
| referer set | 66.5% / 57.6% | 37% | 67% |
| busiest hour ÷ quietest | 8.8× / 6.1× | **204×** | 6–8× |
| methods | GET, POST, HEAD, OPTIONS | GET, POST | all four |
| statuses | incl. 429, 403, 500 | five kinds | incl. all |

The webroot was measured the same way, against the real installation from the
same case:

| | real | before | now |
|---|---|---|---|
| files | 1,744 | 149 | 1,528 |
| `.php` files | 669 | **69 at every scale** | 749 |
| `.php` size median / p90 | 2,844 / 16,858 | 274 / 301 | 3,166 / 20,018 |
| `.ini` language files | 382 | 0 | 422 |
| `.html` index guards | 276 | 3 | 280 |
| all files, median size | 1,507 | 86 | 1,472 |

The PHP count was not tied to `--scale` at all: `--scale large` grew the log
and the uploads and left the installation the same 69 files. Precision is
measured against the files that must stay silent, so it was measuring a tenth
of the surface it claimed. Two thirds of a real CMS tree is translation files
and empty `index.html` guards — boring, one line each, and entirely absent.

Three of the log findings mattered more than the rest:

**Neither real log was plain Combined.** One carried an unquoted vhost token
between the size and the referer; the other carried Plesk's two trailing
fields. Shellhound's `LOG_PATTERN` has an explicit branch for each, with a
comment calling them years of real-webhost quirks whose removal "would
silently drop exactly the attacker lines the index exists to answer about" —
and nothing generated here had ever exercised either. The most load-bearing
part of the parser was the one part the test data never touched.

**The long tail was missing entirely.** Half of all clients in a real log
appear exactly once, and together they account for only 2–7% of the lines. A
session model cannot produce that, because a session is a browser and a
browser fetches a dozen files. It needed a separate population of
single-request addresses — link-followers, feed readers, uptime probes — 90%
of which carry no referer.

**The night floor was zero.** Traffic ran 06:00–22:00 and stopped, giving a
busiest-to-quietest ratio of 204× where reality is 6–9×. Any quiet-window
reasoning would have looked flawless here and failed in the field.

None of this changes recall or precision — those measure what they measure.
What it changes is whether "realistic" was a claim or a measurement.

## World profiles

| | WordPress | Joomla |
|---|---|---|
| Version read from | `wp-includes/version.php` | `libraries/src/Version.php` (4/5) or `libraries/cms/version/version.php` (3) |
| Accounts | `wp_users`, by column position | `#__users`, by column position |
| Who is an administrator | serialized role in `wp_usermeta` | `#__user_usergroup_map`, group **8** |
| Uploads land in | `wp-content/uploads` | `images` |
| Guard string | `ABSPATH` / `WPINC` | `_JEXEC` |

Joomla is the second profile rather than Drupal because Shellhound parses
WordPress and Joomla *in detail* and merely recognises the rest — so Joomla is
the only other CMS where a generated case can be wrong in an interesting way
(wrong column order, wrong version file, wrong group id) instead of falling
through to the generic path where almost anything parses.

Run them all, with coverage summed over the catalogue:

```bash
python -m shellforge check --all --shellhound ../shellhound
```

```
scenario               recall  precision  rules   result
------------------------------------------------------------
bruteforce-admin      100.0%     100.0%      3   ok
clean-baseline        100.0%     100.0%      1   ok
db-only-spam          100.0%     100.0%      9   ok
false-guard           100.0%     100.0%      4   ok
ghost-shell           100.0%     100.0%      6   ok
probe-wave            100.0%     100.0%      4   ok
shell-kit             100.0%     100.0%     13   ok
wp-upload-shell       100.0%     100.0%     12   ok

COMBINED COVERAGE  97.1%  (33/34 rules exercised by the catalogue)
```

Coverage is only meaningful in aggregate. Per case it says what one narrative
happened to touch, which is not a fact about the rule set. The one rule left
is `webshell.unreadable`, which needs a genuine filesystem read error:
`chmod 000` on POSIX, and nothing a generator can rely on under Windows. The
scenario plants it on POSIX and writes a note into the ground truth on
Windows rather than quietly claiming coverage the platform does not have.

### bruteforce-admin reproduces a detection gap on WordPress

`logs.login_success` — the only HIGH log rule about a successful break-in —
needs a flood **plus** a 2xx from the authenticated backend. That second
condition is right: it replaced "plus a redirect", which Joomla hands out for
every login attempt whether the password was correct or not.

But `AUTHENTICATED_AREA_RE` is `/administrator/index.php?…option=com_…` —
Joomla's URL shape, and only that. No WordPress admin URL matches it, while
`wp-login.php` *is* a recognised login endpoint. So on WordPress the flood
half fires and the proof half has nothing to match on, and **the rule cannot
fire at all** on the most widely deployed CMS there is.

The scenario runs on both profiles and asserts the difference: on Joomla the
intruder produces both rules; on WordPress the ground truth expects the flood
and explicitly forbids the success, with the reason attached.

The natural WordPress analogue would be `/wp-admin/` excluding
`admin-ajax.php` and `admin-post.php`, which are reachable without a session.

### revslider-lfi: the status code cannot separate them

Slider Revolution before 3.0.96 read any file the query string named, and
`admin-ajax.php` **answers 200 whether the read worked or not**. A success
returns `wp-config.php` — database host, user, password, salts. A failure
returns a few dozen bytes. Both are `200`.

Outcome gating on the status code is right in general and useless here. The
case contains two addresses sending the *same* requests:

| | answered | response size |
|---|---|---|
| exfiltrated | 200 | 2,900–5,200 bytes — the file came back |
| repelled | 200 | 41 bytes — nothing came back |

A correct run today reports them **identically**, and the ground truth says
so rather than pretending otherwise. The discriminator that does exist is the
response size, which the combined log format has carried all along in a
column nothing reads. The sizes are recorded under `byte_counts` so a future
rule has something to be checked against.

Two further things this case pins, both measured rather than assumed:

- The vulnerable slider sits **inside the theme**, not in
  `wp-content/plugins` — that is how the CVE spread, because the site owner
  did not know they had it. The CMS inventory consequently does not list it,
  so "check the version in the inventory" does not work for this class. The
  shipped hunt pattern says so instead of repeating the advice.
- Nothing was dropped. It is a read: the webroot is untouched and what the
  attacker took left in a response body, which is the one thing an access log
  never keeps.

### long-tail-admin reproduces a scale-dependent false positive

`logs.login_flood` triggers on thirty login POSTs from one address;
`logs.login_success` on thirty plus a 3xx. Neither counts within a time
window, so the threshold is not a statement about behaviour — it is a
statement about how long somebody kept their logs.

One administrator, one office address, one login every working morning, each
answered with the redirect a successful login produces:

| | |
|---|---|
| after ~6 weeks | ~30 logins → flood. MEDIUM |
| after ~9 weeks | ~46 logins, plus the backend pages they legitimately opened → **HIGH** on Joomla |

Nothing about the site changed and nobody attacked it. The case contains no
attacker at all — clean webroot, untouched database, every probe answered 404
— and carries a **second** administrator with identical habits but fewer days
present, who stays silent. The two differ in nothing except how long they
appear in the log.

The proof-of-access half of the rule is doing its job here; the administrator
matches it because they really did log in. What is left is the **count**:
thirty login POSTs with no time window is a threshold on the length of the
log, not on anybody's behaviour. The index already carries the timestamps, and
already counts `login_statuses` — a brute force leaves a long tail of failures
before it succeeds, and this administrator left none.

Found by the scale test rather than by inspection: `--scale large` generates
sixty days of traffic and the site's own editor crossed the threshold.
`common.plant_editor` now counts the logins it generated and predicts the
consequence, so every scenario stays honest at every scale instead of flipping
at one.

### joomla-helix3 reproduces a detection gap

Helix3 appends `.json` to the layout name it writes, so the traversal
`../../up.php` lands in the webroot as **`up.php.json`**. That file is
invisible to all three engines at once, and each for its own reason:

| Engine | Why it says nothing |
|---|---|
| `webshell.double_ext` | `DOUBLE_EXT_RE` matches *harmless-then-executable* (`logo.jpg.php`). This name is the other way round |
| content rules | `.json` is not in `PHP_EXTS`, so the file is never opened for scanning |
| `errorlog.hard` | `_PATH_RE` stops the captured path at `.php`, so the fatal resolves to `/var/www/html/up.php` — which does not exist |

The file is nonetheless executable: Apache's `mod_mime` dispatches on any
extension present in the name, which is precisely why the exploit writes it in
that shape.

The scenario carries a conventionally-named shell from the same intrusion as a
**control**, so "nothing was found" cannot be confused with "the engines never
ran" — that one is found normally.

### ghost-shell reproduces a discrepancy in Shellhound

`docs/rules.md` says the error-log engine catches "a file deleted before the
copy was taken", and that "for that last one the log is the only remaining
evidence that the path existed at all". Six lines later it says "a path is
only written when it resolves to a file under a registered webroot".

Both cannot hold. `errorlog._resolver()` requires `os.path.isfile()`, so a
fatal naming a deleted file is counted under `unresolved` and produces no
finding — measured, not inferred.

The scenario encodes **what happens**, not what is documented: the ghost is
planted with no expected rules, alongside a control shell that *is* present,
so "no finding" cannot be confused with "the engine never ran". If Shellhound
is changed, the finding appears and the scorer reports it under EXTRA — which
is informational, so a fix does not turn the build red but does not go
unnoticed either.

### wp-upload-shell

Modelled on CVE-2020-25213 (WP File Manager 6.0–6.8 shipped an
unauthenticated elFinder connector). It was chosen because it is the only
WordPress case in [`docs/cve-log-signatures.md`](docs/cve-log-signatures.md)
where a distinctive exploit request, a distinctive follow-up request *and* a
real drop directory are all documented from a primary source — so the whole
chain log → webroot → chronology can be made consistent without inventing the
middle of it.

One step is there specifically because it is **invisible**: the exploit
`POST` to `connector.minimal.php` sits outside every upload directory, so no
built-in rule sees it. That is not a gap — it is the case for the pattern
library, which is why the generated `hunt_patterns.json` carries the CVE
pattern that finds it.

## Payloads

Everything is an inert marker: the shortest text that carries a pattern and
does nothing. No shell here works, and none ever should. The spellings are
lifted from Shellhound's own `tests/fixtures.py` where one existed, because
those have been proven to survive a scanner on this class of machine.

### Virus scanners

On Windows, Defender intervenes when a file is **opened**, not when it is
written. So generating succeeds and the failure arrives much later as
`engine found nothing`, which reads like a bug in the detector. Shellforge
therefore reads every generated file back before returning, and fails loudly
with the file name if one has been eaten. Exclude the output directory from
real-time scanning; `--no-verify-readable` only turns the check off, not the
problem.

## Tests

```bash
python -m unittest discover -s tests -t .
```

They test the generator's own promises — that a seed determines the bytes,
that a marker trips the rule it claims and no other, that the ground truth
matches what is on disk, and that the shell is never requested before it was
dropped. The end-to-end test needs a Shellhound checkout and **skips loudly**
without one; a test that silently passes when it could not run is worse than
no test.

## Documents

- [`docs/concept.md`](docs/concept.md) — the design, in full
- [`docs/cve-log-signatures.md`](docs/cve-log-signatures.md) — verified CVE
  catalogue per CMS: exact access-log signatures, drop paths, confidence
  ratings, and which CVEs are structurally invisible in a log

## Licence

Apache-2.0, matching Shellhound.
