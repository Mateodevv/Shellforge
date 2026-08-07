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
| `long-tail-admin` | both | No attack at all, for long enough that it looks like one. **Reproduces a scale-dependent false positive** — see below |
| `clean-baseline` | both | A working site where nothing happened. Expectation: INFO about the scanners and nothing else |

Most scenarios name no CMS at all, and that is the point of separating world
from narrative: `bruteforce-admin` is a story about logins, not about
WordPress. A scenario that names one is doing so deliberately —
`wp-upload-shell` models a specific WordPress plugin's CVE, and running it
against Joomla would produce a case that could not have happened, so the
registry refuses the pairing rather than generating it.

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
