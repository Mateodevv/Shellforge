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
python -m shellforge check --shellhound ../shellhound
```

```
generated  wp-upload-shell-small-42  (95 files, 884 log lines)
analysed   95 files | 884 log lines indexed

SHELLFORGE SCORE -- wp-upload-shell | seed 42

  recall     100.0%   (16/16 planted objects fully found)
  precision  100.0%   (0 findings about nothing planted)
  coverage    35.3%   (12/34 rules exercised by this case)

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

| Scenario | What it is for | Status |
|---|---|---|
| `wp-upload-shell` | The standard case, modelled on CVE-2020-25213 | **done** |
| `bruteforce-admin` | No file artifact at all — log and database only | planned |
| `db-only-spam` | Injected content, webroot clean | planned |
| `ghost-shell` | Shell deleted before the copy; only the error log remembers | planned |
| `false-guard` | Forged `_JEXEC` — the documented limitation, as a test | planned |
| `clean-baseline` | Expectation: **zero** findings | planned |
| `noisy-but-clean` | Legitimate `shell_exec`, tracking scripts, scanner floods | planned |
| `multi-wave` | Two attackers, overlapping windows | planned |

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
