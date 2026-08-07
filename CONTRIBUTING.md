# Contributing

Bug reports and pull requests are welcome.

## Two rules that are not negotiable

**No data from real incidents.** Not in a fixture, not in a bug report, not in
a scenario. This is inherited from
[SHELLHOUND](https://github.com/Mateodevv/shellhound) and matters more here,
because a generator does not contain such data once — it emits it endlessly.
For a reproduction, describe the shape of the data or build a minimal example.

**No working attack code.** Every payload is an inert marker: the shortest text
that carries the pattern a detector looks for and does nothing else, in the
spirit of an EICAR file. If a new marker is needed, put it in
[`shellforge/markers.py`](shellforge/markers.py) next to the others, say which
rule it exists to trigger, and prove it triggers that rule and no other.

There is a practical reason on top of the principled one: on Windows, Defender
intervenes when a file is **opened**, not when it is written. A real payload
gets quarantined between generating and reading, and the failure surfaces as
`OSError(22)` — which reads like a bug in this tool rather than like a scanner.

## The architectural rule

**Shellforge must never import, copy or mirror SHELLHOUND's detection code.**

A generator that knew how the rules worked would generate exactly the data
those rules already pass, and the score would measure nothing but its own
assumptions. Shellforge states independently what was planted; SHELLHOUND
states independently what it sees; the diff is the test.

The two places SHELLHOUND is imported at all are
[`shellforge/runner.py`](shellforge/runner.py), which calls `scan()` and reads
the `findings` table afterwards, and `score.shellhound_rule_ids()`, which asks
for the rule catalogue so the coverage section is not a hardcoded list that
drifts. Neither reimplements a rule.

## A new scenario

1. Add a module under [`shellforge/scenarios/`](shellforge/scenarios/) and
   decorate its builder with `@register("name")`.
2. Plant every object with the rule ids it owes, and say in the `note` why.
3. Add the silence assertions. **This is the half that gets forgotten** and
   the half that measures precision.
4. Keep the four evidence kinds consistent: a file must be requested in the
   log *after* it appeared, an account must be registered inside the window
   the log says somebody was logging in. `tests/test_shellforge.py` checks the
   first of those; add a check for whatever your scenario claims.
5. Run `python -m shellforge check --scenario <name> --shellhound ../shellhound`
   until recall and precision are both 100%. If one of them will not reach
   100%, that is either a bug in the scenario or a finding about SHELLHOUND —
   say which in the pull request.

Prefer a scenario that exercises a rule nothing currently reaches. The
coverage line of the score report names them.

## A new CMS profile

Implement `build(rng, scale) -> Site` under
[`shellforge/world/`](shellforge/world/) and register it in
`generate.WORLDS`. Put version markers exactly where SHELLHOUND reads them,
and get the account table's column order right — WordPress and Joomla accounts
are read **by position**, so a tidied-up column order parses into nonsense.

A profile whose baseline files accidentally trip a rule turns a precision test
into a false-negative test without anybody noticing. Generated files carry the
CMS bootstrap guard and no call the content rules look for.

## Tests

```bash
python -m unittest discover -s tests -t .
```

Everything must stay seeded. `random` at module level, `time.time()`,
`uuid4()`, `os.urandom` and iteration over a set will all pass review once and
then produce a case that cannot be reproduced from its seed — which makes
every failure a rumour.
