# tests/test_shellforge.py
"""Tests of the generator itself.

NOT tests of Shellhound. The whole point of the separation is that this
repository does not know how the rules work, so what is checked here is the
generator's own promises: that a seed determines the bytes, that a marker
trips the rule it claims to and no other, and that the ground truth is
internally consistent.

The end-to-end test (generate -> analyse -> score) needs a Shellhound
checkout and SKIPS without one, loudly. A test that silently passes when it
could not run is worse than no test.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shellforge import markers, scenarios          # noqa: E402
from shellforge.generate import generate           # noqa: E402
from shellforge.rng import Rng                     # noqa: E402
from shellforge.score import score, site_path      # noqa: E402

SHELLHOUND = Path(__file__).resolve().parents[2] / "shellhound"


class SeedDeterminism(unittest.TestCase):
    """Same seed, same bytes. Everything else here depends on this."""

    def test_same_seed_same_digest(self):
        digests = []
        for _ in range(2):
            with tempfile.TemporaryDirectory() as tmp:
                digests.append(generate(scenario="wp-upload-shell", seed=1234,
                                        out=Path(tmp))["digest"])
        self.assertEqual(digests[0], digests[1],
                         "the same seed produced two different cases -- "
                         "something unseeded got in")

    def test_different_seeds_differ(self):
        out = []
        for seed in (1, 2):
            with tempfile.TemporaryDirectory() as tmp:
                out.append(generate(scenario="wp-upload-shell", seed=seed,
                                    out=Path(tmp))["digest"])
        self.assertNotEqual(out[0], out[1])

    def test_substreams_are_independent(self):
        """Drawing from one stream must not shift another.

        Without this, adding a file to the webroot changes every log line and
        diffing two runs stops saying anything about what actually changed.
        """
        root = Rng(5)
        logs_first = [root.derive("logs").randint(0, 10**6) for _ in range(3)]
        root2 = Rng(5)
        root2.derive("world").randint(0, 10**6)      # drain a sibling
        logs_after = [root2.derive("logs").randint(0, 10**6) for _ in range(3)]
        self.assertEqual(logs_first, logs_after)


class GroundTruthShape(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        summary = generate(scenario="wp-upload-shell", seed=42,
                           out=Path(cls.tmp.name))
        cls.case = Path(summary["case_dir"])
        cls.truth = json.loads(
            (cls.case / "ground_truth.json").read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_every_planted_file_exists_and_matches_its_hash(self):
        import hashlib
        for planted in self.truth["planted"]:
            if planted["kind"] != "file":
                continue
            path = self.case / "webroot" / planted["ident"].lstrip("/")
            self.assertTrue(path.is_file(), f"{planted['ident']} not written")
            got = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(got, planted["sha256"],
                             f"{planted['ident']}: ground truth records a hash "
                             f"that is not what is on disk")

    def test_planted_and_quiet_do_not_overlap(self):
        """An object cannot be both required to fire and required to be silent
        about the same rule -- that is a scenario contradicting itself."""
        planted = {p["ident"]: set(p["expect_rules"])
                   for p in self.truth["planted"]}
        for entry in self.truth["must_not_fire"]:
            overlap = planted.get(entry["ident"], set()) & set(entry["rules"])
            self.assertFalse(overlap,
                             f"{entry['ident']} is required to produce "
                             f"{overlap} and forbidden from producing it")

    def test_reference_copy_lacks_exactly_what_was_added(self):
        for planted in self.truth["planted"]:
            if planted["kind"] != "file":
                continue
            rel = planted["ident"].lstrip("/")
            # Only the files the attack ADDED are absent from the reference;
            # the legitimate noisemakers were there all along.
            if "wp-file-manager/lib/files" in rel or "uploads/2026/01" in rel:
                self.assertFalse((self.case / "reference" / rel).exists(),
                                 f"{rel} is in the clean reference copy")

    def test_timeline_is_ordered_and_complete(self):
        stamps = [e["at"] for e in self.truth["timeline"]]
        self.assertEqual(stamps, sorted(stamps))
        acts = {e["act"] for e in self.truth["timeline"]}
        for required in ("exploit", "drop_shell", "use_shell", "persistence"):
            self.assertIn(required, acts)

    def test_shell_is_requested_only_after_it_appears(self):
        """The cross-consistency claim, checked rather than asserted.

        A log that fetches a file before it was dropped is the single most
        common way generated evidence gives itself away.
        """
        drop = next(e for e in self.truth["timeline"]
                    if e["act"] == "drop_shell")
        shell = drop["detail"]
        log = (self.case / "logs" / "access.log").read_text(encoding="utf-8")
        hits = [line for line in log.splitlines() if shell in line]
        self.assertTrue(hits, "the dropped shell is never requested")
        stamp = drop["at"].replace("T", ":").replace("Z", "")
        day = stamp.split(":")[0]
        for line in hits:
            self.assertGreaterEqual(
                _apache_iso(line), drop["at"],
                f"the shell was requested before it was dropped ({day})")


def _apache_iso(line: str) -> str:
    """`[05/Jan/2026:09:12:33 +0000]` -> `2026-01-05T09:12:33Z`."""
    from datetime import datetime
    raw = line.split("[", 1)[1].split("]", 1)[0]
    when = datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z")
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


class MarkersAreSingleRuleProbes(unittest.TestCase):
    """Each marker trips the rule it claims and nothing else.

    This is the one place Shellhound is imported, and only to ask it what it
    thinks of a byte string -- no rule is copied or reimplemented here.
    """

    @classmethod
    def setUpClass(cls):
        if not (SHELLHOUND / "server").is_dir():
            raise unittest.SkipTest(f"no Shellhound checkout at {SHELLHOUND}")
        sys.path.insert(0, str(SHELLHOUND))

    def _rules_for(self, name: str, body) -> set:
        from server.engines import webshell
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "webroot"
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body.encode() if isinstance(body, str) else body)
            findings, _skip, _inert = webshell.scan_file(str(path), str(root))
        return {f[0] for f in findings}

    def test_command_marker_does_not_also_trip_standalone_exec(self):
        """`system` is deliberately absent from the standalone rule, which is
        what keeps this marker a single-rule probe. If that ever changes the
        scenario's expectations silently become wrong."""
        got = self._rules_for("wp-content/uploads/x.php", markers.CMD_INPUT)
        self.assertIn("webshell.cmd_input", got)
        self.assertNotIn("webshell.standalone_exec", got)

    def test_double_extension_marker_stays_inert(self):
        got = self._rules_for("wp-content/uploads/a.pdf.php",
                              markers.INERT_BODY)
        self.assertEqual(got, {"webshell.double_ext"},
                         "the disguise marker must not also look executable")

    def test_genuine_core_file_is_silent(self):
        self.assertEqual(
            self._rules_for("wp-includes/functions.php", markers.GENUINE_CORE),
            set())

    def test_clean_htaccess_is_silent(self):
        self.assertEqual(
            self._rules_for("wp-content/uploads/.htaccess",
                            markers.HTACCESS_CLEAN),
            set())


class EndToEnd(unittest.TestCase):
    """Generate, analyse, score. The loop the whole thing exists to close."""

    def _score(self, scenario, seed=42):
        from shellforge.runner import analyse
        from shellforge.score import load_truth, read_findings

        with tempfile.TemporaryDirectory() as tmp:
            summary = generate(scenario=scenario, seed=seed, out=Path(tmp))
            case = Path(summary["case_dir"])
            analyse(case / "sh", webroot=case / "webroot",
                    logs=case / "logs", dump=case / "dump.sql",
                    shellhound=SHELLHOUND)
            return score(load_truth(case / "ground_truth.json"),
                         read_findings(case / "sh" / "case.db"))

    def test_every_scenario_scores_clean(self):
        if not (SHELLHOUND / "server").is_dir():
            self.skipTest(f"no Shellhound checkout at {SHELLHOUND}")
        for scenario in scenarios.names():
            with self.subTest(scenario=scenario):
                result = self._score(scenario)
                self.assertEqual(result.misses, [], "planted but not reported")
                self.assertEqual(result.false_positives, [],
                                 "reported but not planted")
                self.assertEqual(result.violations, [],
                                 "a named silence assertion broke")
                self.assertEqual(result.wrong_severity, [])

    def test_the_catalogue_reaches_almost_every_rule(self):
        """Coverage is a property of the CATALOGUE, not of one case.

        The threshold is deliberately not 100%: `webshell.unreadable` needs a
        genuine read error and is POSIX-only, so a Windows run legitimately
        falls one short. A drop below this means a scenario stopped firing.
        """
        if not (SHELLHOUND / "server").is_dir():
            self.skipTest(f"no Shellhound checkout at {SHELLHOUND}")
        from shellforge.score import coverage, shellhound_rule_ids
        fired = set()
        for scenario in scenarios.names():
            fired |= self._score(scenario).fired_rules
        cov = coverage(fired, shellhound_rule_ids(SHELLHOUND))
        self.assertGreaterEqual(
            cov["ratio"], 0.97,
            f"catalogue coverage fell to {cov['ratio']:.1%}; "
            f"not exercised: {cov['never_fired']}")


class PathNormalisation(unittest.TestCase):

    def test_windows_and_posix_roots_both_normalise(self):
        self.assertEqual(
            site_path(r"C:\cases\x\webroot\wp-content\shell.php",
                      [r"C:\cases\x\webroot"]),
            "/wp-content/shell.php")
        self.assertEqual(
            site_path("/srv/case/webroot/a/b.php", ["/srv/case/webroot"]),
            "/a/b.php")

    def test_path_outside_every_root_is_left_alone(self):
        self.assertEqual(site_path("/elsewhere/x.php", ["/srv/webroot"]),
                         "/elsewhere/x.php")


class ScoringLogic(unittest.TestCase):
    """The scorer's own arithmetic, on invented findings."""

    def _finding(self, artifact, rule, severity=0, kind="file"):
        return {"artifact": artifact, "rule_id": rule, "severity": severity,
                "artifact_kind": kind, "evidence": "", "rule": rule,
                "source": "webshell", "line": 1}

    def test_unplanted_artifact_counts_as_false_positive(self):
        truth = {"planted": [], "must_not_fire": []}
        result = score(truth, [self._finding("/a.php", "webshell.upload_php")])
        self.assertEqual(len(result.false_positives), 1)

    def test_tolerated_rule_is_not_an_extra(self):
        truth = {"planted": [{"kind": "file", "ident": "/a.php",
                              "expect_rules": ["webshell.upload_php"],
                              "expect_severity": "high",
                              "tolerate_rules": ["webshell.cmd_input"]}],
                 "must_not_fire": []}
        result = score(truth, [
            self._finding("/a.php", "webshell.upload_php"),
            self._finding("/a.php", "webshell.cmd_input")])
        self.assertEqual(result.extras, [])
        self.assertEqual(len(result.hits), 1)

    def test_severity_is_only_checked_once_the_rule_fired(self):
        """A severity complaint about a rule that never ran is noise stacked
        on top of the real failure."""
        truth = {"planted": [{"kind": "file", "ident": "/a.php",
                              "expect_rules": ["webshell.upload_php"],
                              "expect_severity": "high"}],
                 "must_not_fire": []}
        result = score(truth, [])
        self.assertEqual(len(result.misses), 1)
        self.assertEqual(result.wrong_severity, [])

    def test_named_silence_assertion_beats_the_blanket_rule(self):
        truth = {"planted": [],
                 "must_not_fire": [{"ident": "/legit.php",
                                    "rules": ["webshell.upload_php"],
                                    "reason": "guarded core file"}]}
        result = score(truth, [self._finding("/legit.php",
                                             "webshell.upload_php")])
        self.assertEqual(len(result.violations), 1)
        self.assertEqual(result.false_positives, [],
                         "one problem must not be reported twice")


class ScenarioRegistry(unittest.TestCase):

    def test_every_registered_scenario_builds(self):
        self.assertIn("wp-upload-shell", scenarios.names())
        for name in scenarios.names():
            with self.subTest(scenario=name), \
                    tempfile.TemporaryDirectory() as tmp:
                summary = generate(scenario=name, seed=3, out=Path(tmp))
                self.assertGreater(summary["planted"], 0,
                                   f"{name} plants nothing")

    def test_no_two_scenarios_produce_the_same_case(self):
        """A scenario whose narrative silently stopped running would still
        generate a valid case -- the world builds either way. Identical
        digests are what that failure looks like from outside."""
        seen = {}
        for name in scenarios.names():
            with tempfile.TemporaryDirectory() as tmp:
                digest = generate(scenario=name, seed=3,
                                  out=Path(tmp))["digest"]
            clash = seen.get(digest)
            self.assertIsNone(
                clash, f"{name} and {clash} produced byte-identical evidence; "
                       f"one of them is not doing anything")
            seen[digest] = name


if __name__ == "__main__":
    unittest.main()
