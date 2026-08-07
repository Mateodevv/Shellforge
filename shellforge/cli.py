# shellforge/cli.py
"""Command line.

    shellforge gen    --scenario wp-upload-shell --seed 42
    shellforge score  --truth <case>/ground_truth.json --case <db>
    shellforge check  --scenario wp-upload-shell --shellhound ../shellhound

`check` is the one that matters: generate, analyse, score, exit non-zero on a
regression. Everything else exists so the three halves can be run apart when
something needs looking at by hand.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

from shellforge import hostile, scenarios
from shellforge.generate import generate
from shellforge.score import (check_clients, clients_ok, coverage,
                              load_truth, read_findings, report, score,
                              shellhound_rule_ids)

DEFAULT_SHELLHOUND = Path(__file__).resolve().parents[2] / "shellhound"


def _add_gen_args(parser):
    parser.add_argument("--scenario", default="wp-upload-shell")
    parser.add_argument("--cms", default="wordpress")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--scale", default="small",
                        choices=["small", "medium", "large"])
    parser.add_argument("--log-format", default="apache",
                        choices=["apache", "nginx"])
    parser.add_argument("--rotate-days", type=int, default=0,
                        help="split the access log every N days; 0 = one file")
    parser.add_argument(
        "--hostile", default="",
        help="comma-separated axes to reshape the evidence along, or `all`. "
             "An axis changes the SHAPE of the evidence and never the ground "
             "truth, so it re-runs the existing assertions over a harder "
             f"file. Available: {', '.join(hostile.names())}")
    parser.add_argument(
        "--no-verify-readable", action="store_true",
        help="skip reading every generated file back. Only when you already "
             "know the copy is incomplete -- on Windows this check is what "
             "turns a virus scanner eating the evidence into an error "
             "message instead of a mysteriously empty result")


def cmd_gen(args) -> int:
    summary = generate(
        scenario=args.scenario, cms=args.cms, seed=args.seed,
        scale=args.scale, out=Path(args.out), log_format=args.log_format,
        rotate_days=args.rotate_days, verify=not args.no_verify_readable)
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"case written to {summary['case_dir']}")
        print(f"  {summary['files']} files | {summary['requests']} log lines "
              f"| {summary['error_lines']} error lines")
        print(f"  {summary['planted']} planted | "
              f"{summary['must_not_fire']} silence assertions")
        print(f"  digest {summary['digest']}")
    return 0


def cmd_score(args) -> int:
    truth = load_truth(Path(args.truth))
    findings = read_findings(Path(args.case))
    result = score(truth, findings)
    known = shellhound_rule_ids(args.shellhound)
    cov = coverage(result.fired_rules, known) if known else None
    print(report(result, truth, cov))
    return 0 if result.ok else 1


def _axes(raw: str):
    """`--hostile` as a list. `all` means every axis, applied together."""
    if not raw:
        return []
    if raw.strip() == "all":
        return hostile.names()
    return [a.strip() for a in raw.split(",") if a.strip()]


def _run_one(args, scenario: str, workdir: Path, quiet: bool = False,
             cms: str = "", axes=()):
    """Generate, analyse and score one scenario. Returns (result, truth)."""
    from shellforge.runner import analyse

    summary = generate(
        scenario=scenario, cms=cms or args.cms, seed=args.seed,
        scale=args.scale, out=workdir, log_format=args.log_format,
        rotate_days=args.rotate_days, verify=not args.no_verify_readable,
        hostile=axes)
    case_path = Path(summary["case_dir"])
    if not quiet:
        print(f"generated  {case_path.name}  "
              f"({summary['files']} files, {summary['requests']} log lines)")

    stats = analyse(
        case_path / "shellhound-case",
        webroot=case_path / "webroot",
        logs=case_path / "logs",
        dump=case_path / "dump.sql",
        shellhound=Path(args.shellhound))
    if not quiet:
        print(f"analysed   {stats['webshell'].get('scanned', '?')} files | "
              f"{stats['logs'].get('lines', '?')} log lines indexed")
        print()

    truth = load_truth(case_path / "ground_truth.json")
    findings = read_findings(case_path / "shellhound-case" / "case.db")
    clients = check_clients(truth,
                            case_path / "shellhound-case" / "logindex.db")
    return score(truth, findings), truth, case_path, clients


def cmd_check(args) -> int:
    """Generate, analyse and score in one go."""
    workdir = Path(args.out) if args.out else Path(
        tempfile.mkdtemp(prefix="shellforge-check-"))
    keep = bool(args.out)
    known = shellhound_rule_ids(args.shellhound)
    try:
        if not args.all:
            result, truth, case_path, clients = _run_one(
                args, args.scenario, workdir, axes=_axes(args.hostile))
            cov = coverage(result.fired_rules, known) if known else None
            print(report(result, truth, cov, clients))
            if keep:
                print(f"\ncase kept at {case_path}")
            return 0 if result.ok and clients_ok(clients) else 1

        # --- every scenario, with coverage summed over all of them ----------
        # COVERAGE IS ONLY MEANINGFUL IN AGGREGATE. Measured per case it says
        # what one narrative happened to touch, which is not a fact about the
        # rule set. Measured over the whole catalogue it says which rules no
        # case in this repository can fail on -- and that is the work list.
        # EVERY VALID PAIRING, not every scenario. A scenario that runs
        # against both profiles is two cases, and the Joomla one exercises a
        # different account parser, a different version file and a different
        # writable directory -- which is the entire reason the world and the
        # narrative were separated.
        from shellforge.generate import WORLDS
        if args.hostile.strip() == "all":
            # EACH AXIS ON ITS OWN, plus the plain shape. Applying all four
            # at once and watching it break tells you nothing: the value of
            # an axis is that a failure has exactly one difference to explain.
            shapes = [()] + [(a,) for a in hostile.names()]
        else:
            shapes = [tuple(_axes(args.hostile))]
        pairs = [(scenario, cms, shape)
                 for cms in sorted(WORLDS)
                 for scenario in scenarios.names(cms)
                 for shape in shapes]

        fired: set = set()
        failed = []
        wide = any(shape for _s, _c, shape in pairs)
        head = f"{'scenario':<24} {'cms':<10}"
        if wide:
            head += f" {'shape':<14}"
        print(head + f" {'recall':>8} {'precision':>10} {'rules':>6}   result")
        print("-" * (72 + (15 if wide else 0)))
        for scenario, cms, shape in pairs:
            result, truth, _path, clients = _run_one(
                args, scenario, workdir, quiet=True, cms=cms, axes=shape)
            fired |= result.fired_rules
            good = result.ok and clients_ok(clients)
            status = "ok" if good else "FAIL"
            label = f"{scenario} [{cms}]" + (f" +{'+'.join(shape)}"
                                             if shape else "")
            if not good:
                failed.append((label, result, truth, clients))
            row = f"{scenario:<24} {cms:<10}"
            if wide:
                row += f" {('+'.join(shape) or '-'):<14}"
            print(row + f" {result.recall:>7.1%} {result.precision:>10.1%} "
                        f"{len(result.fired_rules):>6}   {status}")
        print()

        for label, result, truth, clients in failed:
            print(f"===== {label} =====")
            print(report(result, truth, None, clients))
            print()

        if known:
            cov = coverage(fired, known)
            print(f"COMBINED COVERAGE  {cov['ratio']:.1%}  "
                  f"({len(cov['exercised'])}/"
                  f"{len(cov['exercised']) + len(cov['never_fired'])} rules "
                  f"exercised by the catalogue)")
            if cov["never_fired"]:
                print()
                print("NEVER EXERCISED BY ANY SCENARIO -- the work list")
                for rule in cov["never_fired"]:
                    print(f"  {rule}")
        print()
        print("PASS" if not failed else f"FAIL ({len(failed)} case(s))")
        if keep:
            print(f"\ncases kept at {workdir}")
        return 1 if failed else 0
    finally:
        if not keep:
            shutil.rmtree(workdir, ignore_errors=True)


def cmd_scenarios(args) -> int:
    for name in scenarios.names():
        print(name)
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="shellforge",
        description="Generate CMS incident evidence with ground truth, "
                    "to test SHELLHOUND.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    gen = sub.add_parser("gen", help="write a case to disk")
    _add_gen_args(gen)
    gen.add_argument("--out", default="./cases")
    gen.add_argument("--json", action="store_true")
    gen.set_defaults(func=cmd_gen)

    sc = sub.add_parser("score", help="diff findings against ground truth")
    sc.add_argument("--truth", required=True)
    sc.add_argument("--case", required=True,
                    help="path to a Shellhound case.db")
    sc.add_argument("--shellhound", default=str(DEFAULT_SHELLHOUND),
                    help="checkout to read the rule catalogue from, for the "
                         "coverage section")
    sc.set_defaults(func=cmd_score)

    ck = sub.add_parser("check", help="generate, analyse and score in one go")
    _add_gen_args(ck)
    ck.add_argument("--shellhound", default=str(DEFAULT_SHELLHOUND))
    ck.add_argument("--out", default=None,
                    help="keep the case here instead of a temporary directory")
    ck.add_argument("--all", action="store_true",
                    help="run every scenario and report coverage summed over "
                         "all of them. Per case, coverage only says what one "
                         "narrative touched")
    ck.set_defaults(func=cmd_check)

    ls = sub.add_parser("scenarios", help="list what can be generated")
    ls.set_defaults(func=cmd_scenarios)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
