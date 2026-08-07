# shellforge/runner.py
"""Drive Shellhound's engines over a generated case, headless.

WHY NOT THE SERVER. Registering evidence through the HTTP API means a running
process, a token and a job queue to poll. The engines are importable and the
tests already call them directly with exactly these signatures, so this takes
the same route the test suite does.

WHAT THIS DOES NOT DO: it does not import, copy or re-implement a single
detection rule. It calls `scan()` and reads the `findings` table afterwards.
That separation is the entire premise of Shellforge -- a generator that knew
how the rules worked would generate the data those rules already pass.
"""
from __future__ import annotations

import sys
from pathlib import Path


def analyse(case_dir: Path, *, webroot: Path, logs: Path, dump: Path,
            shellhound: Path) -> dict:
    """Run every engine that has evidence, into a fresh `case.db`."""
    root = Path(shellhound).resolve()
    if not (root / "server").is_dir():
        raise FileNotFoundError(
            f"{root} does not look like a Shellhound checkout "
            f"(no server/ directory)")
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

    from server import db
    from server.engines import (cmsinventory, errorlog, logindex, sqldump,
                                webshell)

    case_dir = Path(case_dir)
    case_dir.mkdir(parents=True, exist_ok=True)

    # Register the evidence first: the error-log engine only writes a finding
    # for a path that resolves under a REGISTERED webroot, so scanning before
    # registering silently produces nothing.
    conn = db.connect(case_dir)
    try:
        for kind, path in (("webroot", webroot), ("access_logs", logs),
                           ("sql_dump", dump)):
            conn.execute(
                "INSERT OR IGNORE INTO evidence (kind, path, added) "
                "VALUES (?,?,?)", (kind, str(Path(path).resolve()), db.now()))
        conn.commit()
    finally:
        conn.close()

    stats = {}
    stats["webshell"] = webshell.scan(case_dir, [str(webroot)])
    stats["cms"] = cmsinventory.scan(case_dir, [str(webroot)])
    stats["sqldb"] = sqldump.scan(case_dir, [str(dump)])
    stats["logs"] = logindex.build(case_dir, [str(logs)])
    stats["errorlog"] = errorlog.scan(case_dir, [str(logs)])
    return stats
