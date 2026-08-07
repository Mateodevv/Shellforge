# shellforge/render/errorlog.py
"""PHP error logs.

WHY THIS EVIDENCE KIND EARNS ITS PLACE. The error log catches exactly what an
access log structurally cannot: a shell run from cron that produced no request
line, a file reached through `include` rather than through a URL, a shell that
crashed on its own broken payload -- and a file DELETED BEFORE THE COPY WAS
TAKEN. For that last one the error log is the only surviving evidence that the
path ever existed, which is the whole basis of the `ghost-shell` scenario.

Shellhound only writes a finding when the path resolves to a file under a
registered webroot, so the generator emits absolute paths under the webroot it
is about to register, and deliberately also a few that do not resolve -- those
must be counted, not dropped in silence.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

# Apache's error-log stamp. Different from the access log's, which is one of
# the small ways a parser can be wrong in only one place.
ERROR_TIME = "%a %b %d %H:%M:%S.%f %Y"

#: `errorlog.hard` (MEDIUM) is fatal / parse / uncaught exception; everything
#: else is `errorlog.soft` (LOW). The scenario picks by which one it means.
HARD = ("PHP Fatal error", "PHP Parse error")
SOFT = ("PHP Warning", "PHP Notice", "PHP Deprecated")


@dataclass
class ErrorLine:
    when: datetime
    level: str                # one of HARD / SOFT
    message: str
    path: str                 # absolute, as PHP writes it
    line: int
    client: str = ""


def apache_error(entry: ErrorLine) -> str:
    # NOT trimmed to milliseconds. `%f` is six digits and the year follows it,
    # so slicing the formatted string to shorten the fraction takes the last
    # three digits of the YEAR with it -- `2026` became `2`, and Apache's own
    # format demands four. Apache writes six digits anyway.
    stamp = entry.when.strftime(ERROR_TIME)
    client = f" [client {entry.client}:0]" if entry.client else ""
    return (f"[{stamp}] [php:error] [pid {7000 + entry.line}]{client} "
            f"{entry.level}:  {entry.message} in {entry.path} "
            f"on line {entry.line}\n")


def write(log_dir: Path, entries: list) -> Path:
    log_dir.mkdir(parents=True, exist_ok=True)
    target = log_dir / "error.log"
    ordered = sorted(entries, key=lambda e: e.when)
    target.write_text("".join(apache_error(e) for e in ordered),
                      encoding="utf-8")
    return target
