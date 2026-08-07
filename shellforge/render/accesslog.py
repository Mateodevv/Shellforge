# shellforge/render/accesslog.py
"""Access logs, in the formats a real server writes them.

RESPONSE SIZE IS A FIELD, NOT DECORATION. Shellhound gates its probe rules on
the status code, which is right for most things and wrong for at least one:
an LFI against `admin-ajax.php` answers 200 whether it worked or not, and the
only discriminator is how many bytes came back. A generator that filled the
size column with a constant would make that class of case untestable, so
every request carries a size that means something.

ROTATION IS PART OF THE TEST. Real evidence arrives as `access.log`,
`access.log.1`, `access.log.2.gz` -- with the oldest entries in the file with
the highest number, which is the sort of thing that is obvious until someone
sorts the directory listing alphabetically and reads the case backwards.
"""
from __future__ import annotations

import gzip
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

APACHE_TIME = "%d/%b/%Y:%H:%M:%S +0000"


@dataclass
class Request:
    when: datetime
    ip: str
    method: str
    uri: str
    status: int
    size: int
    agent: str
    referer: str = "-"

    def sort_key(self):
        return (self.when, self.ip, self.uri)


def apache_combined(req: Request) -> str:
    stamp = req.when.strftime(APACHE_TIME)
    return (f'{req.ip} - - [{stamp}] "{req.method} {req.uri} HTTP/1.1" '
            f'{req.status} {req.size} "{req.referer}" "{req.agent}"\n')


def nginx_combined(req: Request) -> str:
    # Nginx's default differs from Apache's in the separator around the
    # request and in nothing else that matters here. Keeping both means a
    # parser change can be tested against the format it was not written for.
    stamp = req.when.strftime(APACHE_TIME)
    return (f'{req.ip} - - [{stamp}] "{req.method} {req.uri} HTTP/1.1" '
            f'{req.status} {req.size} "{req.referer}" "{req.agent}"\n')


FORMATS = {"apache": apache_combined, "nginx": nginx_combined}


def write(log_dir: Path, requests: list, *, fmt: str = "apache",
          rotate_days: int = 0, gzip_old: bool = True) -> list:
    """Write the requests, optionally split into rotated files.

    Returns the list of files written, newest first -- which is the order an
    analyst reads them and the opposite of the order they sort in.
    """
    log_dir.mkdir(parents=True, exist_ok=True)
    render = FORMATS[fmt]
    ordered = sorted(requests, key=Request.sort_key)
    if not ordered:
        (log_dir / "access.log").write_bytes(b"")
        return [log_dir / "access.log"]

    if not rotate_days:
        target = log_dir / "access.log"
        target.write_text("".join(render(r) for r in ordered), encoding="utf-8")
        return [target]

    # Bucket by day, then group days into files of `rotate_days` each.
    buckets: dict = {}
    for req in ordered:
        buckets.setdefault(req.when.date(), []).append(req)
    days = sorted(buckets)
    chunks = [days[i:i + rotate_days]
              for i in range(0, len(days), rotate_days)]
    chunks.reverse()          # newest chunk first -> becomes access.log

    written = []
    for index, chunk in enumerate(chunks):
        lines = "".join(render(r) for day in chunk for r in buckets[day])
        if index == 0:
            target = log_dir / "access.log"
            target.write_text(lines, encoding="utf-8")
        elif gzip_old and index > 1:
            target = log_dir / f"access.log.{index}.gz"
            with gzip.open(target, "wt", encoding="utf-8") as fh:
                fh.write(lines)
        else:
            target = log_dir / f"access.log.{index}"
            target.write_text(lines, encoding="utf-8")
        written.append(target)
    return written
