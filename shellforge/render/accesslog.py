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
    #: Bytes sent, or `None` for the `-` a server writes when it does not
    #: know. MEASURED AT 12-13% OF LINES in two real logs from different
    #: hosters, and on one of them it appears on `200` responses too -- so
    #: "unknown" is a third state and not a synonym for zero.
    size: object
    agent: str
    referer: str = "-"

    def sort_key(self):
        return (self.when, self.ip, self.uri)

    @property
    def size_field(self) -> str:
        return "-" if self.size is None else str(self.size)


def apache_combined(req: Request) -> str:
    stamp = req.when.strftime(APACHE_TIME)
    return (f'{req.ip} - - [{stamp}] "{req.method} {req.uri} HTTP/1.1" '
            f'{req.status} {req.size_field} "{req.referer}" "{req.agent}"\n')


def nginx_combined(req: Request) -> str:
    # Nginx's default differs from Apache's in the separator around the
    # request and in nothing else that matters here. Keeping both means a
    # parser change can be tested against the format it was not written for.
    stamp = req.when.strftime(APACHE_TIME)
    return (f'{req.ip} - - [{stamp}] "{req.method} {req.uri} HTTP/1.1" '
            f'{req.status} {req.size_field} "{req.referer}" "{req.agent}"\n')


#: The site the line belongs to, written UNQUOTED between the size and the
#: referer. Apache emits it under `%v` on any host that keeps one log for
#: several sites, which is most shared hosting.
VHOST = "www.example.test"


def apache_vhost(req: Request) -> str:
    """Combined with a bare vhost token, plus a trailing quoted field.

    MEASURED, NOT INVENTED. This is the exact shape one of the two real logs
    used: `… 200 18020 <vhost> "referer" "user agent" "-"`. Shellhound's
    `LOG_PATTERN` carries `(?:[^"\\s]\\S* )?` for precisely this token, and
    until now nothing generated here ever exercised that branch -- the one
    the comment beside it calls out as the sort of quirk whose removal
    "would silently drop exactly the attacker lines the index exists to
    answer about".
    """
    stamp = req.when.strftime(APACHE_TIME)
    return (f'{req.ip} - - [{stamp}] "{req.method} {req.uri} HTTP/1.1" '
            f'{req.status} {req.size_field} {VHOST} '
            f'"{req.referer}" "{req.agent}" "-"\n')


def plesk(req: Request) -> str:
    """Combined plus Plesk's two trailing fields.

    Also measured: `… "referer" "user agent" "Traffic IN:820 OUT:3256"
    "ReqTime:0 sec"`. Handled by `LOG_PATTERN`'s `(?:\\s.*)?$`, and likewise
    never generated here before.
    """
    stamp = req.when.strftime(APACHE_TIME)
    inb = 200 + len(req.uri) + len(req.agent)
    outb = 165 if req.size is None else req.size + 165
    return (f'{req.ip} - - [{stamp}] "{req.method} {req.uri} HTTP/1.1" '
            f'{req.status} {req.size_field} "{req.referer}" "{req.agent}" '
            f'"Traffic IN:{inb} OUT:{outb}" "ReqTime:0 sec"\n')


FORMATS = {"apache": apache_combined, "nginx": nginx_combined,
           "vhost": apache_vhost, "plesk": plesk}


#: The bytes a Windows editor puts at the head of a file it saved as UTF-8.
BOM = b"\xef\xbb\xbf"


def _encode(lines: list, *, newline: str, encoding: str,
            raw_lines=(), bom: bool = False) -> bytes:
    """Render lines to the bytes that land on disk.

    BYTES, NOT TEXT, because the shape of the file is the thing under test:
    a byte-order mark, a line ending and a codec are not visible through
    `write_text(..., encoding="utf-8")`, and one of them is exactly what a
    reader gets wrong.

    `raw_lines` are spliced between the good ones at even intervals rather
    than appended. Damage at the END of a file is found by anybody; damage in
    the MIDDLE is what silently costs the lines after it.
    """
    if raw_lines:
        step = max(1, len(lines) // (len(raw_lines) + 1))
        for offset, extra in enumerate(raw_lines):
            lines.insert(min(len(lines), step * (offset + 1) + offset), extra)
    body = newline.join(lines)
    if lines:
        body += newline
    # `errors="replace"` on the way out too: a Latin-1 target cannot hold
    # every character the corpus has, and a generator that raised here would
    # be refusing to produce the very file it is meant to produce.
    raw = body.encode(encoding, errors="replace")
    return (BOM + raw) if bom else raw


def write(log_dir: Path, requests: list, *, fmt: str = "apache",
          rotate_days: int = 0, gzip_old: bool = True,
          bom: bool = False, newline: str = "\n", encoding: str = "utf-8",
          raw_lines=()) -> list:
    """Write the requests, optionally split into rotated files.

    Returns the list of files written, newest first -- which is the order an
    analyst reads them and the opposite of the order they sort in.
    """
    log_dir.mkdir(parents=True, exist_ok=True)
    render = FORMATS[fmt]
    ordered = sorted(requests, key=Request.sort_key)
    shape = dict(newline=newline, encoding=encoding)
    if not ordered:
        (log_dir / "access.log").write_bytes(b"")
        return [log_dir / "access.log"]

    if not rotate_days:
        target = log_dir / "access.log"
        target.write_bytes(_encode(
            [render(r).rstrip("\n") for r in ordered],
            raw_lines=list(raw_lines), bom=bom, **shape))
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
        lines = [render(r).rstrip("\n") for day in chunk for r in buckets[day]]
        # The damaged lines and the mark go into the CURRENT file only: a
        # rotation writes each file once and the head of the archive was
        # written weeks ago.
        blob = _encode(lines, raw_lines=list(raw_lines) if index == 0 else (),
                       bom=bom and index == 0, **shape)
        if index == 0:
            target = log_dir / "access.log"
            target.write_bytes(blob)
        elif gzip_old and index > 1:
            target = log_dir / f"access.log.{index}.gz"
            with gzip.open(target, "wb") as fh:
                fh.write(blob)
        else:
            target = log_dir / f"access.log.{index}"
            target.write_bytes(blob)
        written.append(target)
    return written
