# shellforge/render/sqldump.py
"""A mysqldump export of the CMS database.

THE SCHEMA BELONGS TO THE WORLD PROFILE, NOT TO THIS MODULE. It used to live
here, spelled out for WordPress, and that made a second CMS impossible without
an `if kind == ...` down the middle of the renderer. Now the profile hands
over a `{logical: Table}` map and a function that turns its accounts into
rows, and this module formats whatever it is given.

WHAT IS STILL THIS MODULE'S BUSINESS is the shape of a real export: the
`-- MySQL dump 10.13` header the evidence detector recognises a dump by, the
`LOCK TABLES` / `DISABLE KEYS` scaffolding, and extended INSERTs with several
rows per statement -- which is what forces a value-level rule to cope with
more than one row on a line.

COLUMN ORDER IS LOAD-BEARING AND IS THE PROFILE'S PROBLEM. Shellhound reads
WordPress and Joomla accounts by POSITION. The profiles carry the real orders
and say so; this module never sorts them.
"""
from __future__ import annotations

from pathlib import Path


def quote(value) -> str:
    """A value as mysqldump writes it."""
    if value is None:
        return "NULL"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    # The order matters: backslashes first, or the escapes get escaped.
    text = (text.replace("\\", "\\\\").replace("'", "\\'")
            .replace("\n", "\\n").replace("\r", "\\r"))
    return f"'{text}'"


def _insert(table: str, columns: list, rows: list) -> str:
    if not rows:
        return ""
    out = [f"LOCK TABLES `{table}` WRITE;",
           f"/*!40000 ALTER TABLE `{table}` DISABLE KEYS */;"]
    values = ",\n".join(
        "(" + ",".join(quote(row.get(col)) for col in columns) + ")"
        for row in rows)
    out.append(f"INSERT INTO `{table}` VALUES\n{values};")
    out.append(f"/*!40000 ALTER TABLE `{table}` ENABLE KEYS */;")
    out.append("UNLOCK TABLES;")
    return "\n".join(out) + "\n"


def render(site, *, database: str = "cms_prod", extra_rows=None) -> str:
    """The whole dump. `extra_rows` is `{logical_table: [row dicts]}`."""
    extra_rows = extra_rows or {}
    parts = [
        "-- MySQL dump 10.13  Distrib 8.0.36, for Linux (x86_64)\n"
        "--\n"
        f"-- Host: localhost    Database: {database}\n"
        "-- ------------------------------------------------------\n"
        "-- Server version\t8.0.36-0ubuntu0.22.04.1\n\n"
        "/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;\n"
        "/*!40103 SET TIME_ZONE='+00:00' */;\n"
    ]

    grouped: dict = {}
    for row in site.rows:
        grouped.setdefault(row.table, []).append(row.values)
    for logical, rows in extra_rows.items():
        grouped.setdefault(logical, []).extend(rows)
    # Accounts last, so a scenario that appended one after the fact still
    # gets it rendered -- they are derived from the account objects rather
    # than carried as loose rows.
    if site.account_rows:
        for logical, rows in site.account_rows(site).items():
            grouped.setdefault(logical, []).extend(rows)

    for logical, table in site.schema.items():
        rows = grouped.get(logical)
        if not rows:
            continue
        physical = site.table(logical)
        parts.append(f"\n--\n-- Table structure for table `{physical}`\n--\n\n"
                     f"DROP TABLE IF EXISTS `{physical}`;\n"
                     + table.ddl.format(t=physical) + "\n\n"
                     f"--\n-- Dumping data for table `{physical}`\n--\n\n"
                     + _insert(physical, table.columns, rows))

    unknown = sorted(set(grouped) - set(site.schema))
    if unknown:
        # Loud rather than silent: a scenario writing into a table the profile
        # never declared would otherwise vanish from the dump, and the case
        # would fail with "planted but not reported" pointing at the engine.
        raise KeyError(
            f"rows written to tables the {site.kind} profile does not "
            f"declare: {', '.join(unknown)}")

    parts.append("\n/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;\n"
                 "\n-- Dump completed\n")
    return "".join(parts)


def write(path: Path, site, **kwargs) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render(site, **kwargs), encoding="utf-8")
    return path
