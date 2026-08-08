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


def _grouped(site, extra_rows) -> dict:
    """Every row this dump will carry, keyed by logical table name.

    Shared by both output shapes: which rows exist is a fact about the case,
    and only the way they are written differs.
    """
    grouped: dict = {}
    for row in site.rows:
        grouped.setdefault(row.table, []).append(row.values)
    for logical, rows in (extra_rows or {}).items():
        grouped.setdefault(logical, []).extend(rows)
    if site.account_rows:
        for logical, rows in site.account_rows(site).items():
            grouped.setdefault(logical, []).extend(rows)
    unknown = sorted(set(grouped) - set(site.schema))
    if unknown:
        raise KeyError(
            f"rows written to tables the {site.kind} profile does not "
            f"declare: {', '.join(unknown)}")
    return grouped


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


def render_phpmyadmin(site, *, database: str = "cms_prod",
                      extra_rows=None) -> str:
    """The same data as phpMyAdmin exports it.

    MEASURED, AND THE MORE COMMON SHAPE. The real Joomla export from a case
    was phpMyAdmin 5.2.3, not mysqldump -- which is unsurprising once stated,
    because phpMyAdmin is what a shared-hosting control panel offers and
    `mysqldump` needs a shell. It differs in four ways that a parser can trip
    over, and this generator produced none of them:

      header          `-- phpMyAdmin SQL Dump`, not `-- MySQL dump 10.13`.
                      The evidence detector recognises a dump by its header.
      column lists    EVERY insert names its columns:
                      `INSERT INTO `x` (`a`, `b`) VALUES` -- 731 of them in
                      the real file and not one plain `VALUES`. Shellhound
                      reads accounts by POSITION, so where those positions
                      come from matters.
      keys afterwards no `PRIMARY KEY` inside `CREATE TABLE`; `ALTER TABLE`
                      statements after the data instead. 345 of them.
      transaction     `START TRANSACTION` / `COMMIT`, and no `LOCK TABLES`.

    Shellhound reads this shape correctly -- measured, not assumed, before
    this was written. What was missing was any test data in it, which is the
    same gap the log formats had: a branch the code has and the fixtures
    never reach.
    """
    extra_rows = extra_rows or {}
    parts = [
        "-- phpMyAdmin SQL Dump\n"
        "-- version 5.2.3\n"
        "-- https://www.phpmyadmin.net/\n"
        "--\n"
        "-- Host: localhost\n"
        "-- Erstellungszeit: 08. Aug 2026 um 09:14\n"
        "-- Server-Version: 10.11.14-MariaDB-0ubuntu0.24.04.1-log\n"
        "-- PHP-Version: 8.1.31\n\n"
        'SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";\n'
        "START TRANSACTION;\n"
        'SET time_zone = "+00:00";\n\n'
        "/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;\n\n"
        f"--\n-- Datenbank: `{database}`\n--\n"
    ]
    grouped = _grouped(site, extra_rows)
    alters = []
    for logical, table in site.schema.items():
        rows = grouped.get(logical)
        if not rows:
            continue
        physical = site.table(logical)
        # CREATE without the key clauses: phpMyAdmin emits those separately.
        body = [line for line in table.ddl.format(t=physical).splitlines()
                if not line.strip().startswith(("PRIMARY KEY", "UNIQUE KEY",
                                                "KEY "))]
        # The line before the closing paren keeps a trailing comma otherwise.
        for i in range(len(body) - 1, -1, -1):
            if body[i].rstrip().endswith(","):
                body[i] = body[i].rstrip().rstrip(",")
                break
        parts.append(f"\n--\n-- Tabellenstruktur für Tabelle `{physical}`\n"
                     f"--\n\n" + "\n".join(body) + "\n\n")
        cols = ", ".join(f"`{c}`" for c in table.columns)
        values = ",\n".join(
            "(" + ", ".join(quote(row.get(col)) for col in table.columns) + ")"
            for row in rows)
        parts.append(f"--\n-- Daten für Tabelle `{physical}`\n--\n\n"
                     f"INSERT INTO `{physical}` ({cols}) VALUES\n{values};\n")
        alters.append(f"ALTER TABLE `{physical}`\n  ADD PRIMARY KEY "
                      f"(`{table.columns[0]}`);\n")

    parts.append("\n--\n-- Indizes der exportierten Tabellen\n--\n\n")
    parts.extend(alters)
    parts.append("COMMIT;\n\n"
                 "/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;\n")
    return "".join(parts)


FORMATS = {"mysqldump": render, "phpmyadmin": render_phpmyadmin}


def write(path: Path, site, fmt: str = "mysqldump", **kwargs) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(FORMATS[fmt](site, **kwargs), encoding="utf-8")
    return path
