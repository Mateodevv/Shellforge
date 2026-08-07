# shellforge/render/sqldump.py
"""A mysqldump export of the CMS database.

COLUMN ORDER IS LOAD-BEARING. Shellhound reads WordPress and Joomla accounts
BY POSITION, because those schemas are fixed and known; everything else it
reads by column NAME. A dump whose `wp_users` columns are in a tidy
alphabetical order would therefore be parsed into nonsense -- and would test
nothing, because no real export looks like that. The orders below are the
real ones.

The header matters too: `-- MySQL dump 10.13` is how the evidence detector
recognises a dump at all, so it is not decoration either.

WHAT GOES IN A VALUE IS THE SCENARIO'S BUSINESS. This module escapes and
formats; it does not know which row is the injected one.
"""
from __future__ import annotations

from pathlib import Path

#: The real `wp_users` column order. Do not sort this.
WP_USERS_COLUMNS = [
    "ID", "user_login", "user_pass", "user_nicename", "user_email",
    "user_url", "user_registered", "user_activation_key", "user_status",
    "display_name",
]

WP_USERMETA_COLUMNS = ["umeta_id", "user_id", "meta_key", "meta_value"]

WP_POSTS_COLUMNS = [
    "ID", "post_author", "post_date", "post_content", "post_title",
    "post_status", "post_name", "post_type",
]

WP_OPTIONS_COLUMNS = ["option_id", "option_name", "option_value", "autoload"]

_DDL = {
    "users": """CREATE TABLE `{t}` (
  `ID` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `user_login` varchar(60) NOT NULL DEFAULT '',
  `user_pass` varchar(255) NOT NULL DEFAULT '',
  `user_nicename` varchar(50) NOT NULL DEFAULT '',
  `user_email` varchar(100) NOT NULL DEFAULT '',
  `user_url` varchar(100) NOT NULL DEFAULT '',
  `user_registered` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  `user_activation_key` varchar(255) NOT NULL DEFAULT '',
  `user_status` int(11) NOT NULL DEFAULT '0',
  `display_name` varchar(250) NOT NULL DEFAULT '',
  PRIMARY KEY (`ID`),
  KEY `user_login_key` (`user_login`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;""",
    "usermeta": """CREATE TABLE `{t}` (
  `umeta_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `user_id` bigint(20) unsigned NOT NULL DEFAULT '0',
  `meta_key` varchar(255) DEFAULT NULL,
  `meta_value` longtext,
  PRIMARY KEY (`umeta_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;""",
    "posts": """CREATE TABLE `{t}` (
  `ID` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `post_author` bigint(20) unsigned NOT NULL DEFAULT '0',
  `post_date` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  `post_content` longtext NOT NULL,
  `post_title` text NOT NULL,
  `post_status` varchar(20) NOT NULL DEFAULT 'publish',
  `post_name` varchar(200) NOT NULL DEFAULT '',
  `post_type` varchar(20) NOT NULL DEFAULT 'post',
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;""",
    "options": """CREATE TABLE `{t}` (
  `option_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `option_name` varchar(191) NOT NULL DEFAULT '',
  `option_value` longtext NOT NULL,
  `autoload` varchar(20) NOT NULL DEFAULT 'yes',
  PRIMARY KEY (`option_id`),
  UNIQUE KEY `option_name` (`option_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;""",
}

COLUMNS = {
    "users": WP_USERS_COLUMNS,
    "usermeta": WP_USERMETA_COLUMNS,
    "posts": WP_POSTS_COLUMNS,
    "options": WP_OPTIONS_COLUMNS,
}

#: WordPress stores the role as a serialized PHP array in usermeta. The engine
#: reads it to decide who is an administrator, so the serialization has to be
#: right down to the string lengths.
ROLE_META = {
    "administrator": 'a:1:{s:13:"administrator";b:1;}',
    "editor": 'a:1:{s:6:"editor";b:1;}',
    "author": 'a:1:{s:6:"author";b:1;}',
    "subscriber": 'a:1:{s:10:"subscriber";b:1;}',
}


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
    # mysqldump batches rows into one extended INSERT. Doing the same is what
    # makes a value-level rule have to cope with several rows per line.
    values = ",\n".join(
        "(" + ",".join(quote(row.get(col)) for col in columns) + ")"
        for row in rows)
    out.append(f"INSERT INTO `{table}` VALUES\n{values};")
    out.append(f"/*!40000 ALTER TABLE `{table}` ENABLE KEYS */;")
    out.append("UNLOCK TABLES;")
    return "\n".join(out) + "\n"


def render(site, *, database: str = "wp_prod", extra_rows=None) -> str:
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

    # Accounts and their roles, built here because they are derived from the
    # account objects rather than carried as loose rows.
    users, usermeta = [], []
    for index, account in enumerate(site.accounts, start=1):
        users.append({
            "ID": index,
            "user_login": account.login,
            "user_pass": account.password_hash,
            "user_nicename": account.login.replace(".", "-"),
            "user_email": account.email,
            "user_url": "",
            "user_registered": account.registered,
            "user_activation_key": "",
            "user_status": 0,
            "display_name": account.display,
        })
        usermeta.append({
            "umeta_id": index, "user_id": index,
            "meta_key": "wp_capabilities",
            "meta_value": ROLE_META.get(account.role, ROLE_META["subscriber"]),
        })
    grouped.setdefault("users", []).extend(users)
    grouped.setdefault("usermeta", []).extend(usermeta)

    for logical in ("users", "usermeta", "posts", "options"):
        rows = grouped.get(logical)
        if not rows:
            continue
        physical = site.table(logical)
        parts.append(f"\n--\n-- Table structure for table `{physical}`\n--\n\n"
                     f"DROP TABLE IF EXISTS `{physical}`;\n"
                     + _DDL[logical].format(t=physical) + "\n\n"
                     f"--\n-- Dumping data for table `{physical}`\n--\n\n"
                     + _insert(physical, COLUMNS[logical], rows))

    parts.append("\n/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;\n"
                 "\n-- Dump completed\n")
    return "".join(parts)


def write(path: Path, site, **kwargs) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render(site, **kwargs), encoding="utf-8")
    return path
