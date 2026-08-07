# shellforge/world/__init__.py
"""CMS world models: what an installation looks like before anyone breaks in.

A world is the boring half and therefore the important one. Anybody can plant
a shell in an empty directory and watch a scanner find it; the question worth
answering is whether it still finds it among four hundred legitimate files,
and whether it keeps quiet about the other three hundred and ninety-nine.

Each profile exposes the same surface, so one scenario script runs against
all of them:

    build(rng, scale) -> Site

`Site` carries the clean webroot, the accounts, the content rows and the URL
space the baseline traffic draws from. It knows nothing about attacks.
"""
from __future__ import annotations

from dataclasses import dataclass, field

SCALES = {
    # (extra plugin files, uploaded media, posts, baseline days, requests/day)
    "small": (3, 12, 14, 6, 120),
    "medium": (9, 60, 60, 21, 900),
    "large": (24, 240, 240, 60, 4000),
}


@dataclass
class Account:
    login: str
    display: str
    email: str
    role: str
    registered: str          # "YYYY-MM-DD HH:MM:SS"
    password_hash: str
    last_login: str = ""


@dataclass
class Row:
    """One content row, rendered into the dump by the CMS profile."""
    table: str
    values: dict


@dataclass
class Site:
    kind: str
    version: str
    #: webroot-relative path -> content. `str` is written UTF-8, `bytes` raw.
    files: dict = field(default_factory=dict)
    accounts: list = field(default_factory=list)
    rows: list = field(default_factory=list)
    #: The paths ordinary visitors request, with a rough weight each.
    urls: list = field(default_factory=list)
    #: Where this CMS's uploads land -- scenarios ask rather than hardcode.
    upload_dir: str = ""
    #: The login endpoint, for flood and brute-force scenarios.
    login_path: str = ""
    #: Table prefix, so the dump and the scenario agree.
    prefix: str = ""
    #: (slug, name, version) each, for the inventory to be checked against.
    plugins: list = field(default_factory=list)
    theme: tuple = ()

    def add(self, path: str, content):
        self.files[path] = content

    def table(self, name: str) -> str:
        return f"{self.prefix}{name}"
