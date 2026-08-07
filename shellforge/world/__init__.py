# shellforge/world/__init__.py
"""CMS world models: what an installation looks like before anyone breaks in.

A world is the boring half and therefore the important one. Anybody can plant
a shell in an empty directory and watch a scanner find it; the question worth
answering is whether it still finds it among four hundred legitimate files,
and whether it keeps quiet about the other three hundred and ninety-nine.

Each profile exposes the same surface, so one scenario script runs against
all of them:

    build(rng, scale) -> Site

EVERYTHING A SCENARIO NEEDS TO KNOW ABOUT A CMS IS A FIELD ON `Site`. Not a
string in the scenario. The moment a narrative writes `wp-content/uploads` or
`/wp-admin/` it becomes a WordPress scenario, and the point of the split is
that `bruteforce-admin` is a story about logins, not about WordPress. So the
profile declares where uploads land, what the login endpoint is, which paths
an authenticated admin requests, which file is the canonical
must-stay-silent core file, and what its database schema looks like -- and
the narrative asks.

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
    table: str               # LOGICAL name; the profile maps it to physical
    values: dict


@dataclass
class Table:
    """One table of a CMS schema, as mysqldump would write it.

    COLUMN ORDER IS LOAD-BEARING and must be the real one. Shellhound reads
    WordPress and Joomla accounts BY POSITION, because those schemas are fixed
    and known. A dump whose columns were tidied into a sensible order parses
    into nonsense -- and tests nothing, because no real export looks like
    that.
    """
    #: Suffix after the table prefix, e.g. `users` -> `wp_users` / `jos_users`.
    suffix: str
    columns: list
    ddl: str                 # `{t}` is substituted with the physical name


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

    # --- what a CMS-agnostic scenario has to be able to ask ----------------
    #: Where uploads land. Scenarios drop files relative to this.
    upload_dir: str = ""
    #: The login endpoint, for flood and brute-force scenarios.
    login_path: str = ""
    #: What an authenticated administrator requests after signing in.
    admin_paths: list = field(default_factory=list)
    #: A URL that PROVES an authenticated backend session on this CMS --
    #: something an unauthenticated client cannot get a 2xx from. Empty when
    #: Shellhound has no way to recognise one for this CMS, which is itself a
    #: fact a scenario has to be able to state.
    authenticated_area: str = ""
    #: Where the active theme/template lives, webroot-relative.
    theme_dir: str = ""
    #: A genuine core file with a bootstrap guard and nothing executable --
    #: the canonical false-positive guard, named per CMS.
    guarded_core: str = ""
    #: Files that legitimately live in the upload tree and must stay silent.
    quiet_upload_files: list = field(default_factory=list)
    #: Logical table names the generic database scenarios write into.
    content_table: str = ""
    config_table: str = ""
    #: The column of `content_table` that holds rendered HTML.
    content_column: str = ""
    #: (index, name, value) -> a row dict for `config_table`, with `value` in
    #: whatever free-text column that CMS keeps settings in. WordPress has
    #: `option_value`; Joomla has `params` on an extension row with six other
    #: mandatory columns. A scenario that built the dict itself would be a
    #: WordPress scenario wearing a generic name.
    config_row: object = None

    # --- database ----------------------------------------------------------
    #: Table prefix, so the dump and the scenario agree.
    prefix: str = ""
    #: logical name -> Table. Order is the order they appear in the dump.
    schema: dict = field(default_factory=dict)
    #: site -> {logical: [row dicts]}. How this CMS expresses its accounts,
    #: which differs enough between WordPress and Joomla that a shared
    #: implementation would be a lie about both.
    account_rows: object = None

    # --- inventory ----------------------------------------------------------
    #: (slug, name, version) each, for the inventory to be checked against.
    plugins: list = field(default_factory=list)
    theme: tuple = ()

    def add(self, path: str, content):
        self.files[path] = content

    def table(self, logical: str) -> str:
        """The physical table name for a logical one."""
        entry = self.schema.get(logical)
        return f"{self.prefix}{entry.suffix if entry else logical}"
