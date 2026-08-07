# shellforge/scenarios/__init__.py
"""Scenarios: the narrative half.

A scenario decides what happened. It receives a clean world and a seeded
generator and returns a `Case` -- the evidence in memory, plus the ground
truth that says what a correct detector must make of it.

CROSS-CONSISTENCY IS THE ONLY THING THAT MAKES THIS REALISTIC. Any generator
can drop a suspicious file in a directory. What separates test data from
plausible test data is that the file was requested in the log at a time AFTER
it appeared, by an address that did something else first, and that the account
in the dump was registered in the window the log says somebody was logging in.
A case whose four evidence kinds disagree tests nothing except whether the
tool notices they disagree.

Time is a single axis, held here in UTC. The hostile variants (log server and
database server disagreeing, DST inside the window) come later and are a
transformation of a finished case, not a different scenario.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Case:
    site: object
    truth: object
    #: The final webroot -- the clean world plus whatever the attack added.
    files: dict = field(default_factory=dict)
    requests: list = field(default_factory=list)
    error_lines: list = field(default_factory=list)
    #: Extra database rows keyed by logical table name.
    extra_rows: dict = field(default_factory=dict)
    #: Webroot-relative paths the attack ADDED, so the reference copy can be
    #: built by removing exactly those.
    added_paths: list = field(default_factory=list)
    #: Paths that existed cleanly and were overwritten. The reference copy
    #: keeps the original content, which is what makes the diff say
    #: "modified" rather than "added".
    modified: dict = field(default_factory=dict)
    #: Hunt patterns this case is meant to be searched with.
    hunt_patterns: list = field(default_factory=list)
    #: Paths to make unreadable AFTER writing and verifying them. POSIX only;
    #: see `generate.generate`. This is the only way to exercise the rule
    #: about a file the scanner could not open, and the only reason a case
    #: ever touches permissions.
    unreadable_paths: list = field(default_factory=list)


#: name -> (builder, supported CMS kinds)
REGISTRY = {}

#: The default. A scenario that names no CMS is claiming to be a story rather
#: than a WordPress story, and every field it needs is on `Site`.
ALL_CMS = ("wordpress", "joomla")


def register(name, cms=ALL_CMS):
    """Register a scenario, and say which world profiles it runs against.

    MOST SCENARIOS SHOULD NAME NONE. `bruteforce-admin` is a story about
    logins; `db-only-spam` is a story about injected content. Restricting one
    to a single CMS is a decision to make deliberately -- `wp-upload-shell` is
    restricted because it models a specific WordPress plugin's CVE, and
    running it against Joomla would produce a case that could not have
    happened.
    """
    def wrap(fn):
        REGISTRY[name] = (fn, tuple(cms))
        return fn
    return wrap


#: Imported for their side effect of registering. An explicit list rather than
#: a `pkgutil` walk: a scenario that fails to import should break the run
#: loudly at a named line, not disappear from the catalogue and take its
#: assertions with it. A silently missing scenario is a silently missing test.
_MODULES = (
    "wp_upload_shell", "joomla_helix3", "bruteforce_admin", "db_only_spam",
    "shell_kit", "probe_wave", "ghost_shell", "false_guard", "clean_baseline",
    "long_tail_admin",
)


def _load():
    import importlib
    for module in _MODULES:
        importlib.import_module(f"shellforge.scenarios.{module}")


def get(name, cms: str = ""):
    _load()
    if name not in REGISTRY:
        raise KeyError(f"unknown scenario {name!r}; have: "
                       f"{', '.join(sorted(REGISTRY))}")
    fn, supported = REGISTRY[name]
    if cms and cms not in supported:
        # Refused rather than run anyway. `wp-upload-shell` against Joomla
        # would happily generate a case -- the world builds either way -- and
        # it would describe an intrusion through a WordPress plugin into an
        # installation that has no plugins. Evidence that could not have
        # happened is worse than no evidence.
        raise KeyError(
            f"scenario {name!r} does not support cms {cms!r}; "
            f"it supports: {', '.join(supported)}")
    return fn


def names(cms: str = ""):
    _load()
    return sorted(n for n, (_fn, supported) in REGISTRY.items()
                  if not cms or cms in supported)


def supported_cms(name: str):
    _load()
    return REGISTRY[name][1]
