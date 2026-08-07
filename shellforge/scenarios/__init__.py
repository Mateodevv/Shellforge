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


REGISTRY = {}


def register(name):
    def wrap(fn):
        REGISTRY[name] = fn
        return fn
    return wrap


def get(name):
    from shellforge.scenarios import wp_upload_shell  # noqa: F401  (registers)
    if name not in REGISTRY:
        raise KeyError(f"unknown scenario {name!r}; have: "
                       f"{', '.join(sorted(REGISTRY))}")
    return REGISTRY[name]


def names():
    from shellforge.scenarios import wp_upload_shell  # noqa: F401
    return sorted(REGISTRY)
