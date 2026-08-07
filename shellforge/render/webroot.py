# shellforge/render/webroot.py
"""Write the file map to disk, and prove it can be read back.

THE VERIFICATION IS NOT PARANOIA. On Windows a virus scanner intervenes when
a file is OPENED, not when it is written -- so generating succeeds, and the
failure arrives much later as `engine found nothing`, which reads like a bug
in the detector. Shellhound's own fixtures learned this the hard way and say
so in a comment; this is the same lesson, enforced at the point where the
damage happens.

The check is opt-out rather than opt-in for the same reason: whoever most
needs it is whoever does not know they need it.
"""
from __future__ import annotations

import hashlib
from pathlib import Path


class UnreadableEvidence(RuntimeError):
    pass


def write(root: Path, files: dict, *, verify: bool = True) -> dict:
    """Write every entry. Returns path -> sha256 of what landed on disk."""
    digests = {}
    for rel in sorted(files):
        content = files[rel]
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        raw = content.encode("utf-8") if isinstance(content, str) else content
        target.write_bytes(raw)
        digests[rel] = hashlib.sha256(raw).hexdigest()
    if verify:
        _verify(root, files)
    return digests


def _verify(root: Path, files: dict):
    """Open every file again. A scanner that ate one is found here, by name."""
    missing, unreadable = [], []
    for rel in sorted(files):
        target = root / rel
        if not target.exists():
            missing.append(rel)
            continue
        try:
            with open(target, "rb") as fh:
                fh.read(64)
        except OSError as exc:
            unreadable.append(f"{rel} ({exc})")
    if missing or unreadable:
        lines = ["evidence did not survive being written."]
        if missing:
            lines.append("  gone:       " + ", ".join(missing[:8]))
        if unreadable:
            lines.append("  unreadable: " + ", ".join(unreadable[:8]))
        lines.append(
            "On Windows this is almost always the virus scanner. Exclude the "
            "output directory from real-time scanning, or pass "
            "--no-verify-readable if you know the case is incomplete.")
        raise UnreadableEvidence("\n".join(lines))


def reference_copy(files: dict, planted_paths) -> dict:
    """The same installation without what was planted in it.

    This is the half of a webroot diff that is normally impossible to get:
    a clean release of exactly the right version, byte for byte. Here it is
    free, because both sides came out of the same generator.
    """
    dropped = set(planted_paths)
    return {rel: content for rel, content in files.items() if rel not in dropped}
