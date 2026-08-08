# shellforge/world/filler.py
"""File bodies of a realistic size, and the boring files that outnumber them.

MEASURED AGAINST A REAL WEBROOT. A live Joomla installation from a real case
held 1,744 files and 55.6 MB; its 669 PHP files had a median of 2,844 bytes,
a p90 of 16,858 and a largest of 893,646. What this generator produced was
69 PHP files of about 280 bytes each, at every scale -- the count did not even
grow, because only the uploaded images were tied to the scale setting.

That is not cosmetic. Precision is measured against the files that must stay
silent, so a webroot a quarter of the real size measures a quarter of the
surface. A 5 MB threshold means nothing in a tree whose biggest file is 310
bytes. A webroot diff has almost nothing to diff. And "55,000 log lines per
second" has a sibling claim about scanning a webroot that nothing here was
ever big enough to test.

TWO THINGS DOMINATE A REAL CMS TREE AND NEITHER IS INTERESTING:

  language files   382 `.ini` files in the real install. Every extension
                   ships translations for every language it knows.
  index guards     276 `.html` files -- the empty `index.html` a CMS drops in
                   every directory so a mis-configured server cannot list it.

They are two thirds of the tree. Leaving them out is what made the generated
webroot both too small and the wrong shape, and putting them in costs
nothing: they are one line each.

EVERYTHING HERE MUST STAY INERT. Padding is comments, string tables and
plain functions -- nothing a content rule looks for. `tests/` asserts the
clean baseline stays silent, which is the check that keeps this honest.
"""
from __future__ import annotations

#: The size a generated PHP file aims for, in the proportions the real tree
#: had. Most are small; a few are a library somebody vendored.
_PHP_SIZES = [
    ((400, 1800), 34),          # a controller, a helper, a view
    ((1800, 6000), 38),         # the median mass
    ((6000, 22000), 20),        # a model with a lot of query building
    ((22000, 90000), 7),        # a fat library file
    ((90000, 400000), 1),       # something vendored and never split
]

_LOREM = (
    "Die Konfiguration wird beim Laden zwischengespeichert und bei jeder "
    "Aenderung verworfen. ")


def php_size(rng) -> int:
    lo, hi = rng.weighted(_PHP_SIZES)
    return rng.randint(lo, hi)


def pad_php(rng, body: str, target: int) -> str:
    """Grow a PHP file to roughly `target` bytes without making it executable.

    Padding is a docblock and a string table: no superglobal, no call any
    content rule matches, nothing that decodes. A generated file that started
    tripping a rule would turn the precision measurement into its opposite
    without anybody noticing, which is exactly the failure this repository
    exists to catch elsewhere.
    """
    if len(body) >= target:
        return body
    out = [body.rstrip("\n"), "", "/**", " * Notes carried by the build:"]
    n = 0
    while sum(len(line) + 1 for line in out) < target - 120:
        n += 1
        out.append(f" * {n:03d}. {_LOREM}")
    out += [" */", "",
            "$config_defaults = array(",
            "    'cache_ttl' => 900,",
            "    'debug' => false,",
            "    'locale' => 'de-DE',",
            ");", ""]
    return "\n".join(out)


#: What a CMS drops into every directory so a mis-configured server cannot
#: produce a listing. In the real tree there were 276 of them.
INDEX_GUARD = "<!DOCTYPE html><title></title>\n"


def language_ini(rng, prefix: str, lines: int = 0) -> str:
    """A translation file. 382 of these were the single largest group."""
    lines = lines or rng.randint(12, 90)
    out = [f"; {prefix} language strings", "; Generated, inert.", ""]
    for i in range(lines):
        out.append(f'{prefix.upper()}_KEY_{i:03d}="Beschriftung {i}"')
    return "\n".join(out) + "\n"


def fill(rng, site, target: int, layout, guard, body_for):
    """Grow the installation to `target` PHP files, then add its furniture.

    `layout` is (directory template, weight) pairs; `{n}` in a template is
    filled with an extension index so the tree has the same broad, shallow
    shape a real one does -- many components, a handful of files each, rather
    than one directory with six hundred files in it.

    `guard` is the bootstrap line that CMS puts at the top of every file, and
    `body_for(name)` produces the file's real content before padding.
    """
    names = ["controller", "view", "model", "helper", "router", "dispatcher",
             "service", "table", "field", "layout", "rule", "mapper",
             "provider", "factory", "trait", "extension", "adapter", "filter"]
    made = 0
    dirs = [d for d, _w in layout]
    weights = [w for _d, w in layout]
    while made < target:
        template = rng.weighted(list(zip(dirs, weights)))
        directory = template.format(n=rng.randint(1, 26))
        for _ in range(rng.randint(2, 7)):
            if made >= target:
                break
            name = f"{rng.choice(names)}{rng.randint(1, 40)}"
            rel = f"{directory}/{name}.php"
            if rel in site.files:
                continue
            site.files[rel] = pad_php(rng, body_for(name), php_size(rng))
            made += 1

    # The two groups that outnumber the code, and were missing entirely.
    for lang in ("de-DE", "en-GB"):
        # MEASURED AT 382. Every extension ships a site file and an
        # administrator file per language, which is where the count
        # comes from -- not from one big folder.
        for i in range(rng.randint(80, 130)):
            # TWO PER EXTENSION PER LANGUAGE: the site strings and the
            # administrator strings are separate files, which is where a
            # count of 382 comes from rather than from one big folder.
            for side in ("", "sys."):
                site.files[f"{site.language_dir}/{lang}/"
                           f"{lang}.ext_{i:03d}.{side}ini"] = \
                    language_ini(rng, f"EXT{i:03d}")
    site.files.update(guards_for(list(site.files)))


def guards_for(paths) -> dict:
    """An `index.html` for every directory the given paths imply.

    Derived rather than listed, because the tree is generated: whatever
    directories the profile created, the CMS would have guarded all of them.
    """
    dirs = set()
    for rel in paths:
        parts = rel.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            dirs.add("/".join(parts[:i]))
    return {f"{d}/index.html": INDEX_GUARD for d in sorted(dirs) if d}
