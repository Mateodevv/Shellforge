# shellforge/corpus.py
"""Word material, shipped rather than depended on.

Small on purpose. This is not trying to be Faker -- it needs enough variety
that two generated cases do not read as the same case with the numbers
changed, and no more.

EVERYTHING IS INVENTED AND SAFE TO PUBLISH. Domains end in `.test` (RFC 6761),
addresses come from the documentation ranges of RFC 5737 (see `rng.ip`). The
plugin names are made up; a real plugin name in a fixture would eventually be
read as an accusation against that plugin.
"""
from __future__ import annotations

# --- people -----------------------------------------------------------------

FIRST_NAMES = [
    "Sabine", "Mehmet", "Anna", "Jonas", "Fatima", "Lukas", "Ingrid", "Ravi",
    "Clara", "Tobias", "Yusuf", "Marta", "Nils", "Elif", "Katrin", "Piotr",
    "Hannah", "Dario", "Leonie", "Amir",
]

LAST_NAMES = [
    "Keller", "Yilmaz", "Brandt", "Novak", "Weber", "Hoffmann", "Lindqvist",
    "Schuster", "Baumann", "Dubois", "Kowalski", "Reinhardt", "Sanchez",
    "Vogel", "Aydin", "Peters", "Gruber", "Marek", "Fischer", "Toth",
]

# --- editorial content ------------------------------------------------------

POST_TITLES = [
    "Öffnungszeiten über die Feiertage", "Neue Filiale in der Innenstadt",
    "Unser Team stellt sich vor", "Versandkosten ab sofort günstiger",
    "Rückblick auf die Hausmesse", "Wartungsarbeiten am Wochenende",
    "Drei Fragen an unsere Werkstatt", "Neuer Katalog ist da",
    "Wir suchen Verstärkung", "Hinweise zur Rücksendung",
    "Zwischen den Jahren erreichbar", "Der Frühling im Sortiment",
]

PARAGRAPHS = [
    "Ab dem kommenden Montag gelten die neuen Zeiten. Wir bitten um Beachtung.",
    "Der Umbau ist abgeschlossen, die Ausstellung ist wieder vollständig begehbar.",
    "Bestellungen aus dem Lagerbestand verlassen das Haus am selben Werktag.",
    "Für Rückfragen steht das Büro während der üblichen Zeiten zur Verfügung.",
    "Die Änderung betrifft ausschließlich Sendungen innerhalb Deutschlands.",
    "Wer vorbeikommen möchte, meldet sich am besten kurz vorher an.",
]

PAGE_SLUGS = [
    "/", "/kontakt/", "/impressum/", "/ueber-uns/", "/leistungen/",
    "/shop/", "/shop/kategorie/werkzeug/", "/shop/kategorie/garten/",
    "/blog/", "/datenschutz/", "/anfahrt/", "/versand-und-zahlung/",
]

# --- user agents ------------------------------------------------------------
# Real UA strings, because a log whose agents are invented is not a log a
# parser can be tested against. They identify browsers, not people.

BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S911B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36",
]

CRAWLER_UAS = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; DuckDuckBot-Https/1.1; https://duckduckgo.com/duckduckbot)",
]

# Agents that name a scanning tool. Shellhound reports these as INFO
# (`logs.scanner_ua`) -- background noise, and a good precision check: a case
# full of these must not turn the work list red.
SCANNER_UAS = [
    "Mozilla/5.0 (Nikto/2.5.0)",
    "sqlmap/1.7.11#stable (https://sqlmap.org)",
    "WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)",
    "Mozilla/5.0 zgrab/0.x",
    "masscan/1.3.2",
    "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
]

# --- WordPress furniture ----------------------------------------------------
# Invented plugin and theme names. Slug, display name, version.

PLUGINS = [
    ("kontaktformular-plus", "Kontaktformular Plus", "3.4.1"),
    ("seo-werkstatt", "SEO Werkstatt", "2.9.0"),
    ("cache-boost", "Cache Boost", "1.12.3"),
    ("bildergalerie-lite", "Bildergalerie Lite", "4.0.2"),
    ("shop-versandrechner", "Shop Versandrechner", "1.5.8"),
    ("cookie-hinweis", "Cookie Hinweis", "2.2.0"),
    ("newsletter-anbindung", "Newsletter Anbindung", "3.1.4"),
    ("backup-werkzeug", "Backup Werkzeug", "5.2.1"),
]

THEMES = [
    ("handwerk-modern", "Handwerk Modern", "2.4.0"),
    ("shop-klassik", "Shop Klassik", "1.8.6"),
]

# WordPress core versions that actually existed, so the inventory has
# something plausible to read out of `wp-includes/version.php`.
WP_VERSIONS = ["6.3.2", "6.4.2", "6.4.3", "6.5.2", "6.6.1"]

# --- Joomla furniture -------------------------------------------------------
# Invented extension names, except the template framework: `shaper_helix3` is
# the real directory JoomShaper's Helix3 installs into, and a scenario about
# CVE-2026-49049 that renamed it would be testing a path no analyst will ever
# see. The framework is named; nothing about its code is reproduced.

JOOMLA_EXTENSIONS = [
    ("com_kontaktformular", "Kontaktformular", "component", "3.2.1"),
    ("com_galerie", "Bildergalerie", "component", "2.7.0"),
    ("com_termine", "Terminverwaltung", "component", "1.9.4"),
    ("mod_aktuelles", "Aktuelles-Modul", "module", "4.1.0"),
    ("mod_wetterbox", "Wetterbox", "module", "2.0.3"),
    ("plg_seo_pfade", "SEO-Pfade", "plugin", "1.4.2"),
    ("plg_sicherung", "Sicherung", "plugin", "5.0.1"),
]

#: (directory, display name, version). `shaper_helix3` is the real one.
JOOMLA_TEMPLATES = [
    ("shaper_helix3", "Helix3", "3.0.9"),
    ("handwerk_j4", "Handwerk J4", "1.6.0"),
]

#: Joomla releases that actually existed. The 3.x ones write RELEASE and
#: DEV_LEVEL into `libraries/cms/version/version.php`; the 4.x and 5.x ones
#: write MAJOR/MINOR/PATCH_VERSION into `libraries/src/Version.php`, and
#: Shellhound reads both, which is why the profile can emit either.
JOOMLA_VERSIONS = ["3.9.28", "3.10.11", "4.2.7", "4.4.3", "5.1.2"]

JOOMLA_PAGE_SLUGS = [
    "/", "/index.php", "/kontakt", "/impressum", "/ueber-uns",
    "/leistungen", "/aktuelles", "/datenschutz", "/anfahrt",
    "/index.php?option=com_content&view=article&id=12",
    "/index.php?option=com_content&view=category&layout=blog&id=9",
    "/component/kontaktformular/",
]


def full_name(rng) -> tuple[str, str]:
    """(login, display name)."""
    first = rng.choice(FIRST_NAMES)
    last = rng.choice(LAST_NAMES)
    ascii_first = _asciify(first).lower()
    ascii_last = _asciify(last).lower()
    login = rng.weighted([
        (f"{ascii_first[0]}.{ascii_last}", 4),
        (f"{ascii_first}.{ascii_last}", 3),
        (f"{ascii_first}{rng.randint(1, 89)}", 1),
    ])
    return login, f"{first} {last}"


_UMLAUTS = str.maketrans({"ä": "ae", "ö": "oe", "ü": "ue", "ß": "ss",
                          "Ä": "Ae", "Ö": "Oe", "Ü": "Ue",
                          "é": "e", "è": "e", "ç": "c", "ł": "l", "ó": "o"})


def _asciify(text: str) -> str:
    return text.translate(_UMLAUTS)


def slugify(text: str) -> str:
    out = []
    for ch in _asciify(text).lower():
        if ch.isalnum():
            out.append(ch)
        elif out and out[-1] != "-":
            out.append("-")
    return "".join(out).strip("-")
