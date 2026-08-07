# shellforge/world/wordpress.py
"""A clean WordPress installation.

EVERY FILE IN HERE MUST BE PROVABLY QUIET. The baseline is what measures
precision, so a file that accidentally carries an executable surface in an
upload directory turns a false-positive test into a false-negative test
without anybody noticing. Two habits keep that honest:

  * Generated PHP carries the `ABSPATH` guard, the way real WordPress files
    do, and contains no call the content rules look for.
  * The one deliberate exception -- the backup plugin that really does call
    `shell_exec` -- is declared as such by the scenario, not smuggled in.

Version markers sit exactly where Shellhound reads them: `$wp_version` in
`wp-includes/version.php`, a `Version:` header in the plugin's main file, and
`Version:` in a theme's `style.css`. They are the point of having an
inventory to check.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from shellforge import corpus, markers
from shellforge.world import Account, Row, Site, Table, SCALES

# --- schema -----------------------------------------------------------------
# THE REAL COLUMN ORDERS. Shellhound reads WordPress accounts by POSITION
# (`row[1]` login, `row[2]` hash, `row[4]` e-mail, `row[6]` registered), so
# these lists are not a stylistic choice. Do not sort them.

SCHEMA = {
    "users": Table(
        suffix="users",
        columns=["ID", "user_login", "user_pass", "user_nicename",
                 "user_email", "user_url", "user_registered",
                 "user_activation_key", "user_status", "display_name"],
        ddl="""CREATE TABLE `{t}` (
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;"""),
    "usermeta": Table(
        suffix="usermeta",
        columns=["umeta_id", "user_id", "meta_key", "meta_value"],
        ddl="""CREATE TABLE `{t}` (
  `umeta_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `user_id` bigint(20) unsigned NOT NULL DEFAULT '0',
  `meta_key` varchar(255) DEFAULT NULL,
  `meta_value` longtext,
  PRIMARY KEY (`umeta_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;"""),
    "posts": Table(
        suffix="posts",
        columns=["ID", "post_author", "post_date", "post_content",
                 "post_title", "post_status", "post_name", "post_type"],
        ddl="""CREATE TABLE `{t}` (
  `ID` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `post_author` bigint(20) unsigned NOT NULL DEFAULT '0',
  `post_date` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  `post_content` longtext NOT NULL,
  `post_title` text NOT NULL,
  `post_status` varchar(20) NOT NULL DEFAULT 'publish',
  `post_name` varchar(200) NOT NULL DEFAULT '',
  `post_type` varchar(20) NOT NULL DEFAULT 'post',
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;"""),
    "options": Table(
        suffix="options",
        columns=["option_id", "option_name", "option_value", "autoload"],
        ddl="""CREATE TABLE `{t}` (
  `option_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `option_name` varchar(191) NOT NULL DEFAULT '',
  `option_value` longtext NOT NULL,
  `autoload` varchar(20) NOT NULL DEFAULT 'yes',
  PRIMARY KEY (`option_id`),
  UNIQUE KEY `option_name` (`option_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;"""),
}

#: WordPress stores the role as a serialized PHP array in usermeta. Shellhound
#: reads it to decide who is an administrator, so the serialization has to be
#: right down to the string lengths.
ROLE_META = {
    "administrator": 'a:1:{s:13:"administrator";b:1;}',
    "editor": 'a:1:{s:6:"editor";b:1;}',
    "author": 'a:1:{s:6:"author";b:1;}',
    "subscriber": 'a:1:{s:10:"subscriber";b:1;}',
}


def config_row(index: int, name: str, value: str) -> dict:
    """A settings row. WordPress autoloads options, so anything in here runs
    on every page view -- which is what makes the table worth infecting."""
    return {"option_id": index, "option_name": name,
            "option_value": value, "autoload": "yes"}


def account_rows(site) -> dict:
    """Accounts as WordPress stores them: the row, plus a capabilities meta."""
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
            "meta_value": ROLE_META.get(account.role,
                                        ROLE_META["subscriber"]),
        })
    return {"users": users, "usermeta": usermeta}

# A minimal but genuine PNG: 1x1, transparent. Uploaded media has to be real
# enough that an image check does not reject it -- that is the whole point of
# the `php_in_image` rule, and a fake header would make the test vacuous.
PNG_1PX = bytes.fromhex(
    "89504e470d0a1a0a0000000d494844520000000100000001080600000"
    "01f15c4890000000a49444154789c6360000002000100" "05fe02fe"
    "dccc59e70000000049454e44ae426082")

JPEG_STUB = bytes.fromhex("ffd8ffe000104a46494600010100000100010000") + \
    b"\x00" * 64 + bytes.fromhex("ffd9")


def _core_php(name: str) -> str:
    """A plausible core file: guard, one function, nothing executable."""
    return (f"<?php\n"
            f"/**\n * {name}\n *\n * @package WordPress\n */\n\n"
            f"if (!defined('ABSPATH')) {{\n    exit;\n}}\n\n"
            f"function wp_{name.replace('-', '_')}_init() {{\n"
            f"    return array('name' => '{name}', 'loaded' => true);\n"
            f"}}\n")


def _plugin_main(slug: str, name: str, version: str) -> str:
    return (f"<?php\n"
            f"/**\n"
            f" * Plugin Name: {name}\n"
            f" * Description: {name} für WordPress.\n"
            f" * Version: {version}\n"
            f" * Author: {name} Team\n"
            f" * Text Domain: {slug}\n"
            f" */\n\n"
            f"if (!defined('ABSPATH')) {{\n    exit;\n}}\n\n"
            f"define('{slug.upper().replace('-', '_')}_VERSION', '{version}');\n\n"
            f"function {slug.replace('-', '_')}_setup() {{\n"
            f"    add_action('init', '{slug.replace('-', '_')}_register');\n"
            f"}}\n")


def _plugin_part(slug: str, part: str) -> str:
    return (f"<?php\n"
            f"if (!defined('ABSPATH')) {{\n    exit;\n}}\n\n"
            f"class {slug.title().replace('-', '')}{part.title()} {{\n"
            f"    public function render($atts = array()) {{\n"
            f"        return sprintf('<div class=\"%s\"></div>', '{slug}');\n"
            f"    }}\n"
            f"}}\n")


def _theme_style(name: str, version: str) -> str:
    return (f"/*\n"
            f"Theme Name: {name}\n"
            f"Version: {version}\n"
            f"Author: {name} Studio\n"
            f"License: GPLv2 or later\n"
            f"*/\n\n"
            f".site-header {{ padding: 1rem 0; }}\n"
            f".site-main {{ max-width: 68rem; margin: 0 auto; }}\n")


#: Core files worth having by name, because they are the ones an analyst and
#: a rule both recognise.
_CORE_FILES = [
    "wp-load.php", "wp-settings.php", "wp-blog-header.php", "wp-cron.php",
    "wp-links-opml.php", "wp-mail.php", "wp-signup.php", "wp-trackback.php",
]

_INCLUDES = [
    "functions", "formatting", "post", "query", "taxonomy", "user",
    "capabilities", "shortcodes", "media", "l10n", "kses", "rest-api",
]

_ADMIN = [
    "options-general", "edit", "upload", "plugins", "themes", "users",
    "tools", "update-core",
]


def build(rng, scale: str = "small") -> Site:
    extra_parts, media_count, post_count, _days, _rpd = SCALES[scale]

    version = rng.choice(corpus.WP_VERSIONS)
    site = Site(
        kind="wordpress", version=version,
        upload_dir="wp-content/uploads",
        login_path="/wp-login.php",
        admin_paths=["/wp-admin/", "/wp-admin/edit.php",
                     "/wp-admin/upload.php", "/wp-admin/admin-ajax.php",
                     "/wp-admin/post.php", "/wp-admin/users.php",
                     "/wp-admin/user-new.php", "/wp-admin/plugin-install.php",
                     "/wp-admin/options-general.php"],
        guarded_core="/wp-includes/functions.php",
        quiet_upload_files=["wp-content/uploads/.htaccess",
                            "wp-content/uploads/index.php"],
        content_table="posts", config_table="options",
        content_column="post_content",
        schema=SCHEMA, account_rows=account_rows,
        config_row=config_row,
        prefix=rng.weighted([("wp_", 6), ("wp7x_", 2), ("wpsite_", 1)]))

    # --- core -------------------------------------------------------------
    site.add("index.php",
             "<?php\ndefine('WP_USE_THEMES', true);\n"
             "require __DIR__ . '/wp-blog-header.php';\n")
    site.add("wp-includes/version.php",
             f"<?php\n"
             f"/**\n * WordPress version\n */\n\n"
             f"$wp_version = '{version}';\n"
             f"$wp_db_version = 57155;\n"
             f"$required_php_version = '7.2.24';\n")
    for name in _CORE_FILES:
        site.add(name, _core_php(name[:-4]))
    for name in _INCLUDES:
        site.add(f"wp-includes/{name}.php", _core_php(name))
    for name in _ADMIN:
        site.add(f"wp-admin/{name}.php", _core_php(name))
    site.add("wp-config.php",
             "<?php\n"
             f"define('DB_NAME', 'wp_{rng.token(6)}');\n"
             "define('DB_USER', 'wpuser');\n"
             f"define('DB_PASSWORD', '{rng.token(14)}');\n"
             "define('DB_HOST', 'localhost');\n"
             f"$table_prefix = '{site.prefix}';\n"
             "define('WP_DEBUG', false);\n"
             "require_once ABSPATH . 'wp-settings.php';\n")
    site.add("wp-content/index.php", "<?php\n// Silence is golden.\n")
    site.add(f"{site.upload_dir}/index.php", "<?php\n// Silence is golden.\n")
    # What WordPress itself puts there. Present so the scenario's malicious
    # .htaccess replaces something rather than appearing out of nowhere.
    site.add(f"{site.upload_dir}/.htaccess", markers.HTACCESS_CLEAN)

    # --- plugins ------------------------------------------------------------
    chosen = rng.sample(corpus.PLUGINS, rng.randint(4, 6))
    for slug, name, ver in chosen:
        site.add(f"wp-content/plugins/{slug}/{slug}.php",
                 _plugin_main(slug, name, ver))
        site.add(f"wp-content/plugins/{slug}/readme.txt",
                 f"=== {name} ===\nStable tag: {ver}\n\n== Beschreibung ==\n\n"
                 f"{name} erweitert WordPress.\n")
        for part in rng.sample(["admin", "widget", "shortcode", "ajax",
                                "settings", "helpers"], extra_parts):
            site.add(f"wp-content/plugins/{slug}/includes/{part}.php",
                     _plugin_part(slug, part))
        site.plugins.append(
            (slug, name, ver, f"wp-content/plugins/{slug}/{slug}.php"))

    # --- theme --------------------------------------------------------------
    theme_slug, theme_name, theme_ver = rng.choice(corpus.THEMES)
    site.theme = (theme_slug, theme_name, theme_ver)
    site.theme_dir = f"wp-content/themes/{theme_slug}"
    site.add(f"wp-content/themes/{theme_slug}/style.css",
             _theme_style(theme_name, theme_ver))
    for part in ("index", "header", "footer", "functions", "single", "page",
                 "search", "404"):
        site.add(f"wp-content/themes/{theme_slug}/{part}.php",
                 _core_php(f"theme-{part}"))

    # --- uploaded media -----------------------------------------------------
    # Dated directories, because that is where a real upload lands and it is
    # what makes the shell's own directory unremarkable.
    base_day = datetime(2026, 1, 1)
    for i in range(media_count):
        day = base_day - timedelta(days=rng.randint(0, 400))
        stem = corpus.slugify(rng.choice(corpus.POST_TITLES))[:22]
        folder = f"{site.upload_dir}/{day:%Y/%m}"
        if rng.chance(0.6):
            site.add(f"{folder}/{stem}-{i}.jpg", JPEG_STUB)
        else:
            site.add(f"{folder}/{stem}-{i}.png", PNG_1PX)

    # --- accounts -----------------------------------------------------------
    seen = set()
    roles = ["administrator", "editor", "author", "author", "subscriber"]
    for i, role in enumerate(roles):
        login, display = corpus.full_name(rng)
        while login in seen:
            login, display = corpus.full_name(rng)
        seen.add(login)
        registered = base_day - timedelta(days=rng.randint(120, 2200))
        site.accounts.append(Account(
            login=login, display=display,
            email=f"{login}@example.test", role=role,
            registered=registered.strftime("%Y-%m-%d %H:%M:%S"),
            # A phpass hash SHAPE, not a hash of anything. Nothing here is
            # crackable because nothing here was hashed.
            password_hash="$P$B" + rng.hexs(29)))

    # --- content ------------------------------------------------------------
    for i in range(post_count):
        title = rng.choice(corpus.POST_TITLES)
        body = " ".join(rng.sample(corpus.PARAGRAPHS, rng.randint(1, 3)))
        published = base_day - timedelta(days=rng.randint(1, 500))
        site.rows.append(Row(table="posts", values={
            "ID": i + 1,
            "post_author": rng.randint(1, len(site.accounts)),
            "post_date": published.strftime("%Y-%m-%d %H:%M:%S"),
            "post_content": f"<p>{body}</p>",
            "post_title": title,
            "post_status": "publish",
            "post_name": corpus.slugify(title),
            "post_type": "post",
        }))

    site.rows.append(Row(table="options", values={
        "option_id": 1, "option_name": "siteurl",
        "option_value": "https://www.example.test", "autoload": "yes"}))
    site.rows.append(Row(table="options", values={
        "option_id": 2, "option_name": "blogname",
        "option_value": "Beispielbetrieb", "autoload": "yes"}))

    # --- the URL space visitors move through --------------------------------
    site.urls = [(u, 10) for u in corpus.PAGE_SLUGS]
    site.urls += [(f"/{corpus.slugify(r.values['post_title'])}/", 3)
                  for r in site.rows if r.table == "posts"][:20]
    site.urls += [
        ("/wp-content/themes/%s/style.css" % theme_slug, 14),
        ("/wp-includes/js/jquery/jquery.min.js", 12),
        ("/favicon.ico", 6),
        ("/robots.txt", 2),
        ("/wp-json/wp/v2/posts", 2),
        ("/feed/", 2),
    ]
    return site
