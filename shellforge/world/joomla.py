# shellforge/world/joomla.py
"""A clean Joomla installation.

WHY JOOMLA IS THE SECOND PROFILE AND NOT DRUPAL. Shellhound parses WordPress
and Joomla in detail and merely RECOGNISES the rest, so Joomla is the only
other CMS where a generated case can be wrong in an interesting way -- wrong
column order, wrong version file, wrong group id -- rather than falling
through to the generic path where almost anything parses.

THREE THINGS HERE ARE NOT DECORATION:

  The version file moved.  Joomla 3 writes `const RELEASE` and `const
  DEV_LEVEL` into `libraries/cms/version/version.php`; Joomla 4 and 5 write
  `MAJOR_VERSION` / `MINOR_VERSION` / `PATCH_VERSION` into
  `libraries/src/Version.php`. Shellhound looks in both places, and a profile
  that only ever emitted one of them would leave half that code untested.

  Accounts are read by POSITION. `row[2]` is the username, `row[3]` the
  e-mail, `row[4]` the password, `row[7]` the registration date. The column
  list below is the real one and must not be tidied.

  Being an administrator is not a column. From Joomla 3.0 the permission
  lives in `#__user_usergroup_map`, and Shellhound looks for group id **8**
  (Super Users). An account table alone cannot say who is an admin here,
  which is exactly the sort of thing a generic generator gets wrong.

The `media/` subdirectories matter too: Shellhound excludes
`media/(system|vendor|com_*|mod_*|plg_*)/` from its writable-upload matching,
because those ship with the CMS. A profile without them would never exercise
that exclusion.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from shellforge import corpus
from shellforge.world import Account, Row, Site, Table, SCALES

PNG_1PX = bytes.fromhex(
    "89504e470d0a1a0a0000000d494844520000000100000001080600000"
    "01f15c4890000000a49444154789c6360000002000100" "05fe02fe"
    "dccc59e70000000049454e44ae426082")

JPEG_STUB = bytes.fromhex("ffd8ffe000104a46494600010100000100010000") + \
    b"\x00" * 64 + bytes.fromhex("ffd9")

#: Joomla's bootstrap guard. The single most effective discriminator
#: Shellhound has, and the reason `false-guard` is a scenario.
JEXEC = "defined('_JEXEC') or die;\n"

# --- schema -----------------------------------------------------------------
# REAL COLUMN ORDERS. Do not sort.

SCHEMA = {
    "users": Table(
        suffix="users",
        columns=["id", "name", "username", "email", "password", "block",
                 "sendEmail", "registerDate", "lastvisitDate", "activation",
                 "params", "lastResetTime", "resetCount", "requireReset"],
        ddl="""CREATE TABLE `{t}` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(400) NOT NULL DEFAULT '',
  `username` varchar(150) NOT NULL DEFAULT '',
  `email` varchar(100) NOT NULL DEFAULT '',
  `password` varchar(100) NOT NULL DEFAULT '',
  `block` tinyint(4) NOT NULL DEFAULT '0',
  `sendEmail` tinyint(4) DEFAULT '0',
  `registerDate` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  `lastvisitDate` datetime DEFAULT NULL,
  `activation` varchar(100) NOT NULL DEFAULT '',
  `params` text NOT NULL,
  `lastResetTime` datetime DEFAULT NULL,
  `resetCount` int(11) NOT NULL DEFAULT '0',
  `requireReset` tinyint(4) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `idx_name` (`name`(100))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;"""),
    "usergroups": Table(
        suffix="usergroups",
        columns=["id", "parent_id", "lft", "rgt", "title"],
        ddl="""CREATE TABLE `{t}` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `parent_id` int(10) unsigned NOT NULL DEFAULT '0',
  `lft` int(11) NOT NULL DEFAULT '0',
  `rgt` int(11) NOT NULL DEFAULT '0',
  `title` varchar(100) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;"""),
    "user_usergroup_map": Table(
        suffix="user_usergroup_map",
        columns=["user_id", "group_id"],
        ddl="""CREATE TABLE `{t}` (
  `user_id` int(11) NOT NULL DEFAULT '0',
  `group_id` int(10) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`user_id`,`group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;"""),
    "content": Table(
        suffix="content",
        columns=["id", "asset_id", "title", "alias", "introtext", "fulltext",
                 "state", "catid", "created", "created_by", "publish_up",
                 "access", "language"],
        ddl="""CREATE TABLE `{t}` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `asset_id` int(10) unsigned NOT NULL DEFAULT '0',
  `title` varchar(255) NOT NULL DEFAULT '',
  `alias` varchar(400) NOT NULL DEFAULT '',
  `introtext` mediumtext NOT NULL,
  `fulltext` mediumtext NOT NULL,
  `state` tinyint(3) NOT NULL DEFAULT '0',
  `catid` int(10) unsigned NOT NULL DEFAULT '0',
  `created` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  `created_by` int(10) unsigned NOT NULL DEFAULT '0',
  `publish_up` datetime DEFAULT NULL,
  `access` int(10) unsigned NOT NULL DEFAULT '0',
  `language` char(7) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;"""),
    "extensions": Table(
        suffix="extensions",
        columns=["extension_id", "name", "type", "element", "folder",
                 "client_id", "enabled", "manifest_cache", "params"],
        ddl="""CREATE TABLE `{t}` (
  `extension_id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `type` varchar(20) NOT NULL,
  `element` varchar(100) NOT NULL,
  `folder` varchar(100) NOT NULL,
  `client_id` tinyint(3) NOT NULL,
  `enabled` tinyint(3) NOT NULL DEFAULT '0',
  `manifest_cache` text NOT NULL,
  `params` text NOT NULL,
  PRIMARY KEY (`extension_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;"""),
    "template_styles": Table(
        suffix="template_styles",
        columns=["id", "template", "client_id", "home", "title", "params"],
        ddl="""CREATE TABLE `{t}` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `template` varchar(50) NOT NULL DEFAULT '',
  `client_id` tinyint(1) unsigned NOT NULL DEFAULT '0',
  `home` char(7) NOT NULL DEFAULT '0',
  `title` varchar(255) NOT NULL DEFAULT '',
  `params` text NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;"""),
}

#: Joomla's stock group ids. **8 is Super Users**, and it is the only one
#: Shellhound treats as an administrator -- see `_joomla_super_ids`.
GROUPS = [
    (1, 0, 1, 20, "Public"),
    (2, 1, 6, 17, "Registered"),
    (3, 2, 7, 14, "Author"),
    (4, 3, 8, 11, "Editor"),
    (5, 4, 9, 10, "Publisher"),
    (6, 1, 2, 5, "Manager"),
    (7, 6, 3, 4, "Administrator"),
    (8, 1, 18, 19, "Super Users"),
]

ROLE_GROUP = {"administrator": 8, "manager": 6, "editor": 4,
              "author": 3, "publisher": 5, "registered": 2}


def config_row(index: int, name: str, value: str) -> dict:
    """A settings row. Joomla keeps extension settings as JSON in `params`,
    and the row needs six other columns to be a valid extension at all --
    which is exactly the difference a generic scenario must not have to know
    about."""
    return {"extension_id": index, "name": name, "type": "plugin",
            "element": name, "folder": "system", "client_id": 0,
            "enabled": 1, "manifest_cache": '{"version":"1.0.0"}',
            "params": value}


def account_rows(site) -> dict:
    """Accounts as Joomla stores them: the row, plus a group-map entry.

    THE GROUP MAP IS NOT OPTIONAL. Since Joomla 3.0 nothing on the account
    itself says who is a Super User; drop this table and every generated case
    reports an installation with no administrators, which is not a shape any
    real dump has.
    """
    users, mapping = [], []
    for index, account in enumerate(site.accounts, start=1):
        users.append({
            "id": index,
            "name": account.display,
            "username": account.login,
            "email": account.email,
            "password": account.password_hash,
            "block": 0,
            "sendEmail": 1 if account.role == "administrator" else 0,
            "registerDate": account.registered,
            "lastvisitDate": account.last_login or None,
            "activation": "",
            "params": "",
            "lastResetTime": None,
            "resetCount": 0,
            "requireReset": 0,
        })
        mapping.append({"user_id": index,
                        "group_id": ROLE_GROUP.get(account.role, 2)})
    return {"users": users, "user_usergroup_map": mapping}


# --- files ------------------------------------------------------------------

def _core_php(name: str, package: str = "Joomla.Site") -> str:
    return (f"<?php\n"
            f"/**\n * @package     {package}\n"
            f" * @subpackage  {name}\n"
            f" * @license     GNU General Public License version 2\n */\n\n"
            f"{JEXEC}\n"
            f"class {name.title().replace('-', '').replace('_', '')}Helper\n"
            f"{{\n"
            f"    public static function getItems($state = 1)\n"
            f"    {{\n"
            f"        return array('state' => $state);\n"
            f"    }}\n"
            f"}}\n")


def _version_file_j4(version: str) -> str:
    major, minor, patch = (version.split(".") + ["0", "0"])[:3]
    return (f"<?php\n"
            f"/**\n * @package  Joomla.Libraries\n */\n\n"
            f"namespace Joomla\\CMS\\Version;\n\n"
            f"{JEXEC}\n"
            f"final class Version\n{{\n"
            f"    public const PRODUCT = 'Joomla!';\n"
            f"    public const MAJOR_VERSION = {major};\n"
            f"    public const MINOR_VERSION = {minor};\n"
            f"    public const PATCH_VERSION = {patch};\n"
            f"    public const EXTRA_VERSION = '';\n"
            f"}}\n")


def _version_file_j3(version: str) -> str:
    parts = version.split(".")
    release = ".".join(parts[:2])
    dev_level = parts[2] if len(parts) > 2 else "0"
    return (f"<?php\n"
            f"/**\n * @package  Joomla.Libraries\n */\n\n"
            f"{JEXEC}\n"
            f"final class JVersion\n{{\n"
            f"    public $PRODUCT = 'Joomla!';\n"
            f"    const RELEASE = '{release}';\n"
            f"    const DEV_LEVEL = '{dev_level}';\n"
            f"    const DEV_STATUS = 'Stable';\n"
            f"}}\n")


def _manifest(name: str, version: str, kind: str, element: str) -> str:
    return (f"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
            f"<extension type=\"{kind}\" method=\"upgrade\">\n"
            f"\t<name>{name}</name>\n"
            f"\t<version>{version}</version>\n"
            f"\t<author>{name} Team</author>\n"
            f"\t<description>{name}</description>\n"
            f"\t<files>\n\t\t<filename>{element}.php</filename>\n"
            f"\t</files>\n</extension>\n")


#: Directories that ship with Joomla and are EXCLUDED from Shellhound's
#: writable-upload matching. Present so that exclusion is exercised: a profile
#: without them would never prove the tool can tell `media/system/` from
#: `images/`.
_SHIPPED_MEDIA = [
    "media/system/js/core.js",
    "media/system/js/keepalive.js",
    "media/vendor/jquery/js/jquery.min.js",
    "media/com_content/js/admin-article.js",
    "media/mod_menu/css/menu.css",
    "media/plg_system_schemaorg/js/schemaorg.js",
]


def build(rng, scale: str = "small") -> Site:
    extra_parts, media_count, article_count, _days, _rpd = SCALES[scale]

    version = rng.choice(corpus.JOOMLA_VERSIONS)
    legacy = version.startswith("3.")
    site = Site(
        kind="joomla", version=version,
        # Joomla's media manager writes here, and `images` is one of the
        # segments Shellhound treats as writable.
        upload_dir="images",
        login_path="/administrator/index.php",
        admin_paths=["/administrator/index.php",
                     "/administrator/index.php?option=com_content",
                     "/administrator/index.php?option=com_media",
                     "/administrator/index.php?option=com_users",
                     "/administrator/index.php?option=com_installer",
                     "/administrator/index.php?option=com_templates",
                     "/administrator/index.php?option=com_config"],
        guarded_core="/components/com_content/src/View/Article/HtmlView.php",
        quiet_upload_files=["images/index.html", "images/joomla_black.png"],
        content_table="content", config_table="extensions",
        content_column="introtext",
        schema=SCHEMA, account_rows=account_rows,
        config_row=config_row,
        # Joomla's installer offers a random prefix and most people take it.
        prefix=rng.weighted([(f"{rng.token(4)}_", 6), ("jos_", 3)]))

    # --- core ---------------------------------------------------------------
    site.add("index.php",
             "<?php\n/**\n * @package  Joomla.Site\n */\n\n"
             "define('_JEXEC', 1);\n"
             "define('JPATH_BASE', __DIR__);\n"
             "require_once JPATH_BASE . '/includes/defines.php';\n"
             "require_once JPATH_BASE . '/includes/framework.php';\n")
    site.add("configuration.php",
             "<?php\nclass JConfig\n{\n"
             "    public $sitename = 'Beispielbetrieb';\n"
             "    public $db = 'joomla_" + rng.token(6) + "';\n"
             "    public $user = 'joomlauser';\n"
             "    public $password = '" + rng.token(14) + "';\n"
             "    public $dbprefix = '" + site.prefix + "';\n"
             "    public $host = 'localhost';\n}\n")
    if legacy:
        site.add("libraries/cms/version/version.php", _version_file_j3(version))
    else:
        site.add("libraries/src/Version.php", _version_file_j4(version))

    for name in ("defines", "framework", "app"):
        site.add(f"includes/{name}.php", _core_php(name, "Joomla.Include"))
    for name in ("Factory", "Uri", "Router", "Application"):
        site.add(f"libraries/src/{name}.php", _core_php(name, "Joomla.Libraries"))
    for component in ("com_content", "com_users", "com_media", "com_contact"):
        site.add(f"components/{component}/src/Controller/DisplayController.php",
                 _core_php("DisplayController", f"Joomla.Site.{component}"))
        site.add(f"administrator/components/{component}/"
                 f"src/Controller/DisplayController.php",
                 _core_php("DisplayController", f"Joomla.Administrator"))
    site.add("components/com_content/src/View/Article/HtmlView.php",
             _core_php("HtmlView", "Joomla.Site.com_content"))
    site.add("administrator/index.php",
             "<?php\n/**\n * @package  Joomla.Administrator\n */\n\n"
             "define('_JEXEC', 1);\n"
             "require_once dirname(__DIR__) . '/includes/defines.php';\n")
    for rel in _SHIPPED_MEDIA:
        site.add(rel, "/* shipped asset */\n")

    # `images/` gets what Joomla itself puts there, so the malicious file a
    # scenario drops later replaces nothing and stands out for what it is.
    site.add("images/index.html", "<!DOCTYPE html><title></title>\n")
    site.add("images/joomla_black.png", PNG_1PX)
    site.add("tmp/index.html", "<!DOCTYPE html><title></title>\n")
    site.add("cache/index.html", "<!DOCTYPE html><title></title>\n")

    # --- extensions ---------------------------------------------------------
    chosen = rng.sample(corpus.JOOMLA_EXTENSIONS, rng.randint(4, 6))
    ext_rows = []
    for index, (element, name, kind, ver) in enumerate(chosen, start=10000):
        folder = {"component": "components", "module": "modules",
                  "plugin": "plugins"}[kind]
        if kind == "plugin":
            base = f"plugins/system/{element}"
        elif kind == "module":
            base = f"modules/{element}"
        else:
            base = f"components/{element}"
        site.add(f"{base}/{element}.php", _core_php(element, name))
        site.add(f"{base}/{element}.xml", _manifest(name, ver, kind, element))
        for part in rng.sample(["helper", "router", "dispatcher", "fields",
                                "service", "layout"], extra_parts):
            site.add(f"{base}/src/{part}.php", _core_php(part, name))
        site.plugins.append((element, name, ver, f"{base}/{element}.php"))
        ext_rows.append(Row(table="extensions", values={
            "extension_id": index, "name": name, "type": kind,
            "element": element,
            "folder": "system" if kind == "plugin" else "",
            "client_id": 0, "enabled": 1,
            "manifest_cache": f'{{"name":"{name}","version":"{ver}"}}',
            "params": "{}"}))
    site.rows += ext_rows

    # --- template -----------------------------------------------------------
    tpl_dir, tpl_name, tpl_ver = rng.choice(corpus.JOOMLA_TEMPLATES)
    site.theme = (tpl_dir, tpl_name, tpl_ver)
    site.theme_dir = f"templates/{tpl_dir}"
    site.add(f"templates/{tpl_dir}/templateDetails.xml",
             _manifest(tpl_name, tpl_ver, "template", "index"))
    site.add(f"templates/{tpl_dir}/index.php",
             "<?php\n" + JEXEC + "\n$doc = $this;\n")
    for part in ("component", "error", "offline"):
        site.add(f"templates/{tpl_dir}/{part}.php",
                 "<?php\n" + JEXEC + f"\n// {part}\n")
    site.add(f"templates/{tpl_dir}/css/template.css",
             ".sp-page-builder { margin: 0; }\n")
    site.rows.append(Row(table="extensions", values={
        "extension_id": 20000, "name": tpl_name, "type": "template",
        "element": tpl_dir, "folder": "", "client_id": 0, "enabled": 1,
        "manifest_cache": f'{{"name":"{tpl_name}","version":"{tpl_ver}"}}',
        "params": "{}"}))
    site.rows.append(Row(table="template_styles", values={
        "id": 8, "template": tpl_dir, "client_id": 0, "home": "1",
        "title": f"{tpl_name} - Default",
        "params": '{"logo":"images/logo.png","preset":"preset1"}'}))

    # --- groups -------------------------------------------------------------
    for gid, parent, lft, rgt, title in GROUPS:
        site.rows.append(Row(table="usergroups", values={
            "id": gid, "parent_id": parent, "lft": lft, "rgt": rgt,
            "title": title}))

    # --- media --------------------------------------------------------------
    base_day = datetime(2026, 1, 1)
    for i in range(media_count):
        stem = corpus.slugify(rng.choice(corpus.POST_TITLES))[:22]
        folder = rng.choice(["images", "images/galerie", "images/banner"])
        if rng.chance(0.6):
            site.add(f"{folder}/{stem}-{i}.jpg", JPEG_STUB)
        else:
            site.add(f"{folder}/{stem}-{i}.png", PNG_1PX)

    # --- accounts -----------------------------------------------------------
    seen = set()
    roles = ["administrator", "manager", "editor", "author", "registered"]
    for role in roles:
        login, display = corpus.full_name(rng)
        while login in seen:
            login, display = corpus.full_name(rng)
        seen.add(login)
        registered = base_day - timedelta(days=rng.randint(120, 2200))
        last = base_day - timedelta(days=rng.randint(1, 90))
        site.accounts.append(Account(
            login=login, display=display,
            email=f"{login}@example.test", role=role,
            registered=registered.strftime("%Y-%m-%d %H:%M:%S"),
            # A bcrypt hash SHAPE, which is what Joomla 3.2+ writes. It is a
            # hash of nothing.
            password_hash="$2y$10$" + rng.hexs(53),
            last_login=last.strftime("%Y-%m-%d %H:%M:%S")))

    # --- content ------------------------------------------------------------
    for i in range(article_count):
        title = rng.choice(corpus.POST_TITLES)
        body = " ".join(rng.sample(corpus.PARAGRAPHS, rng.randint(1, 3)))
        created = base_day - timedelta(days=rng.randint(1, 500))
        site.rows.append(Row(table="content", values={
            "id": i + 1, "asset_id": 100 + i, "title": title,
            "alias": corpus.slugify(title),
            "introtext": f"<p>{body}</p>", "fulltext": "",
            "state": 1, "catid": rng.randint(2, 9),
            "created": created.strftime("%Y-%m-%d %H:%M:%S"),
            "created_by": rng.randint(1, len(site.accounts)),
            "publish_up": created.strftime("%Y-%m-%d %H:%M:%S"),
            "access": 1, "language": "*"}))

    # --- the URL space visitors move through --------------------------------
    site.urls = [(u, 10) for u in corpus.JOOMLA_PAGE_SLUGS]
    site.urls += [(f"/{corpus.slugify(r.values['title'])}", 3)
                  for r in site.rows if r.table == "content"][:20]
    site.urls += [
        (f"/templates/{tpl_dir}/css/template.css", 14),
        ("/media/system/js/core.js", 12),
        ("/media/vendor/jquery/js/jquery.min.js", 10),
        ("/favicon.ico", 6),
        ("/robots.txt", 2),
        ("/index.php?option=com_content&view=featured&format=feed", 2),
    ]
    return site
