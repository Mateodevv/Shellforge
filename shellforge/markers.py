# shellforge/markers.py
"""Inert markers -- the shortest text that trips exactly one rule.

NOTHING HERE IS A WORKING TOOL. Every payload is a probe in the spirit of an
EICAR file: it carries the pattern a detector looks for and does nothing else.
There is no shell here, no uploader, no network code, and there must never be.

Three reasons, in ascending order of how often they bite:

  1. Shellhound's own CONTRIBUTING forbids incident data and working attack
     code in the repository. A generator that emits some is worse, because it
     emits it endlessly.
  2. A test fixture ends up on a real machine. `Testing/` directories get
     copied to servers.
  3. THE PRACTICAL ONE. Windows Defender intervenes on ACCESS, not on write.
     A file with a real webshell pattern gets quarantined between generating
     and reading, and the failure arrives as `OSError(22) Invalid argument`,
     which reads like a bug in the generator rather than like a scanner.
     `shellforge gen --verify-readable` checks the assumption instead of
     trusting it.

The exact spellings below are lifted from Shellhound's own
`tests/fixtures.py` where one existed, on purpose: those have been proven to
survive a scanner on this class of machine. Inventing a new spelling means
re-testing that, and the value of a novel way to write `system($_GET[...])`
is zero.

WHICH RULE EACH ONE TRIPS is stated per marker and asserted by the scenario
that plants it. A marker that starts tripping two rules is a bug in the
marker, not a discovery.
"""
from __future__ import annotations

# --- PHP content markers ----------------------------------------------------
# Key = the rule id the marker exists to trigger.

#: `webshell.cmd_input` (HIGH). Note it does NOT also trip
#: `webshell.standalone_exec`: that rule lists shell_exec/passthru/proc_open/
#: pcntl_exec and deliberately not `system`, so this stays a single-rule probe.
CMD_INPUT = "<?php\n@system($_GET['cmd']);\n"

#: `webshell.dropper` (HIGH).
DROPPER = "<?php\nfile_put_contents($_POST['n'], $_POST['d']);\n"

#: `webshell.obfuscation` (MEDIUM).
OBFUSCATION = "<?php\n$x = gzinflate(base64_decode($p));\n"

#: `webshell.eval_input` (HIGH).
EVAL_INPUT = "<?php\neval(base64_decode($q));\n"

#: `webshell.var_func` (HIGH). Case-sensitive by design in the rule.
VAR_FUNC = "<?php\n$f = 'strlen';\n$f($_POST['v']);\n"

#: `webshell.chr_concat` (MEDIUM). Five links is the threshold; six here so a
#: change to the counting does not silently drop below it.
CHR_CONCAT = ("<?php\n$s = chr(115).chr(121).chr(115).chr(116)"
              ".chr(101).chr(109);\n")

#: `webshell.standalone_exec` (MEDIUM) and nothing else -- no request
#: reference. This is what a legitimate admin tool looks like to the scanner,
#: which is why the scenario plants it as an ACCEPTED medium rather than as a
#: false positive.
STANDALONE_EXEC = ("<?php\nif (!defined('ABSPATH')) { exit; }\n"
                   "function bw_dump($target) {\n"
                   "    return shell_exec('mysqldump --single-transaction');\n"
                   "}\n")

#: No rule at all. The false-positive guard: right place, real guard, nothing
#: executable. If this ever produces a finding, a rule has gone wrong.
GENUINE_CORE = ("<?php\nif (!defined('ABSPATH')) { exit; }\n"
                "function wp_x() { return 1; }\n")

#: `webshell.double_ext` (HIGH) via its NAME. The body carries no executable
#: surface on purpose, so the location rule books it as inert and the double
#: extension is the only thing that fires.
INERT_BODY = "<?php\necho 1;\n"

#: `webshell.php_in_image` (HIGH). Real PNG magic so a file-type check sees an
#: image, with a PHP tag behind it.
PHP_IN_IMAGE = b"\x89PNG\r\n\x1a\n" + b"<?php echo 2; ?>\n"

# --- .htaccess markers ------------------------------------------------------

#: `webshell.htaccess_handler` (HIGH).
HTACCESS_HANDLER = "AddType application/x-httpd-php .jpg\n"

#: `webshell.htaccess_prepend` (HIGH). The persistence trick: the code still
#: runs after the shell itself has been deleted.
HTACCESS_PREPEND = 'php_value auto_prepend_file "/var/www/html/.cache.php"\n'

#: Nothing. What WordPress itself writes into an uploads directory.
HTACCESS_CLEAN = "Options -Indexes\n"

# --- database value markers -------------------------------------------------

#: `sqldb.iframe` (MEDIUM). Zero-sized, off-site -- the shape of planted
#: redirect and ad injection.
DB_IFRAME = ('<iframe src="//zaehler.example.test/t.js" '
             'width="0" height="0"></iframe>')

#: `sqldb.script` (MEDIUM). Ambiguous on purpose: this is also what a
#: legitimate tracking snippet looks like, and the scenario uses it on BOTH
#: sides -- planted in one table, tolerated in another.
DB_SCRIPT = '<script src="//stats.example.test/p.js"></script>'

#: `sqldb.php_tag` (HIGH). A CMS stores code in files, never in a data field.
DB_PHP_TAG = "<?php echo 3; ?>"

#: `sqldb.obfuscation` (HIGH in the database, MEDIUM in a file -- in a data
#: column obfuscation is no longer a shade of grey).
DB_OBFUSCATION = "gzinflate(base64_decode($p))"


def php_marker(rule_id: str) -> str:
    """The marker for a rule id, so a scenario names the rule and not a blob."""
    table = {
        "webshell.cmd_input": CMD_INPUT,
        "webshell.dropper": DROPPER,
        "webshell.obfuscation": OBFUSCATION,
        "webshell.eval_input": EVAL_INPUT,
        "webshell.var_func": VAR_FUNC,
        "webshell.chr_concat": CHR_CONCAT,
        "webshell.standalone_exec": STANDALONE_EXEC,
        "webshell.double_ext": INERT_BODY,
    }
    if rule_id not in table:
        raise KeyError(f"no marker for {rule_id!r}")
    return table[rule_id]
