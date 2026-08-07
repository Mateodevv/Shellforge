# Shellforge — Konzept

Stand 2026-08-07. **Der MVP steht und läuft** — siehe [Status](#status) am Ende.
Der Rest dieses Dokuments ist der Entwurf, dem er folgt.

## Zweck

Shellforge erzeugt randomisierte, realistische CMS-Vorfallsdaten, um
**SHELLHOUND** (`..\shellhound`) zu testen — eine lokale DFIR-Workbench, die
Webroot-Kopie, Apache/Nginx-Access-Logs und einen CMS-SQL-Dump einliest und aus
~34 Regeln Findings erzeugt.

Shellhounds vorhandene `tests/fixtures.py` sind bewusst minimal (eine winzige
Datei pro Regel). Damit ist nichts geprüft, was Skalierung, realistisches
Rauschen, Kreuzkonsistenz zwischen den Quellen oder die False-Positive-Rate
angeht. Genau diese Lücke füllt Shellforge.

## Kernidee: Testorakel, nicht Datengenerator

Shellforge gibt **Evidence + Ground Truth** aus. Neben `webroot/`, `logs/`,
`dump.sql` entsteht eine `ground_truth.json`, die festhält, was gepflanzt wurde
und welche Regel darauf feuern muss. Damit wird aus „sieht plausibel aus" eine
Messgröße: Recall und Precision pro Regel, lauffähig in CI.

## Architekturregel (nicht verhandelbar)

Shellforge importiert oder spiegelt **niemals** Shellhounds Erkennungscode.
Sonst erzeugt eine kaputte Regel genau die Daten, die zur kaputten Regel passen.
Shellforge sagt unabhängig, *was gepflanzt wurde*; Shellhound sagt unabhängig,
*was es sieht*; der Vergleich ist der Test. Deshalb eigenes Repo, kein
Unterordner von Shellhound.

## Payload-Regel

Nur inerte Marker im EICAR-Geist — kürzester Text, der genau eine Regel
auslöst. Keine funktionsfähigen Shells. Grund: Shellhounds eigene
CONTRIBUTING-Regel, und praktisch frisst Windows Defender funktionierende Shells
und meldet das als `OSError(22)`. Nach der Generierung läuft ein
`--verify-readable`-Durchgang, der abbricht statt einen halb aufgefressenen Fall
auszuliefern.

## Vier Schichten

1. **Szenario** — das Narrativ: Recon → Exploit → Shell-Drop → Nutzung →
   Persistenz → DB-Injection. Hier entsteht Realismus, nämlich durch
   **Kreuzkonsistenz**: die Datei im Webroot muss im Log zu plausibler Zeit
   abgerufen worden sein, der Admin-Account im Dump nach dem Bruteforce
   registriert, der Error-Log-Eintrag einen existierenden Pfad nennen.
2. **Weltmodell** — CMS-Profil (WordPress, Joomla, Drupal, TYPO3, Magento,
   PrestaShop, Contao) mit Verzeichnisstruktur, Versionsmarkern an den Stellen,
   wo Shellhound sie liest, Plugin-Sets; dazu die Betriebs-Baseline aus echten
   Besuchern, Bots, Redaktionsarbeit, Cronjobs.
3. **Renderer** — je Evidence-Art einer: Webroot, Access-Log (Apache combined /
   Nginx / rotiert / `.gz`), Error-Log, SQL-Dump, saubere Referenzkopie.
4. **Ground-Truth-Emitter** — schreibt mit, was die anderen drei getan haben.

Nutzen der Trennung: dasselbe Szenario läuft durch sieben CMS-Profile. In Drupal
testet es die generische Spalten-nach-Name-Erkennung, in WordPress den
positionsbasierten Pfad — mit einem Szenario-Skript.

## Szenariokatalog

| Szenario | Was es prüft |
|---|---|
| `wp-upload-shell` | Standardfall: Upload-Lücke, Shell, `.htaccess`-Persistenz |
| `bruteforce-admin` | Fall **ohne** Datei-Artefakt — nur Log + DB |
| `db-only-spam` | SEO-Iframes in `wp_posts`, Webroot sauber |
| `ghost-shell` | Shell vor der Kopie gelöscht — nur das Error-Log beweist sie noch |
| `false-guard` | Shell mit gefälschtem `// _JEXEC`; die dokumentierte Limitation |
| `supply-chain` | Kompromittiertes Plugin-Update: korrekter Guard, obfuskierte Payload |
| `clean-baseline` | Erwartung: **null** Findings |
| `noisy-but-clean` | Legit-Admintool mit `shell_exec`, Tracking-`<script>` im Dump, Scanner-Flut — höchstens INFO/LOW |
| `multi-wave` | Zwei Angreifer, überlappende Zeiträume |

Die beiden sauberen Szenarien sind die wertvollsten und werden meist vergessen.
Shellhounds Fixtures haben genau **eine** False-Positive-Wache
(`wp-includes/functions.php`). Eine Regelverschärfung, die tausend legitime
Plugin-Dateien rot färbt, würde die aktuelle Suite komplett passieren.

## Ground-Truth-Format

```json
{
  "seed": 42, "scenario": "wp-upload-shell",
  "cms": {"kind": "wordpress", "version": "6.4.2"},
  "planted": [
    {"kind": "file", "path": "wp-content/uploads/2026/01/kb-media.php",
     "sha256": "…", "expect_rules": ["webshell.upload_php"], "expect_severity": "high"},
    {"kind": "actor", "ip": "203.0.113.42", "expect_rules": ["logs.upload_php_2xx"]}
  ],
  "must_not_fire": [
    {"path": "wp-content/plugins/backup-tool/cli.php",
     "reason": "legit admin tool using shell_exec, guarded, outside upload dirs"}
  ],
  "timeline": [{"t": "2026-01-07T09:12:00Z", "actor": "203.0.113.42", "act": "drop_shell"}]
}
```

`planted` misst Recall, `must_not_fire` misst Precision. Regel-IDs sind stabil
(`webshell.upload_php`, `logs.sqli`, …) und liegen neben der Regel in der Engine.
`shellforge score` diffed Shellhounds `/api/cases/{slug}/findings` gegen die
Ground Truth. Nebenprodukt: eine Regelabdeckungsmatrix — welche der 34 Regeln
kein Szenario je auslöst.

## Feindliche Achsen

Shellhounds `fixtures_hostile.py` („55 Bugs, die Hälfte unsichtbar auf dieser
Form") ist die beste vorhandene Spezifikation. Diese Achsen werden
Generator-Parameter statt handgeschriebener Sonderfixtures:

- **Zeit** — Log-Zeitzone ≠ DB-Zeitzone, freier Offset, DST-Sprung im Zeitraum.
  Shellhound hat einen Offset-Regler pro Quelle; die Ground Truth kennt die
  wahre Zeitachse.
- **Skalierung** — 500+ Clients (über den 200er-Cap), 1–5 Mio. Logzeilen für die
  55k/s-Behauptung, mehrere Logdateien mit gleichem Basename.
- **Encoding/Form** — Latin-1, BOM, CRLF, sehr lange URIs, kaputte Zeilen
  zwischen guten, Groß-/Kleinschreibung in Pfaden, IPv6, `<?PHP` in Großbuchstaben.
- **Dump-Fallen** — DDL innerhalb von Datenwerten, escapte Backslashes,
  wechselnde Tabellenpräfixe.

## Zwei Nebenprodukte

**Referenzkopie.** Shellforge erzeugt sauberes Release *und* manipulierten
Webroot aus derselben Quelle → perfekte Ground Truth für den Webroot-Diff
(added/modified/deleted), sonst kaum zu beschaffen.

**Fallentwicklung.** Dasselbe Szenario als `v1` und `v2` (v2 = v1 plus weitere
Angreiferaktivität) testet direkt „Triage-Zustände überleben einen Re-Scan,
Fingerprints sind stabil" — heute nur von Hand prüfbar.

## Technik

Python ≥ 3.10, reine Standardbibliothek mit kleinen mitgelieferten Wortkorpora
(kein Faker) — passt zu Shellhounds „Tests laufen ohne zusätzliche
Abhängigkeiten". Alles seed-basiert: gleicher Seed → byteidentischer Fall.

```
shellforge gen --scenario wp-upload-shell --cms wordpress --seed 42 --scale medium --out ./cases/
```

Die bestehenden Mini-Fixtures in Shellhound werden **nicht** ersetzt. Sie sind
gut, weil ein Fehlschlag dort die kaputte Regel benennt. Shellforge ist die
Schicht darüber: Integration, Skalierung, Precision.

## MVP

Ein Szenario (`wp-upload-shell`), ein CMS-Profil, Ground Truth, `shellforge
score` gegen den Findings-Endpoint. Sobald die Schleife einmal geschlossen ist
und eine Zahl ausgibt, sind weitere Szenarien und CMS-Profile Fleißarbeit. Der
übliche Fehler wäre, erst breit Generatoren zu bauen und die Auswertung ans Ende
zu schieben.

## Entschiedene Fragen

**`shellforge score` liest `case.db` direkt**, nicht die HTTP-API. Die API
hieße laufender Server, Token und Job-Polling in einem CI-Job, der eine Zahl
will. Die Kopplung, die man stattdessen kauft, ist eine Tabelle mit sechs
Spalten — und `findings` ist das stabilste Objekt im Schema, weil der
Fingerprint per Design Re-Scans überleben muss.

**Artefaktidentität.** Shellhound speichert als Artefakt den absoluten Pfad auf
der Analysemaschine (`webshell.py:283`); `site_path` dient nur intern den
Standortregeln. Die Ground Truth bleibt webroot-relativ und portabel, der
Scorer normalisiert über die `evidence`-Tabelle — dieselbe Quelle, aus der die
Oberfläche ihre `roots` zieht.

## Status

| Baustein | Zustand |
|---|---|
| Paket, CLI (`gen` / `score` / `check` / `scenarios`) | fertig |
| Ground-Truth-Modell + JSON-Emitter | fertig |
| WordPress-Weltmodell | fertig |
| Renderer: Webroot, Access-Log, Error-Log, SQL-Dump | fertig |
| Weltmodelle WordPress **und Joomla** | fertig |
| **Zehn Szenarien**, 17 CMS-Paarungen (siehe unten) | fertig |
| Scorer + Regelabdeckungsmatrix + `check --all` | fertig |
| Eigene Testsuite (22 Tests) | grün |

Gemessen gegen Shellhound, alle 17 Paarungen, alle Seeds und Skalen:
**Recall 100 %, Precision 100 %, Regelabdeckung 100 %** (34 von 34 Regeln, auf
Linux; unter Windows 97,1 %). `large` sind 238.940 Logzeilen und 341 Dateien;
die komplette Schleife aus Erzeugen, Analysieren und Bewerten läuft in
7,4 Sekunden.

Die Trennung von Welt und Narrativ zahlt sich hier aus: sieben der zehn
Szenarien laufen unverändert gegen beide CMS-Profile. Nur die drei
CVE-spezifischen sind an ihr System gebunden, und die Registry **verweigert**
eine ungültige Paarung, statt sie stillschweigend zu erzeugen — ein
`wp-upload-shell` gegen Joomla beschriebe einen Einbruch durch ein
WordPress-Plugin in eine Installation, die keine Plugins hat.

| Szenario | Prüft |
|---|---|
| `wp-upload-shell` | Der Standardfall, CVE-2020-25213 |
| `joomla-helix3` | CVE-2026-49049, RCE-Variante. **Reproduziert eine Erkennungslücke**, siehe unten |
| `joomla-helix3-deface` | Dieselbe CVE, DB-Variante: der Webroot bleibt byteidentisch zu einer sauberen Installation |
| `shell-kit` | Ein Toolkit im Theme — Content-Regeln allein, ohne dass die Standortregel ihre Arbeit macht |
| `bruteforce-admin` | Kein Datei-Artefakt. Zwei Fluten: eine bekommt einen Redirect und muss HIGH werden, die andere nicht und muss MEDIUM bleiben |
| `db-only-spam` | Webroot sauber, Code in der Datenbank |
| `probe-wave` | Identische SQLi- und Traversal-Payloads, einmal mit 200 und einmal mit 404 beantwortet |
| `false-guard` | Gefälschtes `ABSPATH` im Kommentar — die dokumentierte Limitation, von beiden Seiten festgenagelt |
| `ghost-shell` | Vor der Kopie gelöschte Shell. **Reproduziert eine Diskrepanz**, siehe unten |
| `clean-baseline` | Nichts ist passiert. Erwartung: INFO über die Scanner, sonst nichts |

Die letzte Regel, `webshell.unreadable`, braucht einen echten Lesefehler:
`chmod 000` unter POSIX, und unter Windows gibt es nichts, worauf sich ein
Generator verlassen kann. Das Szenario pflanzt sie unter POSIX und schreibt
unter Windows eine Notiz in die Ground Truth, statt eine Abdeckung zu
behaupten, die die Plattform nicht hat.

### Sieben Befunde aus dem Bau

**Eine Datei über ihrer Nutzlast zu ändern spaltet die Entscheidung.** Der
Fingerprint ist `source|rule|artifact|line`. Fügt ein Angreifer Zeilen *vor*
der Nutzlast ein, wandert jedes Content-Finding der Datei — das alte behält
die Triage-Entscheidung und beschreibt eine Zeile, an der nichts mehr steht,
das zutreffende kommt unentschieden zurück. Gemessen an `cache-warm.php`:
`webshell.obfuscation` steht danach zweimal in der Tabelle, Zeile 2 als
`reviewed` und Zeile 4 als `new`. Der Analyst wird zweimal gefragt, und der
Fall meldet ein Problem als zwei. Positionsregeln (`upload_php`,
`double_ext`) sind mit `line=None` gespeichert und bleiben korrekt erhalten.
Reproduziert von `shellforge evolve`, dort als `SPLIT` gemeldet.


**Shellforge hat eine Verhaltensänderung in Shellhound erkannt, und zwar
sofort.** Zwischen zwei Läufen kam Shellhounds Commit *„Das Werkzeug hat den
Betreiber der Seite des Einbruchs beschuldigt"* (5a14eb1) dazu: aus echten
Falldaten mit 1,33 Mio. Logzeilen war klar geworden, dass ein Redirect kein
Erfolg ist — Joomla beantwortet jeden Login-POST mit 303 — und dass ein POST
mit `option=com_*` kein Login-Versuch ist. Beide Korrekturen sind richtig.
Die Szenarien wurden rot, weil sie noch das alte Verhalten erwarteten, und
genau dafür existiert das Repo: die CI wird rot, wenn *drüben* etwas anders
wird, und der Score-Report sagt welche Zusage nicht mehr gilt.

**`logs.login_success` kann auf WordPress nicht mehr feuern.** Der Ersatz für
den Redirect ist ein 2xx aus dem authentifizierten Backend — richtig, aber
`AUTHENTICATED_AREA_RE` lautet `/administrator/index.php?…option=com_…` und
matcht damit nur Joomlas URL-Form. `wp-login.php` gilt weiterhin als
Login-Endpunkt, die Flut-Hälfte greift also; die Beweis-Hälfte hat auf
WordPress nichts zum Matchen. Die einzige HIGH-Log-Regel über einen
erfolgreichen Einbruch ist auf dem meistverbreiteten CMS tot. Das Szenario
`bruteforce-admin` läuft auf beiden Profilen und behauptet den Unterschied
explizit. Naheliegendes Gegenstück wäre `/wp-admin/` ohne `admin-ajax.php`
und `admin-post.php`, die auch ohne Session erreichbar sind.

**Die Bruteforce-Schwelle ist weiterhin von der Loglänge abhängig.**
`logs.login_flood` zählt 30 Login-POSTs pro Adresse, `logs.login_success` 30
plus ein 3xx — beide ohne Zeitfenster. Ein Administrator, der jeden
Werktagmorgen einmal ein Login macht und jedes Mal den Redirect eines
erfolgreichen Logins bekommt, überschreitet die Schwelle nach etwa sechs
Wochen und wird nach neun Wochen als *possible successful brute-force* mit
**HIGH** gemeldet. Am Standort hat sich nichts geändert; nur der Log ist
länger. Gefunden hat das der Skalentest, nicht die Durchsicht: bei
`--scale large` entstehen 60 Tage Traffic, und der eigene Redakteur des
Falls kippte über die Schwelle. Das Szenario `long-tail-admin` reproduziert
es absichtlich und bei jeder Skala, mit einem zweiten Administrator gleicher
Gewohnheit und weniger Tagen, der still bleibt — die beiden unterscheiden
sich in nichts als der Zeit, die sie im Log stehen. `common.plant_editor`
zählt jetzt die erzeugten Logins und sagt die Folge voraus, statt bei einer
Skala umzukippen.


**`up.php.json` ist für alle drei Engines unsichtbar.** Helix3 hängt `.json`
an den Layout-Namen an, aus `../../up.php` wird also `up.php.json` im Webroot.
Diese Datei fällt durch jedes Raster, und zwar jeweils aus einem eigenen
Grund: `DOUBLE_EXT_RE` matcht *harmlos-dann-ausführbar* (`logo.jpg.php`), hier
ist es umgekehrt; `.json` steht nicht in `PHP_EXTS`, die Content-Regeln öffnen
die Datei also nie; und `_PATH_RE` im Errorlog schneidet den Pfad bei `.php`
ab, wodurch der Fatal auf `/var/www/html/up.php` auflöst — eine Datei, die
nicht existiert. Ausführbar ist sie trotzdem, weil `mod_mime` auf jede im
Namen vorhandene Endung dispatcht; genau deshalb wählt der Exploit diese Form.
Das Szenario trägt eine konventionell benannte Shell aus demselben Einbruch
als Kontrolle mit, damit „nichts gefunden" nicht mit „die Engines liefen nie"
verwechselt werden kann.


**Die Doku des Error-Log-Motors widerspricht sich.** `docs/rules.md` nennt „a
file deleted before the copy was taken" als das, wofür der Motor da ist — „the
log is the only remaining evidence that the path existed at all" — und sechs
Zeilen später: „a path is only written when it resolves to a file under a
registered webroot". Beides zusammen geht nicht. `errorlog._resolver()`
verlangt `os.path.isfile()`, also wird ein Fatal auf eine gelöschte Datei
unter `unresolved` gezählt und erzeugt kein Finding. Gemessen, nicht
gefolgert: `{'findings': 0, 'unresolved': 1}`. Das Szenario `ghost-shell`
kodiert das tatsächliche Verhalten und trägt eine Kontroll-Shell mit, die
vorhanden ist — sonst wäre „kein Finding" nicht von „der Job lief nie" zu
unterscheiden. Ob Code oder Doku falsch ist, entscheidet dieses Repo nicht.


**Der Error-Log-Resolver matcht per Tail.** Ein Pfad `/var/www/html/…` aus dem
Log wird gegen den registrierten Webroot aufgelöst, indem sukzessive vordere
Segmente abgeschnitten werden. Deshalb funktionieren synthetische
Server-Pfade, ohne dass der Fall an sein Verzeichnis gebunden wird — die
Evidence bleibt verschiebbar.

**Gewöhnliche PHP-Warnings sind erwartete Findings, keine Störung.** Der erste
Lauf meldete drei „False Positives" auf legitimen Plugin-Dateien. Das war
korrektes Verhalten von Shellhound (`errorlog.soft`, LOW) und ein Loch in der
Ground Truth. Sie stehen jetzt als Erwartung drin — die Zusage „bleibt LOW"
ist prüfenswert, weil die Regel ihr Gewicht erst gewinnt, wenn sie auf
demselben Artefakt landet wie etwas anderes.

## Siehe auch

[cve-log-signatures.md](cve-log-signatures.md) — verifizierter CVE-Katalog mit
exakten Log-Signaturen und Webroot-Artefakten pro CMS.
