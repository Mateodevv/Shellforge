# Security

## Your scanner will flag this repository, and it is right to look

`shellforge/markers.py` contains short strings that look like web shells —
`system($_GET[...])`, `gzinflate(base64_decode(...))`, an `.htaccess` mapping
`.jpg` to the PHP handler. That is the point of them: they carry the pattern a
detector looks for so that a detector can be tested.

**They are inert.** Each one is the shortest text that trips exactly one rule,
in the spirit of an EICAR file. Nothing here accepts a connection, reads a
request, writes a file, or runs. There is no shell in this repository, and
there must never be one — see [CONTRIBUTING.md](CONTRIBUTING.md).

Generated cases contain the same markers, plus invented addresses out of the
documentation ranges of RFC 5737 and domains ending in `.test`. No data from
any real incident is in this repository or produced by it. See
[NOTICE](NOTICE).

### If your antivirus quarantines something

Exclude the output directory from real-time scanning. On Windows, Defender
intervenes when a file is **opened**, not when it is written, so a generated
case is written successfully and then becomes unreadable. Shellforge reads
every file back before returning and fails with the file name if one has gone
missing, which is why the error says "evidence did not survive being written"
rather than something about the engine finding nothing.

`--no-verify-readable` turns off the check, not the problem.

## What this tool is not

It is not a service, takes no input from a network, and opens no port. It
writes files to a directory you name and reads a SQLite database you point it
at. The realistic failure modes are a path traversal through a scenario name
or an output path — both of which are your own arguments, on your own machine.

## Reporting a vulnerability

Do not open a public issue. Report privately through GitHub's **Security →
Report a vulnerability** on this repository.

Worth reporting:

- anything that makes a generated case escape the output directory,
- anything that turns a marker into something that actually executes,
- a way for a scenario or ground-truth file to cause code execution when read.

Vulnerabilities in SHELLHOUND itself belong in
[its own SECURITY.md](https://github.com/Mateodevv/shellhound/blob/main/SECURITY.md),
not here.
