# Contributing

Bug reports, detection rules, taxonomy entries and fixes are welcome. Security problems go through
[SECURITY.md](SECURITY.md), not a public issue.

## Sign off your commits (DCO)

Sign off every commit you contribute with a `Signed-off-by:` line. By adding it you certify the
[Developer Certificate of Origin 1.1](https://developercertificate.org/): you wrote the change, or
otherwise have the right to submit it under the project's licence (Apache-2.0).

```bash
git commit -s -m "Catch base64-piped curl in MCP commands"
```

`-s` adds `Signed-off-by: Your Name <you@example.com>` from your git config. The name and address
become part of the public history. There is no separate contributor licence agreement.

## Clean room

Write rules and code from public sources: advisories, incident write-ups, format specifications,
your own research. Do not copy code, rules, signatures or data from another scanner or a commercial
product, even one whose output you can see. Say where an indicator came from: an entry copied from
a report links it (as every entry in `known-bad-hashes.json` does), and every bundled data file is
attributed in [NOTICE](NOTICE).

## Build and test

Python 3.11 or newer. The scanner has no runtime dependencies and must keep it that way: the
standard library only (`python tools/check_licences.py` fails otherwise).

```bash
PYTHONPATH=src python -m unittest discover -s tests -p "test_*.py"
python tools/killer_demo.py                       # five planted problems, one scan; exit 0 only if all five hit
PYTHONPATH=src python -m aiterprise_scan scan . --offline --exclude "tests/**" --fail-on high --format table
```

On Windows, separate `PYTHONPATH` entries with `;`. CI runs the same commands, plus the docs build,
the GitHub Action, the pre-commit hook and the binaries.

Three rules the code keeps everywhere, and a change must not break them:

- **Scanned content is hostile.** Never import, unpickle, load, execute or launch anything that was
  scanned; read it with size limits.
- **`--offline` sends nothing.** Every network call goes through the online path and is listed in
  [docs/privacy.md](docs/privacy.md).
- **No invented numbers.** A false-positive rate is measured or shown as not measured; "no match"
  is never reported as "safe".

## Contributing a detection rule

Most rules are data in `src/aiterprise_scan/data/ait/`: command rules and description-poisoning
patterns are a regex with an id, severity, description, remediation and a `sample` it must match;
model rules, known-bad hashes and licence verdicts have their own files. A rule is accepted when it
passes three gates:

1. **It catches what it claims.** Its `sample`, plus a test with a realistic malicious input.
   Where a whole scan matters (exit code, the gate, the report), add a golden fixture under
   `tests/golden/` and its expected exit code and findings in `tests/test_golden.py`.
2. **It stays quiet on near misses.** A test with benign text that looks like the attack: the
   install line from a real README, a skill that tells the agent *not* to read secrets. The clean
   fixtures (`F02`, `F04b`, `F12`) must stay free of medium-or-worse findings.
3. **Its tests fail without it.** Delete or weaken the pattern and run the tests: if nothing goes
   red, the tests do not cover the rule yet.

Then regenerate the rules reference, which a test checks:

```bash
python tools/gen_rules_doc.py
```

A new rule reads **not measured** until it has been measured on a corpus with
`tools/measure_fp.py` ([how rates are measured](docs/fp-methodology.md)). If you have a corpus of
clean projects, include the run in the pull request; if not, say so, and the rule ships unmeasured.

## Pull requests

- One change per pull request, with the tests that prove it, and `docs/STATUS.md` updated when
  something is built, changed or found not to work.
- Describe what you ran and what you did not.
- Say what someone running the scanner will notice. A release's `CHANGELOG.md` section, which
  becomes its GitHub release notes, is written from that.
- The pull-request template's checklist repeats these steps: tick what you ran.
- False positives: `aiterprise-scan report-fp RULE` (with consent, when logged in to SecDB) or the
  **False positive** issue form, with the smallest input that triggers it. Bugs and missing
  coverage have their own forms; blank issues are off. Vulnerabilities and evasions go to a
  private report ([SECURITY.md](SECURITY.md)), never an issue.
