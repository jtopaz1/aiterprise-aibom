# How false-positive rates are measured

Every finding in the JSON report carries a `quality` block for its rule, and the
[rules reference](rules.md) lists the same numbers. This page says what a number means, which corpus
it came from and what it cannot tell you.

## The number

```text
fp_rate_measured = clean projects where the rule fired
                   / clean projects whose scan examined something that rule judges
```

- **"Examined something that rule judges"** is read from the scan's own coverage counts: an agent
  skill for `ait.skill.*`, a text file for `ait.secret.*`, a package name for `ait.pkg.typosquat`. A
  project with no skills says nothing about a skill rule, so it is not in that rule's denominator.
- **A rate is written only from 25 such projects up** (`--min-samples`). Below that the rule stays
  `fp_rate_measured: null`, shown as **not measured**. No rate is ever estimated or carried over
  from another rule.
- **A rule listed in a data file that never fired** on a corpus that measured its family is written
  at 0, with that corpus's sample size. Before 2026-11-17 such a rule fell back to its family's
  rate.
- **`scope`** says whether the entry is the rule's own (`rule`) or its family's (`family`, for
  example `ait.skill.*`). A rule without an entry of its own reports its family's.
- **Facts are not measured.** Advisories, known-malicious versions, KEV, licences, registry facts
  and policy decisions are facts about a package, not guesses. A clean corpus says nothing about
  them, so they always read "not measured".

A rate of 0 on *n* samples is not a proof of zero. By the rule of three, the true rate is below
3/*n* with about 95 % confidence: under 1.1 % for the 275 skills, under 0.3 % for the 1,017
package names.

## The corpora (2026-11-17)

| Corpus | Size | Families measured | Result |
|---|---|---|---|
| Agent skills installed on one developer machine (Claude Code skills and plugins, Cursor, Gemini), one per skill name, assumed benign | 275 skills | `ait.skill.*`, with a per-rule entry for each command rule and poison pattern | family 11.64 % (32 of 275); e.g. `desc.hidden.conceal` 4.00 %, poison patterns 9–20 at 0 |
| Site-packages of two local Python environments, one project per package | 210 packages (205 gave secrets a chance) | `ait.secret.*` | family 3.41 % (7 of 205), all from the PEM private-key rule; Anthropic, OpenAI and Slack keys 0.49 % each |
| Names of the packages installed on one developer machine | 1,017 names | `ait.pkg.typosquat`; with `--online`, the release signals | typosquat 0.20 % (2 of 1,017); `publisher-change` 0.63 % (2 of 317); `provenance-dropped` 0 of 317; `dormant-release` and `version-jump` 0 of 131 |

The skill rate is high because the description-poisoning patterns were written for short tool
descriptions and also run over long skill bodies. [Implementation status](STATUS.md) lists what the
measurement found and fixed.

## What is not measured yet

- **Model-file rules.** No real checkpoints have been scanned, so every `ait.model.*` rule reads
  "not measured". An exact-hash rule (`ait.model.known-bad-hash`) has no false positive of its own;
  its risk is a wrong entry, and each entry links the report it was copied from.
- **MCP config rules** (`ait.mcp.*`): no corpus of clean MCP configs large enough yet.
- **The design's targets**: a corpus of at least 200 AI repositories and 500 real model files, and
  automatic demotion of a noisy rule. Neither is built; a critical rule with a measured rate above 0
  still reports critical.

## Limits of these corpora

- They come from one developer's machine. Skills and packages someone chose to install are not a
  random sample of what exists.
- "Assumed benign" is an assumption. A finding on a corpus project counts as a false positive even
  if the project really does what the rule describes, so a rate can overstate the noise.
- The skill corpus measures rules on skill bodies only; the same patterns on MCP tool descriptions
  are not measured.

## Reproduce

```bash
python tools/measure_fp.py --corpus-name "installed agent skills" \
    --projects-from skills.txt --family ait.skill. --merge --write
python tools/measure_fp.py --corpus-name "site-packages sample" \
    --packages /path/to/site-packages --family ait.secret. --merge --write
python tools/measure_fp.py --corpus-name "installed package names" \
    --names-from names.json --online --merge --write
python tools/gen_rules_doc.py
```

`--merge` replaces only the families a run measured. `tools/gen_rules_doc.py` regenerates the rules
reference from the result.

## Report a false positive

Logged in to SecDB, `aiterprise-scan report-fp RULE --notes "…"` sends the rule id and your note,
after asking for your consent, so the case can be reviewed. Nothing else from the scan is sent. A
third-party provider's result (`ext.*`) is never sent; report it to that provider. Meanwhile,
`aibom.policy.yaml` silences a finding locally (see [Policy and suppressions](policy.md)).
