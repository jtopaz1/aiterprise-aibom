# Policy and suppressions

The scanner reads `aibom.policy.yaml` from the scanned directory, or the file given with
`--policy`. `aiterprise-scan policy lint FILE` checks one without scanning.

```yaml
version: 1
use_context: commercial          # commercial | internal | research | non-profit
fail_on: [critical, high]
ignore:
  - rule: ait.pkg.malicious-unpinned
    paths: ["experiments/**"]
allow_packages: ["pkg:pypi/openai@>=1.40"]
deny_packages: ["pkg:pypi/litellm@1.82.7"]
allow_model_licences: [apache-2.0, mit]
deny_model_licences: [cc-by-nc-4.0]
suppressions:                    # expiry is mandatory
  - finding: 1a2b3c4d5e6f7a8b    # fingerprint, advisory id or rule id
    until: 2027-06-30
    reason: vendor patch scheduled
    approved_by: security@company
baseline: .aiterprise/baseline.json
```

| Key | Meaning |
|---|---|
| `use_context` | how the code is used; licence verdicts depend on it |
| `fail_on` | severities that fail the build (the `--fail-on` flag overrides it) |
| `ignore` | drop a rule, optionally only under some paths |
| `allow_packages` / `deny_packages` | purl patterns with version ranges; a denied package is an `ait.policy.denied-package` finding |
| `allow_model_licences` / `deny_model_licences` | licence ids for models and datasets |
| `suppressions` | accept a specific finding until a date, with a reason |
| `baseline` | findings recorded here do not fail the gate |

## Where the gate looks

The policy, the suppressions and the baseline belong to the scanned project:

| Scan | Directory that is read |
|---|---|
| a directory | that directory |
| a single file | the directory that holds it |
| `--bom FILE` alone | the current directory |
| `mcp --agent-configs` without `--path` | none: no policy is looked up unless `--policy` names one |

`.aiterprise/suppressions.json` and the `baseline:` path of a policy are read from that directory, also
when `--policy` names a policy file kept somewhere else. `--baseline FILE` names a baseline directly.

A policy or a suppressions file that does not load stops the scan with exit code 2; nothing is
scanned. A key the scanner does not know is not an error: it is ignored and listed in the notes of
the report.

The command line, the [web UI](ui.md) and the MCP tool apply the same gate, so a project passes or
fails the same way through each of them.

## Org policy from the cloud

An AIterprise cloud can hold one policy for the whole organisation. Each project pulls it:

```bash
aiterprise-scan policy pull --cloud https://aibom.example.com      # or set AITERPRISE_CLOUD_URL
```

It writes `aibom.policy.yaml` (or `--out FILE`) with a first-line comment naming the policy version.
The next pull sends that version back and leaves the file alone when nothing changed. A policy that
does not load with this scanner is refused and the local file is kept. The pull needs the SecDB
key you logged in with; the key is only ever sent over https (plain http only to this machine).

## Suppressions

A suppression always has an expiry. When it lapses, the finding fails the gate again. Suppressions
made in the [web UI](ui.md) go to `.aiterprise/suppressions.json` with the same rules — a reason,
and an expiry at most 365 days ahead. Commit that file so CI applies them too.

## Known-malicious findings

A finding whose verdict is `malicious` (for example `ait.pkg.malicious`) is never silenced by
`ignore`, `allow_packages`, a rule-, path- or advisory-wide suppression, or a baseline. Only an
expiring suppression that names its fingerprint accepts it. A record that its source withdrew is
reported with status `withdrawn` (info, exit 0) — never active, never dropped.

## Importing from Snyk

`--snyk .snyk` imports the ignore entries of a `.snyk` file as suppressions; entries without an
expiry get 30 days.
