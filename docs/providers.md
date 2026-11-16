# Third-party providers (bring your own key)

`--byo` asks a third-party service about the files a scan examined, with **your own API key**, over
a direct connection from your machine to that service. One provider is supported today:
[VirusTotal](https://www.virustotal.com). No SecDB login is needed, and the key never goes to
AIterprise.

The results are VirusTotal's, not ours. They have their own rule ids (`ext.virustotal.*`, never
`ait.*`), the title starts with `VirusTotal:`, and the evidence carries the provider name, the
engine counts and the public report link. They are never merged into AIterprise data.

## Usage

```bash
export VT_API_KEY=…                               # from your secret store
aiterprise-scan . --byo virustotal=VT_API_KEY
```

The value after `=` is the **name of an environment variable** that holds the key. The key itself
is never accepted on the command line, where it would land in shell history and process lists,
and the `--byo` value is never repeated in an error message. An unknown provider, a value that
is not `PROVIDER=ENV_VAR`, or a variable that is unset or empty is a usage error (exit 2) before
anything is scanned. `--byo` is repeatable, once per provider.

## What is sent

| Sent | To |
|---|---|
| the SHA-256 of each model file and package archive the scan examined | VirusTotal only |
| your key, in the `x-apikey` header | VirusTotal only |

One request per file: `GET https://www.virustotal.com/api/v3/files/<sha256>`. A model file inside
an archive is looked up by the hash of that member.

## What is never done

- **No upload.** File content never leaves the machine, and the scanner has no upload path. A
  file VirusTotal has never seen stays "unknown".
- **No cache.** Answers are not written to the scanner's cache or to definition data; the next
  scan asks again. The reports you write, and `--save` history, stay on your machine and hold
  these findings like any other.
- **Never sent to SecDB or a cloud.** `scan --upload` and `upload` take provider findings, their
  coverage entry and their notes out of the report before sending it, and print how many were
  kept local. `report-fp` refuses an `ext.*` rule id.
- **Never measured or tuned.** `fp_rate_measured` is always `null` for `ext.*` rules, and the
  mapping below does not change with what VirusTotal returns.
- **No redirect is followed**, so the key is not sent on to another host.
- **The key is never shown or kept**: not in output, reports, saved history or error messages.

## Severity mapping

The adapter reads `data.attributes.last_analysis_stats` (malicious, suspicious, harmless,
undetected):

| VirusTotal says | Finding | Severity |
|---|---|---|
| 5 or more engines: malicious | `ext.virustotal.malicious` | high |
| 1 to 4 engines: malicious | `ext.virustotal.suspicious` | medium — a few engines can be a false positive |
| "suspicious" engines only | `ext.virustotal.suspicious` | medium — can be a false positive |
| no engine flags the file | none; counted as known to VirusTotal, never as clean | |
| `404`, or no engine result yet | none; counted as unknown to VirusTotal | |

Provider findings count towards `--fail-on` like any other finding. `ext.virustotal.malicious`
has the verdict `malicious`, so only an expiring suppression that names its fingerprint accepts it
(see [Policy and suppressions](policy.md)). The fingerprint includes the file's SHA-256: new
content at the same path is a new finding.

## Budget

The public VirusTotal API key allows 4 lookups a minute. A scan therefore makes **at most 4
lookups** and never sleeps. They go to the most suspicious files first: files that already have
findings (worst first), then pickle-family model files, then the rest. Files beyond the budget are
reported as not checked — never as clean.

If your key allows more, raise the budget: `AITERPRISE_VIRUSTOTAL_MAX_LOOKUPS=200`.

## When VirusTotal gives no answer

"No answer" is never read as clean. Each case is a note in the report (`not verified with
VirusTotal`) and shows in the coverage line (`virustotal <known>/<answered>`, or `virustotal
skipped (…)`). After any failed call VirusTotal is not called again in that scan; a call is never
retried.

| Case | Reported as | Exit code |
|---|---|---|
| quota exhausted (`429`) | the remaining files are not verified | unchanged |
| key refused (`401`, `403`) | the remaining files are not verified | unchanged |
| timeout, unreachable, `5xx`, an unreadable answer | the remaining files are not verified | 2 (incomplete scan) |
| over the lookup budget | those files are not checked | unchanged |
| `--offline` | no call is made; every file is not verified | unchanged |

## Environment

| Variable | Meaning |
|---|---|
| `AITERPRISE_VIRUSTOTAL_MAX_LOOKUPS` | lookups per scan (default 4) |
| `AITERPRISE_VIRUSTOTAL_URL` | base URL instead of `https://www.virustotal.com`, for a proxy or a test server; https only (plain http to this machine only), the same rule as for [SecDB and cloud keys](privacy.md) |

## VirusTotal's terms

Your use of VirusTotal is between you and VirusTotal. Their public (free) API key is for
non-commercial use under VirusTotal's terms of service and is rate-limited; commercial use needs a
premium key from VirusTotal.
