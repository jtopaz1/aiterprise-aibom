# aiterprise-scan

The open-source scanner that lists a project's AI supply chain and judges it. This glossary fixes
the words for a scan and for the decision whether it passes.

## Language

### Scanning

**Scan**:
One pass over a target that lists its AI components and the findings about them, with no decision
about passing or failing.
_Avoid_: run, check, analysis

**Gated scan**:
A scan to which the project's policy, suppressions and baseline have been applied, and whose pass
or failure is decided.
_Avoid_: judged scan, policy scan

**Gate**:
The decision whether a scan passes: it fails when a finding that nobody has accepted is at or above
the policy's threshold.
_Avoid_: check, quality gate

### Sources

**Source**:
Something a scan consults to judge what it found: a data set (the malicious-package snapshot, OSV,
KEV), a service (a package registry, SecDB) or one of the scanner's own analyzers.
_Avoid_: analyzer (for all of them), checker, feed, engine

**Coverage**:
Per source and scan: how many items the source was asked about and for how many it had something
to say; a source that was not consulted says why. "No match" is never read as "never checked".
_Avoid_: examined (the key it has in a report), stats

### Rules for text

**Command rule**:
A shipped pattern that judges a command line something will run: an MCP server's launch command, a
hook, a skill's script or a package's install script. It finds, for example, a download piped into
a shell. One rule makes the same finding wherever the command was found; only the rule id's family
(`ait.mcp`, `ait.skill`, `ait.archive`) says where.
_Avoid_: command pattern, shell rule

**Poison pattern**:
A shipped pattern that judges free text an agent reads, such as a tool description or a skill's
instructions, for words that turn the agent against its user: hidden instructions, reading secrets,
sending data away.
_Avoid_: poison rule, injection rule, description rule

### Reports

**Report document**:
The JSON form of one scan's result, with a named schema: what the JSON report prints, what the
history keeps and what an upload starts from. The table, SARIF and HTML reports are renderings, not
report documents.
_Avoid_: scan document, result file, dump

**Upload view**:
The copy of a report document that may leave the machine: it holds no third-party provider results
and no local paths.
_Avoid_: sanitised report, stripped report

### What the gate reads

**Policy root**:
The project directory a scan belongs to: the scanned directory, the directory holding the scanned
file, or the current directory when only a BOM is judged. A scan of the machine's own agent configs
has none.
_Avoid_: project root, working directory, policy directory

**Suppression**:
A recorded decision to accept one finding, or a family of findings, until a stated date and for a
stated reason.
_Avoid_: waiver, exception, mute

**Baseline**:
The set of findings a project already had when it adopted the gate; they are reported and do not
fail it.
_Avoid_: snapshot, allow-list
