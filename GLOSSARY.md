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
