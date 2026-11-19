# Editors and CI

The same scanner and the same `aibom.policy.yaml` run everywhere; only how the findings are shown
changes.

## VS Code and Cursor

Copy [`templates/vscode/tasks.json`](https://github.com/jtopaz1/aiterprise-aibom/blob/main/templates/vscode/tasks.json)
to `.vscode/tasks.json` in your project (or merge its `tasks` into the one you have), then run
**Tasks: Run Task** and pick one:

| Task | What it does |
|---|---|
| AIBOM: scan the workspace | New findings go to the Problems panel, each at its file and line; the task fails when the gate fails |
| AIBOM: full report with inventory | The table report, with every discovered AI component |
| AIBOM: this machine's MCP servers and skills | The agent configs and skills folders of this machine, into the Problems panel |
| AIBOM: open the local dashboard | `aiterprise-scan ui` |

The tasks expect `aiterprise-scan` on the `PATH` (for example `pipx install git+https://github.com/jtopaz1/aiterprise-aibom@v0.1.0`).
The Problems panel is fed by `--format compact`: one line per new finding,

```text
requirements.txt:1: error: Known-malicious package version (litellm 1.82.7) [critical ait.pkg.malicious]
```

which also suits Vim's quickfix list and Emacs' compilation mode. Critical and high findings are
errors, medium ones warnings, low and info ones information.

## GitLab CI

```yaml
include:
  - remote: https://raw.githubusercontent.com/jtopaz1/aiterprise-aibom/main/templates/gitlab/aiterprise-scan.gitlab-ci.yml
```

The job runs on merge requests and on the default branch. A merge request shows the new findings
in its Code Quality widget (`--format codequality`, a Code Climate issue list), the job log shows
the table, and `aiterprise-report/` keeps the Markdown report, the Code Quality report and the AI-BOM
(CycloneDX 1.6, the newest version GitLab reads). Set `AIBOM_FAIL_ON`, `AIBOM_PATH` and `AIBOM_ARGS`
as job variables; a SecDB key goes in a masked CI/CD variable named `AITERPRISE_API_KEY`. The job
installs the release's wheel from GitHub (`AIBOM_INSTALL`); the image has no git, so a `git+https://`
URL needs an image that has it.

## GitHub Actions

See [Quickstart](quickstart.md#ci): the action comments the new findings on the pull request, writes
the job summary, uploads SARIF to code scanning and gates the build.

## pre-commit

```yaml
- repo: https://github.com/jtopaz1/aiterprise-aibom
  rev: v0.1.0
  hooks: [{ id: aiterprise-scan }]
```
