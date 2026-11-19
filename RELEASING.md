# Releasing `aiterprise-scan`

Pushing a tag `vX.Y.Z` runs `.github/workflows/release.yml`:

```text
dist ──────┐                      wheel + sdist, licence check, killer demo, self-SBOM
binaries ──┴─ sign ─┬─ pypi       Sigstore bundle per file, SHA256SUMS; then PyPI, only when switched on
                    ├─ image      ghcr.io/<owner>/aiterprise-scan with provenance and SBOM
                    └─ github-release (needs sign and image, not pypi)
```

**PyPI is off.** The project has no PyPI account, so the `pypi` job runs only when the repository
variable `PUBLISH_TO_PYPI` is `true` ([Publishing to PyPI](#publishing-to-pypi-optional)). People
install from the git tag, the release's binaries and wheel, or the image; the GitLab template
installs the release's wheel.

A refused PyPI upload does not hold back the GitHub Release. Fix the cause (for `invalid-publisher`,
the pending publisher's five values below) and re-run the failed `pypi` job of the same run; nothing
is rebuilt. A release run made before `github-release` stopped waiting for PyPI (v0.1.0) is published
with the `publish-release` workflow instead: run it by hand with the tag and the run's id. It
publishes the run's own signed files only after each matches `SHA256SUMS` and carries a Sigstore
signature made by `release.yml` at that tag.

`v0.1.0` was tagged on 2026-11-18: signing and the ghcr.io image went out; PyPI refused the upload
three times (`invalid-publisher`: there was no PyPI account, so no publisher). Its GitHub release was published on 2026-11-19
by `publish-release` from run 44243042031: 20 files, each of the 10 that are not bundles checked
against `SHA256SUMS` and its signature first.

CI already runs most of a release on every pull request: the wheel, the sdist, the self-SBOM, the six
binaries (Linux, macOS and Windows on x86-64 and arm64, each held to the killer demo) and the
container image. The parts that only a real tag exercises are signing, the PyPI upload, the ghcr.io
push and the GitHub release.

## One-time setup (needs the repository owner)

1. **PyPI** is optional and off; [Publishing to PyPI](#publishing-to-pypi-optional) says how to
   turn it on.
2. **The `pypi` environment** exists (GitHub made it when v0.1.0's job first ran). Add required
   reviewers to it (Settings → Environments) if a release should wait for a person, and restrict it
   to tags `v*` (Deployment branches and tags) before turning PyPI on.
3. **The repository is public** (since 2026-11-18; the history was checked that day: no token,
   password, private key, database URL, local path or real e-mail address in any commit or branch,
   only the noreply addresses of the committing accounts). That is what lets the image job add a
   GitHub artifact attestation (v0.1.0's image has one), the action upload SARIF to code scanning,
   and the release links and the README's demo image work for everyone. Sigstore signing writes
   the repository name, the workflow path and the commit to the **public** Rekor log either way.
   The `ghcr.io/jtopaz1/aiterprise-scan` package is public too: `published` pulls it without
   signing in every week.
4. **Still to switch on** (Settings, by the owner):
   - *Private vulnerability reporting* (Security): `SECURITY.md` and the issue chooser's "Report a
     vulnerability" link send reporters there, and neither can take a report until it is on;
   - *Secret scanning* and *Push protection*. `tests/test_mcp.py` holds a made-up `sk-proj-` key and
     `tests/test_secrets.py` AWS's documented example key, both to test redaction; close an alert on
     either as *used in tests*;
   - the repository's description and topics (the About box), which search and the GitHub topic
     pages use.

## Each release

1. Set `__version__` in `src/aiterprise_scan/__init__.py`, the two `version` fields in `server.json`,
   and the pins the docs tell people to use, in `README.md` and `docs/` (tests fail if any of them
   differ): `action@vX.Y.Z`, the pre-commit `rev: vX.Y.Z`, `git+…@vX.Y.Z`, the image tag `:X.Y.Z`,
   the `releases/tag/vX.Y.Z` links, the tag in the `cosign verify-blob` example, and the wheel URL
   that the GitLab template installs (`AIBOM_INSTALL`).
2. Add the release's section to `CHANGELOG.md`, newest first: `## X.Y.Z — YYYY-MM-DD`, then what
   changed for someone who runs the scanner. It becomes the GitHub release's notes
   (`tools/release_notes.py`); a test fails while `__version__` has no section, and so does the
   `github-release` job. Its links must be absolute: a release page resolves no relative link.
3. Run the checks listed under *Reproduce* in `docs/STATUS.md`.
4. Tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`. The `dist` job refuses a tag that does not
   match `__version__`.
5. Once the release run is done, run the `published` workflow by hand (it also runs weekly). It
   installs everything the docs offer from where it was published and holds each to the killer
   demo: pip from the git tag (Linux, macOS, Windows, on the Python floor), the six binaries
   downloaded from the release after every file of it matched `SHA256SUMS` and its Sigstore
   signature, the ghcr.io image and `latest` pulled without signing in (and the image's build
   attestation verified), the Action and the pre-commit hook at the tag, the GitLab template with
   the install it ships, and PyPI when `PUBLISH_TO_PYPI` is on (then a version missing from PyPI
   fails).

## What is checked before anything is uploaded

The `dist` job, before the wheel and sdist go anywhere (every pull request runs the same, without
`--release`):

- `twine check --strict`: the metadata and the README render as PyPI will render them;
- `tools/check_dist.py dist --release`: exactly one wheel and one sdist of `__version__`; the sdist holds
  the package, its metadata and the licence files only (no tests: they plant malicious samples on
  purpose and cannot run without their fixtures), the wheel the package and its `.dist-info` only, no
  compiled files; both carry every module and every declared data file; the description does not say
  "Not released yet";
- the wheel installed into a clean virtual environment, `defs status` and the killer demo.

## Cannot be undone

- A version uploaded to PyPI can be yanked but its number can never be reused.
- Rekor entries are permanent.

## Publishing to PyPI (optional)

Without PyPI, `pip install aiterprise-scan` finds nothing and the name is not reserved; everything
else works. To publish there:

1. Create a PyPI account at pypi.org (two-factor authentication is required). The name
   `aiterprise-scan` was free on 2026-11-19.
2. Under *Your account → Publishing*, add a GitHub *pending publisher*:

   | Field | Value |
   |---|---|
   | PyPI project name | `aiterprise-scan` |
   | Owner | `jtopaz1` |
   | Repository name | `aiterprise-aibom` |
   | Workflow name | `release.yml` |
   | Environment name | `pypi` |

   No token is stored anywhere; the `pypi` job proves its identity to PyPI with GitHub's OIDC token.
3. Set the repository variable `PUBLISH_TO_PYPI` to `true` (Settings → Secrets and variables →
   Actions → Variables). The next tag uploads. For v0.1.0, re-run the failed `pypi` job of run
   44243042031: that run predates the switch. Re-running it also re-runs that run's
   `github-release` job; check the release notes afterwards (`tools/release_notes.py v0.1.0`).
4. Once PyPI has the release, `published`'s `pypi` job installs it on Linux, macOS and Windows.
   Then let the docs say `pipx install aiterprise-scan` and allow it in
   `PublishedChannelsTests.test_the_docs_install_only_what_was_published`, and put the PyPI version
   and Python-versions badges in the README.

Publishing `server.json` to the MCP registry (`mcp-publisher login github`, then
`mcp-publisher publish`) needs a package the registry can check: the manifest names the PyPI
package, whose description carries `mcp-name: io.github.jtopaz1/aiterprise-scan`, so it waits for
PyPI (or for the manifest to name the ghcr.io image instead).
