# Releasing `aiterprise-scan`

Pushing a tag `vX.Y.Z` runs `.github/workflows/release.yml`:

```text
dist ──────┐                      wheel + sdist, licence check, killer demo, self-SBOM
binaries ──┴─ sign ─┬─ pypi       Sigstore bundle per file, SHA256SUMS; then PyPI (trusted publishing)
                    ├─ image      ghcr.io/<owner>/aiterprise-scan with provenance and SBOM
                    └─ github-release (needs sign, pypi and image)
```

No release has been made yet. CI already runs most of it on every pull request: the wheel, the sdist,
the self-SBOM, the three binaries (each held to the killer demo) and the container image. The parts
that only a real tag exercises are signing, the PyPI upload, the ghcr.io push and the GitHub release.

## One-time setup (needs the repository owner)

1. **PyPI trusted publisher.** The name `aiterprise-scan` is free on PyPI (checked 2026-11-16). Sign in
   at pypi.org, open *Publishing*, and add a *pending publisher*:

   | Field | Value |
   |---|---|
   | PyPI project name | `aiterprise-scan` |
   | Owner | `jtopaz1` |
   | Repository name | `aiterprise-aibom` |
   | Workflow name | `release.yml` |
   | Environment name | `pypi` |

   No token is stored anywhere; the `pypi` job proves its identity to PyPI with GitHub's OIDC token.
2. **The `pypi` environment** is created by GitHub the first time the job runs. Add required reviewers
   to it (Settings → Environments) if a release should wait for a person.
3. **Decide the repository's visibility first.** While the repository is private:
   - the image job skips GitHub artifact attestation (it needs a public repository or Enterprise Cloud);
     the image still carries BuildKit provenance and an SBOM;
   - the action's SARIF upload to code scanning is not available;
   - Sigstore signing still writes the repository name, the workflow path and the commit to the
     **public** Rekor transparency log, and the sdist on PyPI is the source code. A release makes the
     code public whatever the repository setting says.

## Each release

1. Set `__version__` in `src/aiterprise_scan/__init__.py` and the two `version` fields in `server.json`
   (a test fails if they differ).
2. Run the checks listed under *Reproduce* in `docs/STATUS.md`.
3. Tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`. The `dist` job refuses a tag that does not
   match `__version__`.

## Cannot be undone

- A version uploaded to PyPI can be yanked but its number can never be reused.
- Rekor entries are permanent.

## After the first PyPI release

Publish `server.json` to the MCP registry (`mcp-publisher login github`, then `mcp-publisher publish`).
The registry checks that the PyPI description carries `mcp-name: io.github.jtopaz1/aiterprise-scan`,
which the README already does, so this cannot happen before the PyPI upload.
