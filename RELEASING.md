# Releasing `aiterprise-scan`

Pushing a tag `vX.Y.Z` runs `.github/workflows/release.yml`:

```text
dist ──────┐                      wheel + sdist, licence check, killer demo, self-SBOM
binaries ──┴─ sign ─┬─ pypi       Sigstore bundle per file, SHA256SUMS; then PyPI (trusted publishing)
                    ├─ image      ghcr.io/<owner>/aiterprise-scan with provenance and SBOM
                    └─ github-release (needs sign, pypi and image)
```

No release has been made yet. CI already runs most of it on every pull request: the wheel, the sdist,
the self-SBOM, the six binaries (Linux, macOS and Windows on x86-64 and arm64, each held to the killer demo) and the container image. The parts
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
   - the PyPI page links into the repository (its README links and the project URLs) and shows the
     demo image from it, so every link and the image are broken for everyone else until it is public.

4. **When it goes public** (Settings, all by the owner; the history was checked on 2026-11-18: no
   token, password, private key, database URL, local path or real e-mail address in any commit or
   branch, only the noreply addresses of the committing accounts):
   - turn on *Private vulnerability reporting* (Security): `SECURITY.md` sends reporters there;
   - turn on *Secret scanning* and *Push protection*. `tests/test_mcp.py` holds a made-up
     `sk-proj-` key and `tests/test_secrets.py` AWS's documented example key, both to test redaction;
     close an alert on either as *used in tests*;
   - restrict the `pypi` environment to tags `v*` (Environments → Deployment branches and tags);
   - after the first release, check that the `ghcr.io/jtopaz1/aiterprise-scan` package is public
     (Packages → Package settings) so `docker run` works without signing in.

## Each release

1. Set `__version__` in `src/aiterprise_scan/__init__.py`, the two `version` fields in `server.json`,
   and the pins the docs tell people to use: `action@vX.Y.Z` and the pre-commit `rev: vX.Y.Z` in
   `README.md`, `docs/quickstart.md` and `docs/integrations.md` (tests fail if any of them differ).
2. For the first release, remove the "Not released yet" notes from `README.md`, `docs/index.md` and
   `docs/quickstart.md` in this same commit. The README is the PyPI description and is frozen at
   upload; the `dist` job refuses to upload one that still says it is not released.
3. Run the checks listed under *Reproduce* in `docs/STATUS.md`.
4. Tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`. The `dist` job refuses a tag that does not
   match `__version__`.

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

## After the first PyPI release

Publish `server.json` to the MCP registry (`mcp-publisher login github`, then `mcp-publisher publish`).
The registry checks that the PyPI description carries `mcp-name: io.github.jtopaz1/aiterprise-scan`,
which the README already does, so this cannot happen before the PyPI upload.
