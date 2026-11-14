"""Repository-native discovery: manifests, lockfiles (lockfile wins) and manifest-free imports."""

import base64
import codecs
import hashlib
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from aiterprise_scan import discover
from aiterprise_scan.discover import discover_imports, discover_packages


def sri(seed: str) -> tuple[str, str]:
    digest = hashlib.sha512(seed.encode()).digest()
    return "sha512-" + base64.b64encode(digest).decode(), digest.hex()


SHA_A = "a" * 64
SHA_B = "b" * 64


class Repo:
    """A throwaway repository on disk."""

    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name).resolve()
        self.root = self.base / "repo"
        self.root.mkdir()

    def close(self) -> None:
        self._tmp.cleanup()

    def write(self, rel: str, content: str, *, raw: bytes | None = None, dedent: bool = True) -> Path:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if raw is None:
            text = textwrap.dedent(content).lstrip("\n") if dedent else content
            raw = text.encode("utf-8")
        path.write_bytes(raw)
        return path

    def files(self) -> list[Path]:
        return sorted(p for p in self.root.rglob("*") if p.is_file())

    def packages(self):
        return discover_packages(self.root, self.files())

    def imports(self):
        return discover_imports(self.root, self.files())


def pick(comps, name, ecosystem=None, version=...):
    hits = [c for c in comps if c.name == name and (ecosystem is None or c.ecosystem == ecosystem)
            and (version is ... or c.version == version)]
    if len(hits) != 1:
        raise AssertionError(f"expected exactly one {name} ({ecosystem}, {version}); got {[c.to_dict() for c in hits]}")
    return hits[0]


def locs(comp):
    return [str(l) for l in comp.locations]


class RepoTest(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.repo = Repo()

    def tearDown(self) -> None:
        self.repo.close()


# ------------------------------------------------------------------------------------------------
# Python manifests
# ------------------------------------------------------------------------------------------------


class RequirementsTests(RepoTest):
    def test_forms_versions_and_lines(self):
        self.repo.write("requirements.txt", f"""
            # demo requirements
            openai==1.3.0            # pinned
            anthropic>=0.7,<1
            transformers[torch,sentencepiece]==4.44.0 ; python_version >= "3.9"
            torch===2.1.0
            langchain==0.1.*
            -e ./local/pkg
            --index-url https://example.invalid/simple
            requests ~= 2.31
            litellm @ git+https://github.com/BerriAI/litellm.git@v1.0 ; sys_platform != "win32"
            git+https://github.com/guardrails-ai/guardrails.git@main#egg=guardrails-ai
            ./vendor/localpkg
            numpy \\
                --hash=sha256:{SHA_A.upper()} \\
                --hash=sha256:{SHA_B}
            chromadb
            this is not a requirement
            """)
        comps = self.repo.packages()
        openai = pick(comps, "openai")
        self.assertEqual((openai.version, openai.version_spec, locs(openai)), ("1.3.0", None, ["requirements.txt:2"]))
        self.assertEqual(openai.source, "manifest")
        self.assertTrue(openai.ai)
        self.assertEqual(openai.properties["ai_category"], "llm-client")
        self.assertIs(openai.properties["direct"], True)

        anthropic = pick(comps, "anthropic")
        self.assertIsNone(anthropic.version)
        self.assertEqual(anthropic.version_spec, ">=0.7,<1")

        tf = pick(comps, "transformers")
        self.assertEqual(tf.version, "4.44.0")
        self.assertEqual(tf.properties["extras"], ["torch", "sentencepiece"])
        self.assertEqual(tf.properties["markers"], 'python_version >= "3.9"')
        self.assertEqual(locs(tf), ["requirements.txt:4"])

        self.assertEqual(pick(comps, "torch").version, "2.1.0")
        lc = pick(comps, "langchain")
        self.assertIsNone(lc.version)  # ==0.1.* is a range
        self.assertEqual(lc.version_spec, "==0.1.*")
        self.assertEqual(pick(comps, "requests").version_spec, "~=2.31")
        self.assertFalse(pick(comps, "requests").ai)

        litellm = pick(comps, "litellm")
        self.assertIsNone(litellm.version)
        self.assertEqual(litellm.properties["url"], "git+https://github.com/BerriAI/litellm.git@v1.0")
        self.assertEqual(litellm.properties["markers"], 'sys_platform != "win32"')
        guard = pick(comps, "guardrails-ai")
        self.assertTrue(guard.properties["url"].startswith("git+https://github.com/guardrails-ai/"))
        self.assertEqual(guard.properties["ai_category"], "guardrail")
        self.assertNotIn("name_inferred", guard.properties)

        numpy = pick(comps, "numpy")
        self.assertEqual(numpy.hashes, {"sha256": SHA_A})
        self.assertEqual(locs(numpy), ["requirements.txt:13"])
        chroma = pick(comps, "chromadb")
        self.assertIsNone(chroma.version)
        self.assertIsNone(chroma.version_spec)
        self.assertEqual(locs(chroma), ["requirements.txt:16"])

        names = {c.name for c in comps}
        self.assertFalse(names & {"local", "pkg", "localpkg", "this"})
        self.assertEqual(len(comps), 10)

    def test_vcs_url_without_egg_infers_name(self):
        self.repo.write("requirements.txt", "git+https://github.com/org/my-tool.git@v2\n")
        comp = pick(self.repo.packages(), "my-tool")
        self.assertTrue(comp.properties["name_inferred"])
        self.assertIsNone(comp.version)

    def test_includes_are_relative_and_confined_to_root(self):
        (self.repo.base / "outside.txt").write_text("evilpkg==1.0\n", encoding="utf-8")
        self.repo.write("requirements.txt", """
            -r deps/base.txt
            --requirement=requirements.txt
            -r ../outside.txt
            openai==1.3.0
            """)
        self.repo.write("deps/base.txt", "anthropic==0.7.0\n-r ../requirements.txt\n-r nested.txt\n")
        self.repo.write("deps/nested.txt", "langchain>=0.1\n")
        comps = self.repo.packages()
        self.assertEqual(sorted(c.name for c in comps), ["anthropic", "langchain", "openai"])
        self.assertEqual(locs(pick(comps, "anthropic")), ["deps/base.txt:1"])
        self.assertEqual(locs(pick(comps, "langchain")), ["deps/nested.txt:1"])

    def test_utf16_le_with_bom(self):
        text = "openai==1.3.0\r\n# comment\r\nanthropic>=0.7\r\n"
        self.repo.write("requirements.txt", "", raw=codecs.BOM_UTF16_LE + text.encode("utf-16-le"))
        comps = self.repo.packages()
        self.assertEqual(locs(pick(comps, "openai", version="1.3.0")), ["requirements.txt:1"])
        self.assertEqual(pick(comps, "anthropic").version_spec, ">=0.7")
        self.assertEqual(locs(pick(comps, "anthropic")), ["requirements.txt:3"])

    def test_dev_files_and_requirements_dir(self):
        self.repo.write("requirements-dev.txt", "pytest==7.4.0\n")
        self.repo.write("requirements/test.txt", "hypothesis>=6\n")
        self.repo.write("requirements/prod.txt", "openai==1.3.0\n")
        self.repo.write("MANIFEST.in", "include README.md\n")
        comps = self.repo.packages()
        self.assertTrue(pick(comps, "pytest").properties["dev"])
        self.assertTrue(pick(comps, "hypothesis").properties["dev"])
        self.assertNotIn("dev", pick(comps, "openai").properties)
        self.assertEqual(len(comps), 3)

    def test_pip_compile_output_is_a_lockfile_and_wins(self):
        self.repo.write("requirements.in", "openai>=1.0\nlangchain\n")
        self.repo.write("requirements.txt", f"""
            #
            # This file is autogenerated by pip-compile with Python 3.11
            # by the following command:
            #
            #    pip-compile --generate-hashes requirements.in
            #
            anyio==4.0.0 \\
                --hash=sha256:{SHA_A}
                # via
                #   httpx
                #   openai
            openai==1.3.0 \\
                --hash=sha256:{SHA_B}
                # via -r requirements.in
            """)
        comps = self.repo.packages()
        openai = pick(comps, "openai")
        self.assertEqual(openai.version, "1.3.0")
        self.assertEqual(openai.source, "lockfile")
        self.assertEqual(locs(openai), ["requirements.txt:12", "requirements.in:1"])
        self.assertIs(openai.properties["direct"], True)
        self.assertEqual(openai.properties["declared_spec"], ">=1.0")
        self.assertEqual(openai.hashes, {"sha256": SHA_B})
        anyio = pick(comps, "anyio")
        self.assertIs(anyio.properties["direct"], False)
        self.assertEqual(anyio.source, "lockfile")
        langchain = pick(comps, "langchain")  # declared but not locked: no version is invented
        self.assertEqual((langchain.version, langchain.source), (None, "manifest"))


class PyprojectTests(RepoTest):
    def test_pep621_optional_and_dependency_groups(self):
        self.repo.write("pyproject.toml", """
            [build-system]
            requires = ["setuptools>=69"]

            [project]
            name = "demo"
            version = "0.1.0"
            dependencies = [
                "openai>=1.3",
                'anthropic==0.7.0',
                "transformers[torch]==4.44.0; python_version >= '3.9'",
            ]

            [project.optional-dependencies]
            dev = ["pytest>=7"]
            rag = ["chromadb~=0.4"]

            [dependency-groups]
            lint = ["ruff==0.1.0"]
            """)
        comps = self.repo.packages()
        openai = pick(comps, "openai")
        self.assertEqual((openai.version, openai.version_spec, locs(openai)), (None, ">=1.3", ["pyproject.toml:8"]))
        self.assertEqual(pick(comps, "anthropic").version, "0.7.0")
        self.assertEqual(locs(pick(comps, "anthropic")), ["pyproject.toml:9"])
        tf = pick(comps, "transformers")
        self.assertEqual((tf.version, tf.properties["extras"]), ("4.44.0", ["torch"]))
        pytest = pick(comps, "pytest")
        self.assertTrue(pytest.properties["dev"])
        self.assertEqual(locs(pytest), ["pyproject.toml:14"])
        chroma = pick(comps, "chromadb")
        self.assertNotIn("dev", chroma.properties)
        self.assertEqual((chroma.properties["extra"], chroma.properties["optional"]), ("rag", True))
        self.assertEqual(chroma.properties["ai_category"], "vector-store")
        ruff = pick(comps, "ruff")
        self.assertTrue(ruff.properties["dev"])
        self.assertEqual(ruff.version, "0.1.0")
        self.assertNotIn("setuptools", {c.name for c in comps})  # build requirements are not runtime deps

    def test_poetry(self):
        self.repo.write("pyproject.toml", """
            [tool.poetry]
            name = "demo"

            [tool.poetry.dependencies]
            python = "^3.11"
            openai = "^1.3.0"
            langchain = "0.1.0"
            transformers = { version = "4.44.0", extras = ["torch"] }
            mylib = { path = "../mylib", develop = true }
            guardrails-ai = { git = "https://github.com/guardrails-ai/guardrails.git", tag = "v0.4.0" }
            "llama-index" = [
                { version = "^0.9", python = "<3.12" },
                { version = "^0.10", python = ">=3.12" },
            ]

            [tool.poetry.group.dev.dependencies]
            pytest = "^7.4"

            [tool.poetry.dependencies.litellm]
            version = "1.40.0"
            """)
        comps = self.repo.packages()
        names = {c.name for c in comps}
        self.assertNotIn("python", names)
        self.assertNotIn("mylib", names)
        openai = pick(comps, "openai")
        self.assertEqual((openai.version, openai.version_spec, locs(openai)), (None, "^1.3.0", ["pyproject.toml:6"]))
        self.assertEqual(pick(comps, "langchain").version, "0.1.0")  # a bare Poetry version is exact
        tf = pick(comps, "transformers")
        self.assertEqual((tf.version, tf.properties["extras"], locs(tf)), ("4.44.0", ["torch"], ["pyproject.toml:8"]))
        guard = pick(comps, "guardrails-ai")
        self.assertEqual(guard.properties["url"], "https://github.com/guardrails-ai/guardrails.git@v0.4.0")
        llama = pick(comps, "llama-index")
        self.assertIsNone(llama.version)
        self.assertEqual(llama.version_spec, "^0.9 || ^0.10")
        self.assertEqual(locs(llama), ["pyproject.toml:11"])
        pytest = pick(comps, "pytest")
        self.assertEqual((pytest.properties["dev"], pytest.properties["group"]), (True, "dev"))
        self.assertEqual(locs(pytest), ["pyproject.toml:17"])
        litellm = pick(comps, "litellm")
        self.assertEqual((litellm.version, locs(litellm)), ("1.40.0", ["pyproject.toml:19"]))


class PipfileTests(RepoTest):
    def test_pipfile(self):
        self.repo.write("Pipfile", """
            [[source]]
            url = "https://pypi.org/simple"
            verify_ssl = true
            name = "pypi"

            [packages]
            openai = "==1.3.0"
            anthropic = "*"
            transformers = {version = ">=4.40", extras = ["torch"]}
            myproj = {path = ".", editable = true}

            [dev-packages]
            pytest = "*"

            [requires]
            python_version = "3.11"

            [scripts]
            start = "python app.py"
            """)
        comps = self.repo.packages()
        self.assertEqual(sorted(c.name for c in comps), ["anthropic", "openai", "pytest", "transformers"])
        openai = pick(comps, "openai")
        self.assertEqual((openai.version, locs(openai)), ("1.3.0", ["Pipfile:7"]))
        self.assertEqual((pick(comps, "anthropic").version, pick(comps, "anthropic").version_spec), (None, "*"))
        self.assertEqual(pick(comps, "transformers").version_spec, ">=4.40")
        self.assertTrue(pick(comps, "pytest").properties["dev"])


# ------------------------------------------------------------------------------------------------
# Python lockfiles
# ------------------------------------------------------------------------------------------------


class PythonLockTests(RepoTest):
    def test_poetry_lock_wins_over_pyproject(self):
        self.repo.write("pyproject.toml", """
            [tool.poetry.dependencies]
            python = "^3.11"
            openai = "^1.3"
            not-locked-yet = "^2.0"

            [tool.poetry.group.dev.dependencies]
            pytest = "^7.4"
            """)
        self.repo.write("poetry.lock", f"""
            # This file is automatically @generated by Poetry 1.7.0 and should not be changed by hand.

            [[package]]
            name = "anyio"
            version = "4.0.0"
            description = "High level compatibility layer"
            optional = false
            python-versions = ">=3.8"
            files = [
                {{file = "anyio-4.0.0-py3-none-any.whl", hash = "sha256:{SHA_A}"}},
            ]

            [[package]]
            name = "openai"
            version = "1.3.5"
            description = "The official Python library for the openai API"
            optional = false
            python-versions = ">=3.7.1"
            files = []

            [package.dependencies]
            anyio = ">=3.5.0,<5"

            [[package]]
            name = "pytest"
            version = "7.4.0"
            description = "pytest"
            category = "dev"
            optional = false
            python-versions = ">=3.7"
            files = []

            [metadata]
            lock-version = "2.0"
            python-versions = "^3.11"
            content-hash = "abc"
            """)
        comps = self.repo.packages()
        openai = pick(comps, "openai")
        self.assertEqual((openai.version, openai.version_spec, openai.source), ("1.3.5", None, "lockfile"))
        self.assertEqual(locs(openai), ["poetry.lock:14", "pyproject.toml:3"])
        self.assertIs(openai.properties["direct"], True)
        self.assertEqual(openai.properties["declared_spec"], "^1.3")
        anyio = pick(comps, "anyio")
        self.assertEqual(anyio.hashes, {"sha256": SHA_A})
        self.assertIs(anyio.properties["direct"], False)
        pytest = pick(comps, "pytest")
        self.assertTrue(pytest.properties["dev"])
        self.assertIs(pytest.properties["direct"], True)
        later = pick(comps, "not-locked-yet")
        self.assertEqual((later.version, later.version_spec, later.source), (None, "^2.0", "manifest"))
        self.assertEqual(len(comps), 4)

    def test_uv_lock_direct_dev_and_hashes(self):
        self.repo.write("uv.lock", f"""
            version = 1
            requires-python = ">=3.11"

            [[package]]
            name = "anyio"
            version = "4.4.0"
            source = {{ registry = "https://pypi.org/simple" }}
            sdist = {{ url = "https://files.example/anyio-4.4.0.tar.gz", hash = "sha256:{SHA_A}", size = 1 }}

            [[package]]
            name = "demo"
            version = "0.1.0"
            source = {{ editable = "." }}
            dependencies = [
                {{ name = "openai" }},
            ]

            [package.dev-dependencies]
            dev = [
                {{ name = "pytest" }},
            ]

            [[package]]
            name = "iniconfig"
            version = "2.0.0"
            source = {{ registry = "https://pypi.org/simple" }}
            wheels = [
                {{ url = "https://files.example/iniconfig-2.0.0-py3-none-any.whl", hash = "sha256:{SHA_B}", size = 1 }},
            ]

            [[package]]
            name = "openai"
            version = "1.40.0"
            source = {{ registry = "https://pypi.org/simple" }}
            dependencies = [
                {{ name = "anyio" }},
            ]

            [[package]]
            name = "pytest"
            version = "8.2.0"
            source = {{ registry = "https://pypi.org/simple" }}
            dependencies = [
                {{ name = "iniconfig" }},
            ]
            """)
        comps = self.repo.packages()
        self.assertNotIn("demo", {c.name for c in comps})  # the project itself
        openai = pick(comps, "openai")
        self.assertEqual((openai.version, openai.properties["direct"], locs(openai)), ("1.40.0", True, ["uv.lock:32"]))
        self.assertNotIn("dev", openai.properties)
        anyio = pick(comps, "anyio")
        self.assertEqual((anyio.properties["direct"], anyio.hashes), (False, {"sha256": SHA_A}))
        self.assertNotIn("dev", anyio.properties)
        pytest = pick(comps, "pytest")
        self.assertEqual((pytest.properties["direct"], pytest.properties["dev"]), (True, True))
        iniconfig = pick(comps, "iniconfig")
        self.assertEqual((iniconfig.properties["direct"], iniconfig.properties["dev"]), (False, True))
        self.assertEqual(iniconfig.hashes, {"sha256": SHA_B})

    def test_pipfile_lock(self):
        self.repo.write("Pipfile.lock", f"""
            {{
                "_meta": {{"hash": {{"sha256": "x"}}, "pipfile-spec": 6, "requires": {{}}, "sources": []}},
                "default": {{
                    "openai": {{
                        "hashes": ["sha256:{SHA_A}", "sha256:{SHA_B}"],
                        "index": "pypi",
                        "markers": "python_full_version >= '3.7.1'",
                        "version": "==1.3.0"
                    }},
                    "myproj": {{"editable": true, "path": "."}}
                }},
                "develop": {{
                    "pytest": {{"hashes": [], "version": "==7.4.0"}}
                }}
            }}
            """)
        comps = self.repo.packages()
        self.assertEqual(sorted(c.name for c in comps), ["openai", "pytest"])
        openai = pick(comps, "openai")
        self.assertEqual((openai.version, openai.source, locs(openai)), ("1.3.0", "lockfile", ["Pipfile.lock:4"]))
        self.assertEqual(openai.hashes, {"sha256": SHA_A})
        pytest = pick(comps, "pytest")
        self.assertEqual((pytest.version, pytest.properties["dev"], locs(pytest)), ("7.4.0", True, ["Pipfile.lock:13"]))

    def test_pipfile_lock_wins_over_pipfile(self):
        self.repo.write("Pipfile", '[packages]\nopenai = ">=1.0"\n')
        self.repo.write("Pipfile.lock", '{"default": {"openai": {"version": "==1.3.0"}}, "develop": {}}')
        openai = pick(self.repo.packages(), "openai")
        self.assertEqual((openai.version, locs(openai)), ("1.3.0", ["Pipfile.lock:1", "Pipfile:2"]))


class CondaTests(RepoTest):
    def test_environment_yml(self):
        self.repo.write("environment.yml", """
            name: ml
            channels:
              - conda-forge
            dependencies:
              - python=3.11
              - pytorch::pytorch=2.1.0
              - numpy==1.26.0
              - scikit-learn=1.3.2=py311hc009520_0
              - faiss-cpu>=1.7   # vector search
              - transformers 4.44.0
              - pip
              - pip:
                - openai==1.3.0
                - "anthropic>=0.7"
                - -r requirements-extra.txt
            """)
        self.repo.write("requirements-extra.txt", "langchain==0.1.0\n")
        comps = self.repo.packages()
        torch = pick(comps, "pytorch", "conda")
        self.assertEqual((torch.version, torch.version_spec), (None, "=2.1.0"))  # conda `=` is fuzzy
        self.assertTrue(torch.ai)
        self.assertEqual(torch.properties["ai_category"], "ml-framework")
        self.assertEqual((torch.properties["channel"], torch.properties["pypi_name"]), ("pytorch", "torch"))
        self.assertEqual(locs(torch), ["environment.yml:6"])
        self.assertEqual(pick(comps, "numpy", "conda").version, "1.26.0")
        sk = pick(comps, "scikit-learn", "conda")
        self.assertEqual((sk.version, sk.properties["build"]), ("1.3.2", "py311hc009520_0"))
        self.assertTrue(sk.ai)
        faiss = pick(comps, "faiss-cpu", "conda")
        self.assertEqual((faiss.version, faiss.version_spec, locs(faiss)), (None, ">=1.7", ["environment.yml:9"]))
        self.assertEqual(pick(comps, "transformers", "conda").version, "4.44.0")
        self.assertEqual(pick(comps, "python", "conda").version_spec, "=3.11")
        openai = pick(comps, "openai", "pypi")
        self.assertEqual((openai.version, locs(openai)), ("1.3.0", ["environment.yml:13"]))
        anthropic = pick(comps, "anthropic", "pypi")
        self.assertEqual((anthropic.version_spec, locs(anthropic)), (">=0.7", ["environment.yml:14"]))
        self.assertEqual(locs(pick(comps, "langchain", "pypi")), ["requirements-extra.txt:1"])


# ------------------------------------------------------------------------------------------------
# npm
# ------------------------------------------------------------------------------------------------


class PackageJsonTests(RepoTest):
    def test_manifest_forms(self):
        self.repo.write("package.json", """
            {
              "name": "demo",
              "version": "1.0.0",
              "dependencies": {
                "openai": "4.20.0",
                "@anthropic-ai/sdk": "^0.9.0",
                "ai": "latest",
                "my-openai": "npm:openai@4.19.0",
                "langchain": "github:langchain-ai/langchainjs#main",
                "local-lib": "file:../local-lib",
                "ws-lib": "workspace:*",
                "pinned-eq": "=1.2.3",
                "range-x": "1.x"
              },
              "devDependencies": {
                "@langchain/core": "~0.1.0",
                "typescript": "5.2.2"
              },
              "peerDependencies": {
                "openai": ">=4"
              }
            }
            """)
        comps = self.repo.packages()
        openai = pick(comps, "openai", version="4.20.0")
        self.assertEqual((openai.version_spec, locs(openai), openai.source), (None, ["package.json:5"], "manifest"))
        sdk = pick(comps, "@anthropic-ai/sdk")
        self.assertEqual((sdk.version, sdk.version_spec, locs(sdk)), (None, "^0.9.0", ["package.json:6"]))
        self.assertEqual(sdk.purl, "pkg:npm/%40anthropic-ai/sdk")
        self.assertTrue(sdk.ai)
        self.assertEqual(pick(comps, "ai").version_spec, "latest")
        alias = pick(comps, "openai", version="4.19.0")
        self.assertEqual((alias.properties["alias"], locs(alias)), ("my-openai", ["package.json:8"]))
        langchain = pick(comps, "langchain")
        self.assertEqual((langchain.version, langchain.properties["url"]), (None, "github:langchain-ai/langchainjs#main"))
        self.assertEqual(pick(comps, "pinned-eq").version, "1.2.3")
        self.assertEqual((pick(comps, "range-x").version, pick(comps, "range-x").version_spec), (None, "1.x"))
        core = pick(comps, "@langchain/core")
        self.assertEqual((core.version_spec, core.properties["dev"], locs(core)), ("~0.1.0", True, ["package.json:16"]))
        self.assertEqual(pick(comps, "typescript").version, "5.2.2")
        peer = pick(comps, "openai", version=None)
        self.assertEqual((peer.version_spec, peer.properties["peer"]), (">=4", True))
        names = {c.name for c in comps}
        self.assertFalse(names & {"local-lib", "ws-lib", "my-openai"})


class NpmLockTests(RepoTest):
    def test_package_lock_v1_nested(self):
        sri_openai, hex_openai = sri("openai")
        self.repo.write("package-lock.json", """
            {
              "name": "demo",
              "version": "1.0.0",
              "lockfileVersion": 1,
              "requires": true,
              "dependencies": {
                "openai": {
                  "version": "4.20.0",
                  "resolved": "https://registry.npmjs.org/openai/-/openai-4.20.0.tgz",
                  "integrity": "@@SRI@@",
                  "requires": {
                    "node-fetch": "^2.6.7"
                  },
                  "dependencies": {
                    "node-fetch": {
                      "version": "2.6.7",
                      "resolved": "https://registry.npmjs.org/node-fetch/-/node-fetch-2.6.7.tgz"
                    }
                  }
                },
                "node-fetch": {
                  "version": "3.3.2",
                  "dev": true
                },
                "string-width-cjs": {
                  "version": "npm:string-width@4.2.3"
                },
                "local": {
                  "version": "file:../local"
                }
              }
            }
            """.replace("@@SRI@@", sri_openai))
        comps = self.repo.packages()
        openai = pick(comps, "openai")
        self.assertEqual((openai.version, openai.source, locs(openai)), ("4.20.0", "lockfile", ["package-lock.json:7"]))
        self.assertEqual(openai.hashes, {"sha512": hex_openai})
        self.assertEqual(openai.properties["integrity"], sri_openai)
        self.assertNotIn("direct", openai.properties)  # v1 does not record it and no package.json here
        nested = pick(comps, "node-fetch", version="2.6.7")
        self.assertEqual(locs(nested), ["package-lock.json:15"])
        top = pick(comps, "node-fetch", version="3.3.2")
        self.assertEqual((locs(top), top.properties["dev"]), (["package-lock.json:21"], True))
        alias = pick(comps, "string-width")
        self.assertEqual((alias.version, alias.properties["alias"]), ("4.2.3", "string-width-cjs"))
        self.assertNotIn("local", {c.name for c in comps})

    def test_package_lock_v3_wins_over_package_json(self):
        sri_sdk, hex_sdk = sri("sdk")
        self.repo.write("package.json", """
            {
              "name": "demo",
              "dependencies": {
                "@anthropic-ai/sdk": "^0.9.0",
                "openai": "^4.20.0",
                "not-installed": "^1.0.0"
              },
              "devDependencies": {
                "typescript": "^5.2.0"
              }
            }
            """)
        self.repo.write("package-lock.json", """
            {
              "name": "demo",
              "lockfileVersion": 3,
              "requires": true,
              "packages": {
                "": {
                  "name": "demo",
                  "dependencies": {"@anthropic-ai/sdk": "^0.9.0", "openai": "^4.20.0"},
                  "devDependencies": {"typescript": "^5.2.0"}
                },
                "node_modules/@anthropic-ai/sdk": {
                  "version": "0.9.1",
                  "resolved": "https://registry.npmjs.org/@anthropic-ai/sdk/-/sdk-0.9.1.tgz",
                  "integrity": "@@SRI@@"
                },
                "node_modules/openai": {
                  "version": "4.20.1"
                },
                "node_modules/openai/node_modules/@types/node": {
                  "version": "18.19.0"
                },
                "node_modules/typescript": {
                  "version": "5.2.2",
                  "dev": true
                },
                "node_modules/agentkeepalive": {
                  "version": "4.5.0"
                },
                "node_modules/mylink": {
                  "resolved": "packages/mylink",
                  "link": true
                }
              }
            }
            """.replace("@@SRI@@", sri_sdk))
        comps = self.repo.packages()
        self.assertNotIn("demo", {c.name for c in comps})
        self.assertNotIn("mylink", {c.name for c in comps})
        sdk = pick(comps, "@anthropic-ai/sdk")
        self.assertEqual((sdk.version, sdk.version_spec, sdk.source), ("0.9.1", None, "lockfile"))
        self.assertEqual(locs(sdk), ["package-lock.json:11", "package.json:4"])
        self.assertEqual(sdk.hashes, {"sha512": hex_sdk})
        self.assertEqual((sdk.properties["direct"], sdk.properties["declared_spec"]), (True, "^0.9.0"))
        self.assertEqual(sdk.purl, "pkg:npm/%40anthropic-ai/sdk@0.9.1")
        openai = pick(comps, "openai")
        self.assertEqual((openai.version, locs(openai)), ("4.20.1", ["package-lock.json:16", "package.json:5"]))
        types = pick(comps, "@types/node")
        self.assertEqual((types.version, types.properties["direct"], locs(types)), ("18.19.0", False, ["package-lock.json:19"]))
        ts = pick(comps, "typescript")
        self.assertEqual((ts.version, ts.properties["dev"], ts.properties["direct"]), ("5.2.2", True, True))
        self.assertIs(pick(comps, "agentkeepalive").properties["direct"], False)
        missing = pick(comps, "not-installed")
        self.assertEqual((missing.version, missing.version_spec, missing.source), (None, "^1.0.0", "manifest"))

    def test_pnpm_v5(self):
        self.repo.write("pnpm-lock.yaml", """
            lockfileVersion: 5.4

            specifiers:
              openai: ^4.20.0
              '@types/node': ^18.0.0

            dependencies:
              openai: 4.20.0

            devDependencies:
              '@types/node': 18.19.0

            packages:

              /openai/4.20.0:
                resolution: {integrity: sha512-AAAA}
                dependencies:
                  some-peer: 1.0.0_react@18.2.0
                dev: false

              /@types/node/18.19.0:
                resolution: {integrity: sha512-BBBB}
                dev: true

              /some-peer/1.0.0_react@18.2.0:
                resolution: {integrity: sha512-CCCC}
                dev: false
            """)
        comps = self.repo.packages()
        openai = pick(comps, "openai")
        self.assertEqual((openai.version, openai.properties["direct"], locs(openai)), ("4.20.0", True, ["pnpm-lock.yaml:15"]))
        self.assertNotIn("dev", openai.properties)
        types = pick(comps, "@types/node")
        self.assertEqual((types.version, types.properties["dev"], types.properties["direct"]), ("18.19.0", True, True))
        peer = pick(comps, "some-peer")
        self.assertEqual((peer.version, peer.properties["direct"], locs(peer)), ("1.0.0", False, ["pnpm-lock.yaml:25"]))

    def test_pnpm_v6(self):
        self.repo.write("pnpm-lock.yaml", """
            lockfileVersion: '6.0'

            settings:
              autoInstallPeers: true
              excludeLinksFromLockfile: false

            dependencies:
              '@anthropic-ai/sdk':
                specifier: ^0.9.0
                version: 0.9.1
              react-dom:
                specifier: ^18.2.0
                version: 18.2.0(react@18.2.0)

            packages:

              /@anthropic-ai/sdk@0.9.1:
                resolution: {integrity: sha512-AAAA}
                dev: false

              /react-dom@18.2.0(react@18.2.0):
                resolution: {integrity: sha512-BBBB}
                peerDependencies:
                  react: ^18.2.0
                dev: false

              /react@18.2.0:
                resolution: {integrity: sha512-CCCC}
                dev: false
            """)
        comps = self.repo.packages()
        sdk = pick(comps, "@anthropic-ai/sdk")
        self.assertEqual((sdk.version, sdk.properties["direct"], locs(sdk)), ("0.9.1", True, ["pnpm-lock.yaml:17"]))
        self.assertTrue(sdk.ai)
        dom = pick(comps, "react-dom")
        self.assertEqual((dom.version, dom.properties["direct"], locs(dom)), ("18.2.0", True, ["pnpm-lock.yaml:21"]))
        self.assertIs(pick(comps, "react").properties["direct"], False)

    def test_pnpm_v9_with_package_json(self):
        self.repo.write("package.json", '{\n  "devDependencies": {\n    "@langchain/core": "^0.1.0"\n  },\n'
                                        '  "dependencies": {\n    "openai": "^4.20.0"\n  }\n}\n')
        self.repo.write("pnpm-lock.yaml", """
            lockfileVersion: '9.0'

            settings:
              autoInstallPeers: true
              excludeLinksFromLockfile: false

            importers:

              .:
                dependencies:
                  openai:
                    specifier: ^4.20.0
                    version: 4.20.0
                devDependencies:
                  '@langchain/core':
                    specifier: ^0.1.0
                    version: 0.1.5(openai@4.20.0)

            packages:

              '@langchain/core@0.1.5':
                resolution: {integrity: sha512-AAAA}
                engines: {node: '>=18'}

              openai@4.20.0:
                resolution: {integrity: sha512-BBBB}

              zod@3.22.4:
                resolution: {integrity: sha512-CCCC}

            snapshots:

              '@langchain/core@0.1.5(openai@4.20.0)':
                dependencies:
                  openai: 4.20.0
                  zod: 3.22.4

              openai@4.20.0: {}

              zod@3.22.4: {}
            """)
        comps = self.repo.packages()
        core = pick(comps, "@langchain/core")
        self.assertEqual((core.version, core.properties["dev"], core.properties["direct"]), ("0.1.5", True, True))
        self.assertEqual(locs(core), ["pnpm-lock.yaml:21", "package.json:3"])
        openai = pick(comps, "openai")
        self.assertEqual((openai.version, locs(openai)), ("4.20.0", ["pnpm-lock.yaml:25", "package.json:6"]))
        self.assertNotIn("dev", openai.properties)
        zod = pick(comps, "zod")
        self.assertEqual((zod.properties["direct"], locs(zod)), (False, ["pnpm-lock.yaml:28"]))

    def test_yarn_classic_descriptor_matching(self):
        sri_openai, hex_openai = sri("openai-4")
        self.repo.write("package.json", """
            {
              "dependencies": {
                "openai": "^4.20.0",
                "@anthropic-ai/sdk": "^0.9.0",
                "string-width-cjs": "npm:string-width@^4.2.0"
              }
            }
            """)
        self.repo.write("yarn.lock", """
            # THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
            # yarn lockfile v1


            "@anthropic-ai/sdk@^0.9.0":
              version "0.9.1"
              resolved "https://registry.yarnpkg.com/@anthropic-ai/sdk/-/sdk-0.9.1.tgz#abc"
              integrity sha512-AAAA

            openai@^3.0.0:
              version "3.3.0"
              resolved "https://registry.yarnpkg.com/openai/-/openai-3.3.0.tgz"

            openai@^4.0.0, openai@^4.20.0:
              version "4.20.1"
              resolved "https://registry.yarnpkg.com/openai/-/openai-4.20.1.tgz"
              integrity @@SRI@@
              dependencies:
                node-fetch "^2.6.7"

            "string-width-cjs@npm:string-width@^4.2.0":
              version "4.2.3"

            "local@file:../local":
              version "1.0.0"
            """.replace("@@SRI@@", sri_openai))
        comps = self.repo.packages()
        new = pick(comps, "openai", version="4.20.1")
        self.assertEqual(locs(new), ["yarn.lock:14", "package.json:3"])
        self.assertEqual((new.properties["direct"], new.hashes), (True, {"sha512": hex_openai}))
        old = pick(comps, "openai", version="3.3.0")
        self.assertEqual((locs(old), old.properties["direct"]), (["yarn.lock:10"], False))
        sdk = pick(comps, "@anthropic-ai/sdk")
        self.assertEqual((sdk.version, locs(sdk)), ("0.9.1", ["yarn.lock:5", "package.json:4"]))
        sw = pick(comps, "string-width")
        self.assertEqual((sw.version, sw.properties["alias"], sw.properties["direct"]), ("4.2.3", "string-width-cjs", True))
        self.assertNotIn("local", {c.name for c in comps})

    def test_yarn_berry(self):
        self.repo.write("yarn.lock", """
            # This file is generated by running "yarn install" inside your project.
            # Manual changes might be lost - proceed with caution!

            __metadata:
              version: 8
              cacheKey: 10c0

            "@anthropic-ai/sdk@npm:^0.9.0":
              version: 0.9.1
              resolution: "@anthropic-ai/sdk@npm:0.9.1"
              dependencies:
                node-fetch: "npm:^2.6.7"
              checksum: 10c0/abcdef
              languageName: node
              linkType: hard

            "demo@workspace:.":
              version: 0.0.0-use.local
              resolution: "demo@workspace:."
              languageName: unknown
              linkType: soft

            "openai@npm:^4.0.0, openai@npm:^4.20.0":
              version: 4.20.1
              resolution: "openai@npm:4.20.1"
              languageName: node
              linkType: hard
            """)
        self.repo.write("package.json", '{"dependencies": {"openai": "^4.20.0"}}')
        comps = self.repo.packages()
        self.assertNotIn("demo", {c.name for c in comps})
        sdk = pick(comps, "@anthropic-ai/sdk")
        self.assertEqual((sdk.version, sdk.source, locs(sdk)), ("0.9.1", "lockfile", ["yarn.lock:8"]))
        self.assertEqual(sdk.properties["yarn_checksum"], "10c0/abcdef")
        self.assertIs(sdk.properties["direct"], False)
        openai = pick(comps, "openai")
        self.assertEqual((openai.version, locs(openai)), ("4.20.1", ["yarn.lock:23", "package.json:1"]))
        self.assertEqual(openai.properties["declared_spec"], "^4.20.0")


# ------------------------------------------------------------------------------------------------
# cross-cutting rules
# ------------------------------------------------------------------------------------------------


class RuleTests(RepoTest):
    def test_ranges_are_never_exact(self):
        py_ranges = [">=1.0", "~=1.0", "==1.*", "!=1.0", "<2", ">1,<2", "==1.0,<2", ">=1.0.0"]
        npm_ranges = ["^1.2.3", "~1.2.3", "1.2", "1.x", "*", "latest", ">=1.0.0 <2.0.0", "1.2.3 - 2.0.0",
                      "^1.0.0 || ^2.0.0", ""]
        self.repo.write("py/requirements.txt", "".join(f"pkg{i}{r}\n" for i, r in enumerate(py_ranges)))
        deps = ", ".join(f'"pkg{i}": "{r}"' for i, r in enumerate(npm_ranges))
        self.repo.write("js/package.json", "{\"dependencies\": {" + deps + "}}")
        self.repo.write("poetry/pyproject.toml", '[tool.poetry.dependencies]\na = "^1.2"\nb = "~1.2"\nc = "1.*"\nd = ">=1,<2"\n')
        self.repo.write("conda/environment.yml", "dependencies:\n  - a=1.2\n  - b>=1\n  - c 1.2.*\n  - d=1.2|1.3\n")
        comps = self.repo.packages()
        self.assertEqual(len(comps), len(py_ranges) + len(npm_ranges) + 8)
        for comp in comps:
            self.assertIsNone(comp.version, comp.to_dict())
            self.assertTrue(comp.version_spec, comp.to_dict())

    def test_exact_pins_are_exact(self):
        self.repo.write("requirements.txt", "a==1.0\nb===1.0.post1\nc == 2.0\n")
        self.repo.write("package.json", '{"dependencies": {"d": "1.2.3", "e": "v1.2.3-beta.1", "f": "=2.0.0"}}')
        comps = self.repo.packages()
        self.assertEqual({c.name: c.version for c in comps},
                         {"a": "1.0", "b": "1.0.post1", "c": "2.0", "d": "1.2.3", "e": "1.2.3-beta.1", "f": "2.0.0"})

    def test_lockfile_scope_is_per_directory(self):
        self.repo.write("a/package.json", '{"dependencies": {"openai": "^4.0.0"}}')
        self.repo.write("b/package-lock.json", '{"lockfileVersion": 3, "packages": {"": {}, '
                                               '"node_modules/openai": {"version": "4.20.0"}}}')
        comps = self.repo.packages()
        self.assertEqual(sorted((c.version or "", c.version_spec or "") for c in comps), [("", "^4.0.0"), ("4.20.0", "")])

    def test_same_declaration_in_two_projects_merges(self):
        self.repo.write("svc1/requirements.txt", "openai==1.3.0\n")
        self.repo.write("svc2/requirements.txt", "pytest\nopenai==1.3.0\n")
        comps = self.repo.packages()
        openai = pick(comps, "openai")
        self.assertEqual(locs(openai), ["svc1/requirements.txt:1", "svc2/requirements.txt:2"])

    def test_malformed_files_do_not_crash(self):
        self.repo.write("bad1/package.json", '{ "dependencies": { "openai": "4.0.0", ')
        self.repo.write("bad1/package-lock.json", "not json at all")
        self.repo.write("bad2/pyproject.toml", "[project\ndependencies = [")
        self.repo.write("bad2/poetry.lock", "[[package]]\nname = ")
        self.repo.write("bad3/pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n\t/x@1.0.0:\n")
        self.repo.write("bad3/yarn.lock", "", raw=bytes(range(256)) * 4)
        self.repo.write("bad4/Pipfile.lock", "[1, 2")
        self.repo.write("bad4/uv.lock", "version = = 1")
        self.repo.write("bad4/Pipfile", "[packages\n")
        self.repo.write("bad5/environment.yml", "dependencies:\n  - a\n - b: [\n")
        self.repo.write("bad5/requirements.txt", "", raw=b"\xff\xfe\x00\x00garbage\x00")
        self.repo.write("good/requirements.txt", "openai==1.3.0\n")
        comps = self.repo.packages()
        self.assertEqual(locs(pick(comps, "openai", version="1.3.0")), ["good/requirements.txt:1"])

    def test_bad_entries_are_skipped(self):
        self.repo.write("uv.lock", 'version = 1\n\n[[package]]\nname = "openai"\nversion = "1.0.0"\n\n'
                                   '[[package]]\nname = 7\n')
        self.assertEqual([c.name for c in self.repo.packages()], ["openai"])

    def test_partial_results_survive_a_parser_error(self):
        self.repo.write("package-lock.json", '{"lockfileVersion": 3, "packages": {"": {}, '
                                             '"node_modules/openai": {"version": "4.20.0"}, '
                                             '"node_modules/ai": {"version": "3.0.0"}}}')
        self.repo.write("requirements.txt", "anthropic==0.7.0\n")
        with mock.patch.object(discover, "_sri_hashes", side_effect=[{}, RuntimeError("boom")]):
            comps = self.repo.packages()
        self.assertEqual(sorted(c.name for c in comps), ["anthropic", "openai"])

    def test_oversized_files_are_skipped(self):
        self.repo.write("requirements.txt", "openai==1.3.0\n" * 50)
        with mock.patch.object(discover, "MAX_MANIFEST_BYTES", 100):
            self.assertEqual(self.repo.packages(), [])
        self.assertEqual(len(self.repo.packages()), 1)

    def test_utf8_bom_package_json(self):
        self.repo.write("package.json", "", raw=codecs.BOM_UTF8 + b'{\n  "dependencies": {\n    "openai": "4.20.0"\n  }\n}\n')
        openai = pick(self.repo.packages(), "openai")
        self.assertEqual((openai.version, locs(openai)), ("4.20.0", ["package.json:3"]))


# ------------------------------------------------------------------------------------------------
# manifest-free discovery
# ------------------------------------------------------------------------------------------------


class ImportTests(RepoTest):
    def test_python_imports(self):
        self.repo.write("app/main.py", """
            import os
            import openai
            from google import genai
            import google.generativeai as gg
            from sklearn.linear_model import LogisticRegression
            from . import local
            from .x import y
            import requests
            from langchain_core.messages import HumanMessage
            from llama_index.core import VectorStoreIndex


            def later():
                import anthropic
                mod = importlib.import_module("litellm")
            """)
        comps = self.repo.imports()
        expected = {
            "openai": ("app/main.py:2", "openai"),
            "google-genai": ("app/main.py:3", "google.genai"),
            "google-generativeai": ("app/main.py:4", "google.generativeai"),
            "scikit-learn": ("app/main.py:5", "sklearn"),
            "langchain-core": ("app/main.py:9", "langchain_core"),
            "llama-index-core": ("app/main.py:10", "llama_index.core"),
            "anthropic": ("app/main.py:14", "anthropic"),
            "litellm": ("app/main.py:15", "litellm"),
        }
        self.assertEqual({c.name: (locs(c)[0], c.properties["import"]) for c in comps}, expected)
        for comp in comps:
            self.assertEqual((comp.ecosystem, comp.source, comp.version, comp.ai), ("pypi", "import", None, True))
            self.assertIs(comp.properties["direct"], True)
            self.assertTrue(comp.properties["ai_category"])

    def test_python_syntax_error_falls_back_to_regex(self):
        self.repo.write("legacy.py", 'print "python 2"\nimport anthropic, os\nfrom transformers import AutoModel\n')
        comps = self.repo.imports()
        self.assertEqual({c.name: locs(c) for c in comps},
                         {"anthropic": ["legacy.py:2"], "transformers": ["legacy.py:3"]})

    def test_imports_merge_across_files(self):
        self.repo.write("a.py", "import openai\nimport openai.types\n")
        self.repo.write("b/c.py", "\n\nfrom openai import OpenAI\n", dedent=False)
        openai = pick(self.repo.imports(), "openai")
        self.assertEqual(locs(openai), ["a.py:1", "b/c.py:3"])

    def test_notebook(self):
        self.repo.write("nb/explore.ipynb", """
            {
             "cells": [
              {
               "cell_type": "markdown",
               "metadata": {},
               "source": ["import tensorflow\\n"]
              },
              {
               "cell_type": "code",
               "execution_count": 1,
               "metadata": {},
               "outputs": [],
               "source": [
                "%pip install openai\\n",
                "!nvidia-smi\\n",
                "import torch\\n",
                "from transformers import pipeline\\n",
                "pipeline?"
               ]
              },
              {
               "cell_type": "code",
               "metadata": {},
               "outputs": [],
               "source": "import os\\nimport chromadb"
              }
             ],
             "metadata": {},
             "nbformat": 4,
             "nbformat_minor": 5
            }
            """)
        comps = self.repo.imports()
        self.assertEqual({c.name: locs(c) for c in comps}, {
            "torch": ["nb/explore.ipynb:16"],
            "transformers": ["nb/explore.ipynb:17"],
            "chromadb": ["nb/explore.ipynb:25"],
        })

    def test_js_and_ts_imports(self):
        self.repo.write("web/src/app.ts", """
            import OpenAI from "openai";
            import Anthropic from '@anthropic-ai/sdk';
            import { ChatOpenAI } from "@langchain/openai/chat_models";
            import type { Foo } from "./local";
            import "ai/rsc";
            import express from "express";
            import {
              pipeline,
            } from "@xenova/transformers";
            export * from "@modelcontextprotocol/sdk/types.js";
            """)
        self.repo.write("web/src/legacy.cjs", "const { ChromaClient } = require('chromadb');\nconst fs = require('fs');\n")
        self.repo.write("web/src/lazy.mjs", "\nconst mod = await import('@pinecone-database/pinecone');\n", dedent=False)
        self.repo.write("web/src/deno.tsx", 'import { Ollama } from "npm:ollama@0.5/browser";\nimport x from "node:fs";\n')
        comps = self.repo.imports()
        self.assertEqual({c.name: locs(c) for c in comps}, {
            "openai": ["web/src/app.ts:1"],
            "@anthropic-ai/sdk": ["web/src/app.ts:2"],
            "@langchain/openai": ["web/src/app.ts:3"],
            "ai": ["web/src/app.ts:5"],
            "@xenova/transformers": ["web/src/app.ts:9"],
            "@modelcontextprotocol/sdk": ["web/src/app.ts:10"],
            "chromadb": ["web/src/legacy.cjs:1"],
            "@pinecone-database/pinecone": ["web/src/lazy.mjs:2"],
            "ollama": ["web/src/deno.tsx:1"],
        })
        for comp in comps:
            self.assertEqual((comp.ecosystem, comp.source, comp.version), ("npm", "import", None))
        self.assertEqual(pick(comps, "@langchain/openai").properties["import"], "@langchain/openai/chat_models")

    def test_large_sources_are_skipped(self):
        self.repo.write("big.py", "import openai\n" + "x = 1\n" * 100)
        with mock.patch.object(discover, "MAX_SOURCE_BYTES", 50):
            self.assertEqual(self.repo.imports(), [])
        self.assertEqual(len(self.repo.imports()), 1)

    def test_imports_ignore_non_source_and_broken_notebooks(self):
        self.repo.write("notes.txt", "import openai\n")
        self.repo.write("broken.ipynb", "{ not json")
        self.repo.write("weird.py", "", raw=b"import anthropic\n\x00\x00\xff")
        comps = self.repo.imports()
        self.assertEqual([c.name for c in comps], ["anthropic"])


if __name__ == "__main__":
    unittest.main()
