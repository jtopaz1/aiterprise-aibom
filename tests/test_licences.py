"""Tests for the model-licence verdict analyzer (C25)."""

from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from aiterprise_scan import data
from aiterprise_scan.licences import (
    LicenceVerdict,
    discover_model_refs,
    judge_licences,
    verdict_for,
)
from aiterprise_scan.model import Component, Location

REQUIRED_FIELDS = (
    "verdict_id", "name", "commercial_ok", "mau_threshold", "attribution_required",
    "attribution_text", "field_of_use", "flow_down", "redistribution_ok", "share_alike",
    "no_derivatives", "text_url", "verified", "checked_at", "notes",
)


def model(name: str, licence: str | None = None, ctype: str = "model", **props) -> Component:
    return Component(
        name=name,
        ctype=ctype,
        ecosystem="huggingface" if ctype == "model" else None,
        licence=licence,
        ai=True,
        source="code-ref",
        locations=[Location("app.py", 3)],
        properties=dict(props),
    )


def by_rule(findings, rule_id):
    return [f for f in findings if f.rule_id == rule_id]


class TempRepo:
    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def write(self, rel: str, content: str) -> Path:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def files(self) -> list[Path]:
        return sorted(p for p in self.root.rglob("*") if p.is_file())

    def close(self) -> None:
        self._tmp.cleanup()


class DataFileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = data.load("licence-verdicts.json")

    def test_every_entry_is_complete_and_cites_its_text(self) -> None:
        seen_ids = set()
        for key, entry in self.db["licences"].items():
            with self.subTest(licence=key):
                self.assertEqual(key, key.lower())
                for f in REQUIRED_FIELDS:
                    self.assertIn(f, entry)
                self.assertIn(entry["commercial_ok"], (True, False, "conditional"))
                self.assertTrue(entry["text_url"].startswith("https://"))
                self.assertRegex(entry["checked_at"], r"^\d{4}-\d{2}-\d{2}$")
                self.assertIsInstance(entry["verified"], bool)
                if not entry["verified"]:
                    self.assertTrue(entry["notes"], "unverified entries must say why")
                self.assertIsInstance(entry["field_of_use"], list)
                self.assertNotIn(entry["verdict_id"], seen_ids)
                seen_ids.add(entry["verdict_id"])
                if entry["commercial_ok"] == "conditional":
                    self.assertTrue(entry.get("mau_threshold") or entry.get("condition_label"))

    def test_required_families_are_covered(self) -> None:
        for key in (
            "llama2", "llama3", "llama3.1", "llama3.2", "llama3.3", "llama4", "gemma", "openrail",
            "openrail++", "bigscience-openrail-m", "creativeml-openrail-m", "bigscience-bloom-rail-1.0",
            "mnpl", "mrl", "qwen", "qwen-research", "databricks-open-model-license", "deepseek",
            "falcon-180b-tii-license", "falcon-llm-license", "apache-2.0", "mit", "bsd-3-clause",
            "cc-by-nc-4.0", "cc-by-4.0", "odc-by", "cdla-permissive-2.0",
        ):
            self.assertIn(key, self.db["licences"])

    def test_aliases_and_inference_rules_point_at_entries(self) -> None:
        licences = self.db["licences"]
        for alias, target in self.db["aliases"].items():
            self.assertIn(target, licences, alias)
        for rule in self.db["inference"]:
            with self.subTest(rule=rule["id"]):
                re.compile(rule["match"])
                if rule["licence"] is not None:
                    self.assertIn(rule["licence"], licences)
                for extra in rule.get("also", []):
                    self.assertIn(extra, licences)


class VerdictForTests(unittest.TestCase):
    def test_exact_tag(self) -> None:
        v = verdict_for("llama3")
        self.assertIsInstance(v, LicenceVerdict)
        self.assertEqual(v.licence_id, "llama3")
        self.assertEqual(v.verdict_id, "llama3-community-v1")
        self.assertFalse(v.inferred)
        self.assertEqual(v.mau_threshold, 700_000_000)
        self.assertEqual(v.commercial_ok, "conditional")

    def test_tag_normalisation_and_aliases(self) -> None:
        self.assertEqual(verdict_for("Apache-2.0").licence_id, "apache-2.0")
        self.assertEqual(verdict_for(" CC-BY-NC-4.0 ").licence_id, "cc-by-nc-4.0")
        self.assertEqual(verdict_for("license:mit").licence_id, "mit")
        self.assertEqual(verdict_for("Mistral AI Research License").licence_id, "mrl")

    def test_exact_tag_beats_model_name(self) -> None:
        v = verdict_for("mit", "meta-llama/Meta-Llama-3-8B")
        self.assertEqual(v.licence_id, "mit")
        self.assertFalse(v.inferred)

    def test_inference_from_model_ids(self) -> None:
        cases = {
            "meta-llama/Meta-Llama-3-8B": "llama3",
            "meta-llama/Llama-3.1-8B-Instruct": "llama3.1",
            "meta-llama/Llama-3.2-11B-Vision-Instruct": "llama3.2",
            "meta-llama/Llama-3.3-70B-Instruct": "llama3.3",
            "meta-llama/Llama-4-Scout-17B-16E": "llama4",
            "meta-llama/Llama-2-7b-hf": "llama2",
            "meta-llama/CodeLlama-7b-hf": "llama2",
            "google/gemma-2-9b": "gemma",
            "google/gemma-4-31B-it": "apache-2.0",
            "mistralai/Codestral-22B-v0.1": "mnpl",
            "mistralai/Mistral-Large-Instruct-2411": "mrl",
            "mistralai/Mistral-7B-v0.1": "apache-2.0",
            "Qwen/Qwen2.5-72B-Instruct": "qwen",
            "Qwen/Qwen2.5-3B-Instruct": "qwen-research",
            "Qwen/Qwen2.5-7B-Instruct": "apache-2.0",
            "Qwen/Qwen2-72B-Instruct": "tongyi-qianwen",
            "databricks/dbrx-instruct": "databricks-open-model-license",
            "deepseek-ai/DeepSeek-R1": "mit",
            "deepseek-ai/DeepSeek-V3": "deepseek",
            "deepseek-ai/deepseek-coder-6.7b-instruct": "deepseek",
            "tiiuae/falcon-180B": "falcon-180b-tii-license",
            "tiiuae/falcon-7b": "apache-2.0",
            "tiiuae/Falcon3-7B-Instruct": "falcon-llm-license",
            "openai/whisper-large-v3": "apache-2.0",
            "microsoft/Phi-3-mini-4k-instruct": "mit",
            "stabilityai/stable-diffusion-xl-base-1.0": "openrail++",
            "llama-3-8b": "llama3",
        }
        exact = verdict_for("llama3").confidence
        for model_id, expected in cases.items():
            with self.subTest(model_id=model_id):
                v = verdict_for(None, model_id)
                self.assertIsNotNone(v)
                self.assertEqual(v.licence_id, expected)
                self.assertTrue(v.inferred)
                self.assertLess(v.confidence, exact)
                self.assertIn(model_id, v.basis)

    def test_placeholder_tag_falls_back_to_inference(self) -> None:
        v = verdict_for("other", "Qwen/Qwen2.5-72B-Instruct")
        self.assertEqual(v.licence_id, "qwen")
        self.assertTrue(v.inferred)

    def test_distill_carries_upstream_licence(self) -> None:
        v = verdict_for(None, "deepseek-ai/DeepSeek-R1-Distill-Llama-8B")
        self.assertEqual(v.licence_id, "mit")
        self.assertEqual(v.also, ["llama3.1"])

    def test_unknown(self) -> None:
        self.assertIsNone(verdict_for(None, "bert-base-uncased"))
        self.assertIsNone(verdict_for(None, "someone/random-model"))
        self.assertIsNone(verdict_for("other"))
        self.assertIsNone(verdict_for(None, None))
        # A declared licence we have no verdict for is not overridden by a name guess.
        self.assertIsNone(verdict_for("acme-proprietary-1.0", "meta-llama/Meta-Llama-3-8B"))
        # Known "licence not established" patterns stop inference instead of guessing.
        self.assertIsNone(verdict_for(None, "mistralai/Mistral-Large-4-1T-A52B"))


class DiscoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = TempRepo()

    def tearDown(self) -> None:
        self.repo.close()

    def find(self, comps, name, ctype=None):
        hits = [c for c in comps if c.name == name and (ctype is None or c.ctype == ctype)]
        self.assertEqual(len(hits), 1, f"{name}: {[c.name for c in comps]}")
        return hits[0]

    def test_python_code_refs(self) -> None:
        (self.repo.root / "models" / "bert").mkdir(parents=True)
        self.repo.write(
            "train.py",
            "from transformers import AutoModel, AutoTokenizer, pipeline\n"  # 1
            "from huggingface_hub import hf_hub_download, snapshot_download\n"  # 2
            "from datasets import load_dataset\n"  # 3
            "tok = AutoTokenizer.from_pretrained('meta-llama/Meta-Llama-3-8B')\n"  # 4
            "m = AutoModel.from_pretrained(\n"  # 5
            "    \"meta-llama/Meta-Llama-3-8B\",\n"  # 6
            "    revision=\"a1b2c3\",\n"  # 7
            ")\n"  # 8
            "clf = pipeline('text-classification', model='distilbert-base-uncased', device=0)\n"  # 9
            "p = hf_hub_download(repo_id='TheBloke/Llama-2-7B-GGUF', filename='x.gguf')\n"  # 10
            "d = hf_hub_download(repo_id=\"org/some-data\", repo_type=\"dataset\", filename='a.csv')\n"  # 11
            "snapshot_download('google/gemma-2-9b')\n"  # 12
            "ds = load_dataset('squad')\n"  # 13
            "ds2 = load_dataset(\"HuggingFaceFW/fineweb\", revision='v1.2')\n"  # 14
            "x = AutoModel.from_pretrained(model_id)\n"  # 15 variable
            "y = AutoModel.from_pretrained(f\"{org}/{name}\")\n"  # 16 f-string
            "z = AutoModel.from_pretrained('./checkpoints/run1')\n"  # 17 local path
            "w = AutoModel.from_pretrained('models/bert')\n"  # 18 exists locally
            "# AutoModel.from_pretrained('commented/out-model')\n"  # 19 comment
            "csv = load_dataset('csv', data_files='a.csv')\n"  # 20 builder
            "o = AutoModel.from_pretrained('output_dir')\n",  # 21 local-looking name
        )
        comps = discover_model_refs(self.repo.root, self.repo.files())
        names = sorted((c.ctype, c.name, c.version or "") for c in comps)
        self.assertEqual(
            names,
            sorted([
                ("model", "meta-llama/Meta-Llama-3-8B", ""),
                ("model", "meta-llama/Meta-Llama-3-8B", "a1b2c3"),
                ("model", "distilbert-base-uncased", ""),
                ("model", "TheBloke/Llama-2-7B-GGUF", ""),
                ("dataset", "org/some-data", ""),
                ("model", "google/gemma-2-9b", ""),
                ("dataset", "squad", ""),
                ("dataset", "HuggingFaceFW/fineweb", "v1.2"),
            ]),
        )
        llama = [c for c in comps if c.name == "meta-llama/Meta-Llama-3-8B" and c.version is None][0]
        self.assertEqual([str(l) for l in llama.locations], ["train.py:4"])
        pinned = [c for c in comps if c.version == "a1b2c3"][0]
        self.assertEqual(pinned.locations[0].line, 6)
        self.assertEqual(pinned.purl, "pkg:huggingface/meta-llama/Meta-Llama-3-8B@a1b2c3")
        for c in comps:
            self.assertTrue(c.ai)
            self.assertEqual(c.source, "code-ref")
            self.assertTrue(all(l.line for l in c.locations))
            if c.ctype == "model":
                self.assertEqual(c.ecosystem, "huggingface")
            else:
                self.assertIsNone(c.ecosystem)
                self.assertEqual(c.properties["repo_type"], "dataset")
                self.assertEqual(c.properties["hf_id"], c.name)
        self.assertEqual(self.find(comps, "TheBloke/Llama-2-7B-GGUF").locations[0].line, 10)
        self.assertEqual(self.find(comps, "squad").locations[0].line, 13)

    def test_sentence_transformer_and_js(self) -> None:
        self.repo.write(
            "embed.py",
            "from sentence_transformers import SentenceTransformer\n"
            "m = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')\n",
        )
        self.repo.write(
            "web/app.ts",
            "import { pipeline } from '@xenova/transformers';\n"
            "// const old = await pipeline('x', 'commented/model');\n"
            "const pipe = await pipeline('sentiment-analysis', 'Xenova/distilbert-base-uncased-finetuned-sst-2-english');\n",
        )
        comps = discover_model_refs(self.repo.root, self.repo.files())
        st = self.find(comps, "sentence-transformers/all-MiniLM-L6-v2")
        self.assertEqual(str(st.locations[0]), "embed.py:2")
        js = self.find(comps, "Xenova/distilbert-base-uncased-finetuned-sst-2-english")
        self.assertEqual(str(js.locations[0]), "web/app.ts:3")
        self.assertFalse([c for c in comps if c.name == "commented/model"])

    def test_notebook_refs(self) -> None:
        nb = {
            "cells": [
                {"cell_type": "markdown", "metadata": {}, "source": ["# Fine-tune\n"]},
                {
                    "cell_type": "code",
                    "metadata": {},
                    "execution_count": 1,
                    "outputs": [],
                    "source": [
                        "from transformers import AutoModelForCausalLM\n",
                        "model = AutoModelForCausalLM.from_pretrained(\"mistralai/Mistral-7B-v0.1\")\n",
                    ],
                },
                {
                    "cell_type": "code",
                    "metadata": {},
                    "execution_count": 2,
                    "outputs": [],
                    "source": "from datasets import load_dataset\nds = load_dataset('imdb')\n",
                },
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
        text = json.dumps(nb, indent=1)
        self.repo.write("nb/train.ipynb", text)
        comps = discover_model_refs(self.repo.root, self.repo.files())
        m = self.find(comps, "mistralai/Mistral-7B-v0.1", "model")
        expected_line = text.splitlines().index(
            next(l for l in text.splitlines() if "Mistral-7B-v0.1" in l)
        ) + 1
        self.assertEqual(m.locations[0].path, "nb/train.ipynb")
        self.assertEqual(m.locations[0].line, expected_line)
        d = self.find(comps, "imdb", "dataset")
        self.assertEqual(d.properties, {"hf_id": "imdb", "repo_type": "dataset"})
        self.assertTrue(d.locations[0].line)

    def test_urls_and_hf_protocol(self) -> None:
        self.repo.write(
            "docs/MODELS.md",
            "We use [Llama 3](https://huggingface.co/meta-llama/Meta-Llama-3-8B).\n"
            "Data: https://huggingface.co/datasets/HuggingFaceFW/fineweb-edu/tree/main\n"
            "See https://huggingface.co/docs/hub/index and https://huggingface.co/meta-llama for docs.\n"
            "Weights: https://huggingface.co/TheBloke/Mistral-7B-GGUF/resolve/main/m.gguf\n",
        )
        self.repo.write(
            "conf/model.yaml",
            "model: hf://Qwen/Qwen2.5-7B-Instruct@v1.0\n"
            "data: hf://datasets/org/table/train.parquet\n",
        )
        comps = discover_model_refs(self.repo.root, self.repo.files())
        got = sorted((c.ctype, c.name, c.version or "", str(c.locations[0])) for c in comps)
        self.assertEqual(
            got,
            sorted([
                ("model", "meta-llama/Meta-Llama-3-8B", "", "docs/MODELS.md:1"),
                ("dataset", "HuggingFaceFW/fineweb-edu", "", "docs/MODELS.md:2"),
                ("model", "TheBloke/Mistral-7B-GGUF", "", "docs/MODELS.md:4"),
                ("model", "Qwen/Qwen2.5-7B-Instruct", "v1.0", "conf/model.yaml:1"),
                ("dataset", "org/table", "", "conf/model.yaml:2"),
            ]),
        )

    def test_licence_citation_links_are_not_model_use(self) -> None:
        self.repo.write(
            "data/verdicts.json",
            '{"text_url": "https://huggingface.co/Qwen/Qwen2.5-3B-Instruct/blob/main/LICENSE",\n'
            ' "notice": "https://huggingface.co/org/m/raw/main/NOTICE.txt",\n'
            ' "card": "https://huggingface.co/org/m2/blob/main/README.md",\n'
            ' "policy": "https://huggingface.co/meta-llama/Llama-3.1-8B/blob/main/USE_POLICY.md"}\n',
        )
        self.repo.write("dl.md", "https://huggingface.co/org/real/resolve/main/model.safetensors\n")
        comps = discover_model_refs(self.repo.root, self.repo.files())
        self.assertEqual([c.name for c in comps], ["org/real"])

    def test_model_card_with_base_model(self) -> None:
        self.repo.write(
            "my-llama-ft/README.md",
            "---\n"
            "language:\n"
            "- en\n"
            "license: llama3\n"
            "base_model: meta-llama/Meta-Llama-3-8B\n"
            "pipeline_tag: text-generation\n"
            "library_name: transformers\n"
            "---\n"
            "# My fine-tune\n",
        )
        comps = discover_model_refs(self.repo.root, self.repo.files())
        cards = [c for c in comps if c.source == "model-card"]
        self.assertEqual(len(cards), 1)
        card = cards[0]
        self.assertEqual(card.ctype, "model")
        self.assertEqual(card.name, "my-llama-ft")
        self.assertEqual(card.licence, "llama3")
        self.assertEqual(card.properties["base_model"], "meta-llama/Meta-Llama-3-8B")
        self.assertEqual(card.properties["pipeline_tag"], "text-generation")
        self.assertEqual(str(card.locations[0]), "my-llama-ft/README.md:4")
        self.assertTrue(card.ai)

    def test_model_card_other_with_licence_name(self) -> None:
        self.repo.write(
            "README.md",
            "---\nlicense: other\nlicense_name: mnpl\nlicense_link: https://mistral.ai/licenses/MNPL-0.1.md\n"
            "library_name: vllm\n---\n",
        )
        comps = discover_model_refs(self.repo.root, self.repo.files())
        card = [c for c in comps if c.source == "model-card"][0]
        self.assertEqual(card.licence, "mnpl")
        self.assertEqual(card.properties["license_declared"], "other")

    def test_dataset_card(self) -> None:
        self.repo.write(
            "data/reviews/README.md",
            "---\n"
            "license: cc-by-nc-4.0\n"
            "task_categories:\n"
            "- text-classification\n"
            "size_categories:\n"
            "- 10K<n<100K\n"
            "---\n",
        )
        comps = discover_model_refs(self.repo.root, self.repo.files())
        card = [c for c in comps if c.source == "model-card"][0]
        self.assertEqual(card.ctype, "dataset")
        self.assertIsNone(card.ecosystem)
        self.assertEqual(card.licence, "cc-by-nc-4.0")
        self.assertEqual(card.properties["repo_type"], "dataset")
        self.assertEqual(card.locations[0].line, 2)

    def test_plain_readme_is_not_a_card(self) -> None:
        self.repo.write("README.md", "---\ntitle: Docs\nlicense: mit\nlayout: page\n---\n# hi\n")
        self.repo.write("other/README.md", "# No front matter\nlicense: mit\n")
        self.assertEqual(discover_model_refs(self.repo.root, self.repo.files()), [])


class JudgeSeverityTests(unittest.TestCase):
    def test_conditional_commercial_matches_sample_output(self) -> None:
        findings = judge_licences([model("meta-llama/Meta-Llama-3-8B", "llama3")], "commercial")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.rule_id, "ait.licence.conditional")
        self.assertEqual(f.severity, "medium")
        self.assertEqual(f.verdict, "suspicious")
        self.assertEqual(f.title, "licence: attribution required + >700M MAU clause vs use_context=commercial")
        self.assertTrue(f.remediation)
        self.assertEqual(f.location.path, "app.py")

    def test_conditional_in_research_is_an_obligation(self) -> None:
        f = judge_licences([model("meta-llama/Meta-Llama-3-8B", "llama3")], "research")[0]
        self.assertEqual((f.rule_id, f.severity, f.verdict), ("ait.licence.obligations", "low", "benign"))

    def test_non_commercial_dataset(self) -> None:
        ds = model("org/reviews", "cc-by-nc-4.0", ctype="dataset", hf_id="org/reviews", repo_type="dataset")
        f = judge_licences([ds], "commercial")[0]
        self.assertEqual((f.rule_id, f.severity, f.verdict), ("ait.licence.non-commercial", "high", "suspicious"))
        self.assertIn("use_context=commercial", f.title)
        for ctx in ("research", "non-profit"):
            f = judge_licences([ds], ctx)[0]
            self.assertEqual((f.rule_id, f.severity, f.verdict), ("ait.licence.non-commercial", "info", "benign"))

    def test_internal_use_of_research_licence_is_a_conflict(self) -> None:
        f = judge_licences([model("mistralai/Codestral-22B-v0.1", "mnpl")], "internal")[0]
        self.assertEqual((f.rule_id, f.severity), ("ait.licence.non-commercial", "high"))
        self.assertIn("license@mistral.ai", f.remediation)

    def test_inferred_non_commercial_model(self) -> None:
        f = judge_licences([model("Qwen/Qwen2.5-3B-Instruct")], "commercial")[0]
        self.assertEqual((f.rule_id, f.severity), ("ait.licence.non-commercial", "high"))
        self.assertTrue(f.evidence[0].detail["inferred"])
        self.assertIn("Apache-2.0 Qwen2.5 size", f.remediation)

    def test_no_derivatives_and_share_alike(self) -> None:
        for ctx in ("commercial", "research"):
            nd = judge_licences([model("org/d", "cc-by-nd-4.0", ctype="dataset")], ctx)[0]
            self.assertEqual((nd.rule_id, nd.severity), ("ait.licence.no-derivatives", "medium"))
            sa = judge_licences([model("org/d", "cc-by-sa-4.0", ctype="dataset")], ctx)[0]
            self.assertEqual((sa.rule_id, sa.severity), ("ait.licence.share-alike", "medium"))
        ncsa = judge_licences([model("org/d", "cc-by-nc-sa-4.0", ctype="dataset")], "commercial")[0]
        self.assertEqual(ncsa.severity, "high")
        self.assertIn("share-alike", ncsa.title)

    def test_use_restrictions_are_low_obligations(self) -> None:
        for lic in ("gemma", "creativeml-openrail-m", "bigscience-openrail-m", "deepseek", "cc-by-4.0", "odc-by"):
            with self.subTest(licence=lic):
                f = judge_licences([model("x/y", lic)], "commercial")[0]
                self.assertEqual((f.rule_id, f.severity, f.verdict), ("ait.licence.obligations", "low", "benign"))

    def test_permissive_is_info(self) -> None:
        for lic in ("apache-2.0", "mit", "bsd-3-clause", "cdla-permissive-2.0"):
            f = judge_licences([model("x/y", lic)], "commercial")[0]
            self.assertEqual((f.rule_id, f.severity), ("ait.licence.obligations", "info"))

    def test_falcon_hosting_condition(self) -> None:
        f = judge_licences([model("tiiuae/falcon-180B")], "commercial")[0]
        self.assertEqual((f.rule_id, f.severity), ("ait.licence.conditional", "medium"))
        self.assertIn("hosting-use needs TII permission", f.title)
        self.assertIn("(licence inferred from model id)", f.title)

    def test_unknown_licence(self) -> None:
        f = judge_licences([model("someone/random-model")], "commercial")[0]
        self.assertEqual((f.rule_id, f.severity, f.verdict), ("ait.licence.unknown", "low", "unknown"))
        f = judge_licences([model("someone/random-model", "acme-eula")], "commercial")[0]
        self.assertEqual(f.rule_id, "ait.licence.unknown")
        self.assertIn("acme-eula", f.title)
        ds = judge_licences([model("squad", ctype="dataset")], "commercial")
        self.assertEqual([x.rule_id for x in ds], ["ait.licence.unknown"])

    def test_model_files(self) -> None:
        # No licence metadata and an uninformative name: no finding (avoid noise on checkpoints).
        self.assertEqual(judge_licences([model("ckpt/epoch3.pt", ctype="model-file")]), [])
        f = judge_licences([model("weights/llama-3-8b.Q4_K_M.gguf", ctype="model-file")])[0]
        self.assertEqual((f.rule_id, f.severity), ("ait.licence.conditional", "medium"))
        self.assertLess(f.confidence, verdict_for(None, "llama-3-8b").confidence)
        f = judge_licences([model("weights/x.gguf", "cc-by-nc-4.0", ctype="model-file")])[0]
        self.assertEqual(f.severity, "high")

    def test_other_ctypes_are_ignored(self) -> None:
        lib = Component("transformers", ctype="library", ecosystem="pypi", licence="cc-by-nc-4.0")
        self.assertEqual(judge_licences([lib]), [])

    def test_unknown_use_context_is_judged_strictly(self) -> None:
        f = judge_licences([model("x/y", "cc-by-nc-4.0")], "weird")[0]
        self.assertEqual(f.severity, "high")
        self.assertIn("use_context=commercial", f.title)


class JudgePolicyTests(unittest.TestCase):
    def test_deny_by_category(self) -> None:
        findings = judge_licences([model("org/d", "cc-by-nc-4.0", ctype="dataset")], "research",
                                  deny=["non-commercial-only", "no-derivative"])
        self.assertEqual([f.rule_id for f in findings], ["ait.licence.denied"])
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(findings[0].verdict, "suspicious")
        self.assertEqual(findings[0].evidence[0].detail["matched"], "non-commercial-only")

    def test_deny_by_verdict_name(self) -> None:
        f = judge_licences([model("meta-llama/Meta-Llama-3-8B", "llama3")], deny=["llama3-community"])
        self.assertEqual([x.rule_id for x in f], ["ait.licence.denied"])

    def test_allow_list(self) -> None:
        allow = ["mit", "apache-2.0", "llama3-community"]
        f = judge_licences([model("meta-llama/Meta-Llama-3-8B", "llama3")], allow=allow)
        self.assertEqual([x.rule_id for x in f], ["ait.licence.conditional"])
        f = judge_licences([model("google/gemma-2-9b", "gemma")], allow=allow)
        self.assertEqual(sorted(x.rule_id for x in f), ["ait.licence.not-allowed", "ait.licence.obligations"])
        not_allowed = by_rule(f, "ait.licence.not-allowed")[0]
        self.assertEqual(not_allowed.severity, "medium")
        self.assertEqual(not_allowed.verdict, "suspicious")
        f = judge_licences([model("x/y", "acme-eula")], allow=allow)
        self.assertEqual(sorted(x.rule_id for x in f), ["ait.licence.not-allowed", "ait.licence.unknown"])

    def test_deny_unknown_raw_licence(self) -> None:
        f = judge_licences([model("x/y", "acme-eula")], deny=["acme-eula"])
        self.assertEqual([x.rule_id for x in f], ["ait.licence.denied"])


class JudgeInheritanceTests(unittest.TestCase):
    def test_fine_tune_inherits_base_model_terms(self) -> None:
        card = model("my-ft", "apache-2.0", base_model="meta-llama/Meta-Llama-3-8B")
        findings = judge_licences([card], "commercial")
        self.assertEqual(sorted((f.rule_id, f.severity) for f in findings),
                         [("ait.licence.conditional", "medium"), ("ait.licence.obligations", "info")])
        base = by_rule(findings, "ait.licence.conditional")[0]
        self.assertTrue(base.title.startswith("base model meta-llama/Meta-Llama-3-8B: "))
        self.assertEqual(base.evidence[0].detail["role"], "base_model")
        self.assertEqual(len({f.fingerprint for f in findings}), len(findings))

    def test_base_with_same_licence_is_not_duplicated(self) -> None:
        card = model("my-ft", "llama3", base_model=["meta-llama/Meta-Llama-3-8B"])
        self.assertEqual(len(judge_licences([card])), 1)

    def test_unknown_base_model(self) -> None:
        card = model("my-ft", "mit", base_model="someone/mystery-base")
        unknown = by_rule(judge_licences([card]), "ait.licence.unknown")
        self.assertEqual(len(unknown), 1)
        self.assertIn("someone/mystery-base", unknown[0].title)

    def test_distill_upstream_licence(self) -> None:
        findings = judge_licences([model("deepseek-ai/DeepSeek-R1-Distill-Llama-8B", "mit")], "commercial")
        rules = sorted((f.rule_id, f.evidence[0].detail["role"]) for f in findings)
        self.assertEqual(rules, [("ait.licence.conditional", "upstream"), ("ait.licence.obligations", "self")])

    def test_name_hint_when_declared_licence_disagrees(self) -> None:
        findings = judge_licences([model("someone/llama-3-8b-finetune", "apache-2.0")], "commercial")
        hint = [f for f in findings if f.evidence[0].detail["role"] == "name-hint"]
        self.assertEqual(len(hint), 1)
        self.assertEqual(hint[0].severity, "medium")
        self.assertLessEqual(hint[0].confidence, 45)
        self.assertIn("declares apache-2.0", hint[0].title)


class EvidenceTests(unittest.TestCase):
    def test_evidence_cites_verdict_and_text(self) -> None:
        f = judge_licences([model("meta-llama/Meta-Llama-3-8B")], "commercial")[0]
        ev = f.evidence[0]
        self.assertEqual(ev.source, "ait-licence")
        self.assertEqual(ev.record, "llama3-community-v1")
        self.assertEqual(ev.url, "https://raw.githubusercontent.com/meta-llama/llama3/main/LICENSE")
        d = ev.detail
        self.assertEqual(d["advisory"], "not legal advice")
        self.assertTrue(d["inferred"])
        self.assertEqual(d["use_context"], "commercial")
        for key in REQUIRED_FIELDS:
            self.assertIn(key, d)
        self.assertNotIn("remediation", d)
        out = f.to_dict()
        self.assertEqual(out["evidence"][0]["record"], "llama3-community-v1")
        self.assertEqual(out["maps_to"], ["LLM03:2025 Supply Chain"])

    def test_end_to_end_from_discovery(self) -> None:
        repo = TempRepo()
        try:
            repo.write("app.py", "from transformers import pipeline\n"
                                 "gen = pipeline('text-generation', model='meta-llama/Meta-Llama-3-8B')\n")
            repo.write("data/README.md", "---\nlicense: cc-by-nc-4.0\ntask_categories:\n- summarization\n---\n")
            comps = discover_model_refs(repo.root, repo.files())
            findings = judge_licences(comps, "commercial")
            got = sorted((f.severity, f.rule_id, str(f.location)) for f in findings)
            self.assertEqual(got, [
                ("high", "ait.licence.non-commercial", "data/README.md:2"),
                ("medium", "ait.licence.conditional", "app.py:2"),
            ])
        finally:
            repo.close()


if __name__ == "__main__":
    unittest.main()
