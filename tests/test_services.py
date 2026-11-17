"""AI endpoints and vector stores as BOM components (design doc 13 §4.2, C02)."""

import tempfile
import unittest
from pathlib import Path

from aiterprise_scan import services
from aiterprise_scan.walk import walk


def discover(files: dict[str, str], ctype: str | None = None):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for rel, text in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        comps = services.discover_services(root, walk(root, all_files=True))
    return {c.name: c for c in comps if ctype is None or c.ctype == ctype}


def endpoints(files):
    return discover(files, "ai-endpoint")


def stores(files):
    return discover(files, "vector-store")


class EndpointTests(unittest.TestCase):
    def test_provider_apis_named_in_code_and_configuration(self):
        found = endpoints({
            "app.py": 'URL = "https://api.openai.com/v1/chat/completions"\n',
            "config/llm.yaml": "endpoint: https://contoso.openai.azure.com/\n",
            "infra/bedrock.json": '{"url": "https://bedrock-runtime.us-east-1.amazonaws.com/model/x/invoke"}',
            "lib/gemini.ts": 'fetch("https://generativelanguage.googleapis.com/v1beta/models")',
        })
        self.assertEqual({n: c.properties["provider"] for n, c in found.items()}, {
            "https://api.openai.com": "OpenAI",
            "https://contoso.openai.azure.com": "Azure OpenAI",
            "https://bedrock-runtime.us-east-1.amazonaws.com": "Amazon Bedrock",
            "https://generativelanguage.googleapis.com": "Google Gemini"})
        self.assertEqual(found["https://api.openai.com"].ctype, "ai-endpoint")
        self.assertEqual(str(found["https://api.openai.com"].locations[0]), "app.py:1")
        self.assertEqual(found["https://api.openai.com"].properties["found_by"], ["url"])

    def test_urls_that_are_not_ai_endpoints(self):
        found = endpoints({"app.py": 'S3 = "https://s3.amazonaws.com/bucket"\nHOME = "https://openai.com/blog"\n',
                           "README.md": "Calls https://api.openai.com/v1 under the hood.",
                           "docs/setup.rst": "OPENAI_BASE_URL=https://proxy.example.com"})
        self.assertEqual(found, {})

    def test_credentials_never_reach_the_component(self):
        found = endpoints({"app.py": 'u = "https://user:hunter2@api.openai.com/v1?api-key=sk-abc#x"\n'})
        self.assertEqual(list(found), ["https://api.openai.com"])
        text = repr(found["https://api.openai.com"].to_dict())
        self.assertNotIn("hunter2", text)
        self.assertNotIn("sk-abc", text)

    def test_endpoint_variables(self):
        found = endpoints({
            ".env": "OPENAI_BASE_URL=https://llm-proxy.internal.example/v1\nOPENAI_API_KEY=${KEY}\n",
            "docker-compose.yml": "services:\n  app:\n    environment:\n      - OLLAMA_HOST=ollama:11434\n"
                                  "      ANTHROPIC_BASE_URL: ${PROXY_URL}\n",
            "Dockerfile": "FROM python:3.12\nENV AZURE_OPENAI_ENDPOINT https://acme.openai.azure.com\n"
                          "ENV OPENAI_BASE_URL https://gw.corp.example/v1\n",
        })
        self.assertEqual(sorted(found), ["http://ollama:11434", "https://acme.openai.azure.com",
                                         "https://gw.corp.example", "https://llm-proxy.internal.example"])
        self.assertEqual(found["https://gw.corp.example"].properties["found_by"], ["env OPENAI_BASE_URL"])
        proxy = found["https://llm-proxy.internal.example"]
        self.assertEqual((proxy.properties["provider"], proxy.properties["found_by"]),
                         ("OpenAI-compatible (self-hosted or proxy)", ["env OPENAI_BASE_URL"]))
        self.assertEqual(found["http://ollama:11434"].properties["provider"], "Ollama")
        self.assertEqual(found["https://acme.openai.azure.com"].properties["provider"], "Azure OpenAI")

    def test_a_client_base_url_in_a_file_that_uses_an_ai_client(self):
        found = endpoints({
            "app.py": 'from openai import OpenAI\n\nclient = OpenAI(base_url="http://10.0.0.5:8000/v1", api_key="x")\n',
            "web.ts": 'import OpenAI from "openai";\nconst c = new OpenAI({ baseURL: "https://openrouter.ai/api/v1" });\n',
            "http.py": 'import httpx\n\nc = httpx.Client(base_url="https://billing.example.com")\n',
        })
        self.assertEqual({n: c.properties["provider"] for n, c in found.items()},
                         {"http://10.0.0.5:8000": "unknown (self-hosted or proxy)", "https://openrouter.ai": "OpenRouter"})
        self.assertEqual(found["http://10.0.0.5:8000"].properties["found_by"], ["client base_url"])
        self.assertEqual(str(found["http://10.0.0.5:8000"].locations[0]), "app.py:3")

    def test_tests_are_not_the_application(self):
        url = 'U = "https://api.openai.com/v1"\n'
        found = endpoints({"tests/test_api.py": url, "src/app.test.ts": url, "pkg/client_test.go": url,
                           "web/spec/x.spec.js": url, "conftest.py": url, "e2e/.env": "OPENAI_BASE_URL=http://x:1\n",
                           "src/app.py": url})
        self.assertEqual([str(loc) for loc in found["https://api.openai.com"].locations], ["src/app.py:1"])

    def test_a_port_names_a_provider_only_when_the_endpoint_is_known_to_be_one(self):
        found = endpoints({"net.go": 'a := "http://foo.com:1234"\nb := "http://localhost:1234"\nc := "http://gpu-box:11434"\n',
                           "llm.py": 'OLLAMA = "http://localhost:11434"\n',
                           ".env": "OLLAMA_HOST=gpu-box:11434\n"})
        self.assertEqual({n: c.properties["provider"] for n, c in found.items()},
                         {"http://localhost:11434": "Ollama", "http://gpu-box:11434": "Ollama"})
        self.assertEqual(found["http://gpu-box:11434"].properties["found_by"], ["env OLLAMA_HOST"])

    def test_comments_and_commented_out_settings_are_not_in_use(self):
        found = discover({
            "client.ts": "/**\n * e.g. 'https://my-resource.services.ai.azure.com'\n */\n"
                         "// fetch('https://api.openai.com/v1')\n/* https://api.mistral.ai */\n",
            "app.py": "# URL = 'https://api.groq.com/openai/v1'\n",
            ".env": "# OPENAI_BASE_URL=https://old-proxy.example/v1\n",
            "compose.yml": "services:\n  q:\n    # image: qdrant/qdrant:v1.12.4\n",
            "Dockerfile": "FROM python:3.12\n# ENV OPENAI_BASE_URL https://gw.corp.example/v1\n",
        })
        self.assertEqual(found, {})

    def test_placeholders_are_not_hosts(self):
        found = endpoints({".env": "ANTHROPIC_BASE_URL=http://<dashboard>:3787\nOPENAI_BASE_URL=http://${HOST}:4000\n"})
        self.assertEqual(found, {})

    def test_one_endpoint_found_several_ways_is_one_component(self):
        found = endpoints({".env": "OPENAI_BASE_URL=https://api.openai.com/v1\n",
                           "app.py": 'from openai import OpenAI\nOpenAI(base_url="https://api.openai.com/v1")\n'})
        self.assertEqual(list(found), ["https://api.openai.com"])
        comp = found["https://api.openai.com"]
        self.assertEqual(comp.properties["found_by"], ["client base_url", "env OPENAI_BASE_URL", "url"])
        self.assertEqual(sorted(str(loc) for loc in comp.locations), [".env:1", "app.py:2"])


class VectorStoreTests(unittest.TestCase):
    def test_container_images(self):
        found = stores({"docker-compose.yml": "services:\n  db:\n    image: qdrant/qdrant:v1.12.4\n"
                                              "  pg:\n    image: postgres:16\n"
                                              "  w:\n    image: cr.weaviate.io/semitechnologies/weaviate:1.25.0\n"
                                              "  m:\n    image: milvusdb/milvus:latest\n",
                        "chroma/Dockerfile": "FROM chromadb/chroma:0.5.0\n"})
        self.assertEqual({n: (c.version, c.properties["image"]) for n, c in found.items()}, {
            "qdrant": ("v1.12.4", "qdrant/qdrant:v1.12.4"),
            "weaviate": ("1.25.0", "cr.weaviate.io/semitechnologies/weaviate:1.25.0"),
            "milvus": (None, "milvusdb/milvus:latest"),
            "chroma": ("0.5.0", "chromadb/chroma:0.5.0")})
        self.assertEqual(str(found["qdrant"].locations[0]), "docker-compose.yml:3")

    def test_clients_opened_on_a_path_url_or_index(self):
        found = stores({
            "rag.py": "import chromadb\nclient = chromadb.PersistentClient(path=\"./chroma_db\")\n",
            "search.py": "from qdrant_client import QdrantClient\n"
                         "q = QdrantClient(api_key=\"k-123\", url=\"https://xyz.cloud.qdrant.io:6333\")\n"
                         "tmp = QdrantClient(\":memory:\")\n",
            "index.ts": 'import { Pinecone } from "@pinecone-database/pinecone";\nconst idx = pc.index("docs");\n',
            "load.py": "from langchain_community.vectorstores import FAISS\n"
                       "db = FAISS.load_local(\"faiss_index\", emb, allow_dangerous_deserialization=True)\n",
            "lance.py": "import lancedb\ndb = lancedb.connect(\"data/lancedb\")\n",
        })
        self.assertEqual(sorted(found), ["chroma:./chroma_db", "faiss:faiss_index", "lancedb:data/lancedb",
                                         "pinecone:docs", "qdrant:https://xyz.cloud.qdrant.io:6333"])
        self.assertEqual(str(found["chroma:./chroma_db"].locations[0]), "rag.py:2")
        self.assertNotIn("k-123", repr(found["qdrant:https://xyz.cloud.qdrant.io:6333"].to_dict()))

    def test_calls_in_files_that_do_not_use_the_store(self):
        found = stores({"api.py": "import requests\nc = HttpClient(host=\"localhost\")\nidx = pc.index(\"x\")\n"})
        self.assertEqual(found, {})

    def test_stores_set_up_by_tests_are_not_listed(self):
        found = stores({"tests/test_rag.py": "import chromadb\nc = chromadb.PersistentClient(path=\"./tmp_db\")\n",
                        "tests/compose.yml": "services:\n  q:\n    image: qdrant/qdrant\n",
                        "tests/fixtures/db/chroma.sqlite3": ""})
        self.assertEqual(found, {})

    def test_stores_on_disk(self):
        found = stores({"store/chroma.sqlite3": "", "vs/index.faiss": "", "vs/index.pkl": ""})
        self.assertEqual(sorted(found), ["chroma:store", "faiss:vs"])
        self.assertEqual(found["faiss:vs"].properties["found_by"], ["files on disk"])


class ScanTests(unittest.TestCase):
    """A scan lists prompts, AI endpoints and vector stores, and the CycloneDX BOM carries them."""

    def test_the_three_classes_reach_the_report_and_the_bom(self):
        from aiterprise_scan import bom
        from aiterprise_scan.scanner import ScanOptions, run_scan

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "AGENTS.md").write_text("Run the tests.", encoding="utf-8")
            (root / ".env").write_text("OPENAI_BASE_URL=https://llm-proxy.internal.example/v1\n", encoding="utf-8")
            (root / "compose.yaml").write_text("services:\n  q:\n    image: qdrant/qdrant:v1.12.4\n", encoding="utf-8")
            result = run_scan(ScanOptions(target=root, offline=True))
        got = sorted((c.ctype, c.name) for c in result.components)
        self.assertEqual(got, [("ai-endpoint", "https://llm-proxy.internal.example"), ("prompt", "AGENTS.md"),
                               ("vector-store", "qdrant")])
        self.assertTrue(all(c.ai for c in result.components))
        doc = bom.build(result)
        kinds = {c["name"]: (c["type"], {p["name"]: p["value"] for p in c.get("properties", [])}["aiterprise:ctype"])
                 for c in doc["components"]}
        self.assertEqual(kinds, {"AGENTS.md": ("data", "prompt"),
                                 "https://llm-proxy.internal.example": ("data", "ai-endpoint"),
                                 "qdrant": ("data", "vector-store")})
        self.assertEqual(result.exit_code, 0)


if __name__ == "__main__":
    unittest.main()
