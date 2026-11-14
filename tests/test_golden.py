"""Golden fixture suite: end-to-end CLI runs with reviewed expectations.

Each fixture under tests/golden/ is scanned offline through the real CLI (`--format json`), so
these tests cover discovery → judgement → policy → exit code together. F02, F04b and F12 are
false-positive canaries: they must stay free of medium-or-worse findings. Binary model files are
generated here (never committed) and are never loaded.
"""

import collections
import io
import json
import os
import pickle
import shutil
import struct
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from aiterprise_scan import cli
from aiterprise_scan.model import SEVERITY_RANK

GOLDEN = Path(__file__).parent / "golden"

# GLOBAL os system / BINUNICODE "echo pwned" / TUPLE1 / REDUCE / STOP — inert bytes, never loaded.
MALICIOUS_PICKLE = b"\x80\x02cos\nsystem\nq\x00X\x0a\x00\x00\x00echo pwnedq\x01\x85q\x02Rq\x03."


def _build_f05(root: Path) -> None:
    (root / "model.pkl").write_bytes(MALICIOUS_PICKLE)
    with zipfile.ZipFile(root / "checkpoint.pt", "w") as zf:
        zf.writestr("archive/data.pkl", MALICIOUS_PICKLE)
        zf.writestr("archive/version", "3\n")


def _build_f12(root: Path) -> None:
    safe = pickle.dumps(collections.OrderedDict(weight=[0.1, 0.2]), protocol=2)
    with zipfile.ZipFile(root / "classifier.pt", "w") as zf:
        zf.writestr("archive/data.pkl", safe)
        zf.writestr("archive/version", "3\n")
    header = json.dumps({"w": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]},
                         "__metadata__": {"format": "pt"}}).encode()
    (root / "model.safetensors").write_bytes(struct.pack("<Q", len(header)) + header + b"\x00" * 8)


BUILDERS = {"F05-unsafe-pickle": _build_f05, "F12-clean-models": _build_f12}

# fixture -> (expected exit code, required findings [(rule prefix, severity)], max allowed severity or None)
EXPECTED = {
    "F01-malicious-requirements": (1, [("ait.pkg.malicious", "critical")], None),
    "F02-clean-python": (0, [], "low"),
    "F03-poisoned-mcp": (1, [("ait.mcp.desc.", "critical")], None),
    "F04-curl-bash-mcp": (1, [("ait.mcp.cmd.", "critical")], None),
    "F04b-clean-mcp": (0, [], "low"),
    "F05-unsafe-pickle": (1, [("ait.model.pickle.dangerous-global", "critical")], None),
    "F06-licence-llama": (1, [("ait.licence.conditional", "medium"), ("ait.licence.non-commercial", "high")], None),
    "F07-npm-lockfile": (1, [("ait.pkg.malicious", "critical")], None),
    "F08-cdxgen-bom": (1, [("ait.pkg.malicious", "critical")], None),
    "F08b-snyk-bom": (0, [("ait.pkg.malicious-unpinned", "low")], "low"),
    "F09-malicious-skill": (1, [("ait.skill.", "critical")], None),
    "F10-bom-config-utf16": (1, [("ait.mcp.desc.", "critical")], None),
    "F11-policy-gate": (1, [("ait.pkg.malicious-range", "medium"), ("ait.policy.denied-package", "high")], None),
    "F12-clean-models": (0, [], "low"),
}


def run_fixture(name: str) -> tuple[int, dict]:
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / name
        shutil.copytree(GOLDEN / name, work)
        if name in BUILDERS:
            BUILDERS[name](work)
        out = Path(tmp) / "out"
        old = os.environ.get("AITERPRISE_CACHE_DIR")
        os.environ["AITERPRISE_CACHE_DIR"] = str(Path(tmp) / "cache")  # an empty cache: fully offline
        try:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = cli.main(["scan", str(work), "--offline", "--format", "json", "--out", str(out)])
        finally:
            if old is None:
                os.environ.pop("AITERPRISE_CACHE_DIR", None)
            else:
                os.environ["AITERPRISE_CACHE_DIR"] = old
        report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    return code, report


class GoldenTests(unittest.TestCase):
    maxDiff = None

    def test_every_fixture_has_expectations(self):
        on_disk = sorted(p.name for p in GOLDEN.iterdir() if p.is_dir())
        self.assertEqual(on_disk, sorted(EXPECTED))


def _make_test(name: str):
    exit_code, required, ceiling = EXPECTED[name]

    def test(self: GoldenTests) -> None:
        code, report = run_fixture(name)
        active = [f for f in report["findings"] if f["status"] == "new"]
        summary = [(f["rule_id"], f["severity"], f.get("location")) for f in active]
        self.assertFalse([n for n in report["notes"] if "analyzer error" in n], report["notes"])
        for prefix, severity in required:
            self.assertTrue(
                any(f["rule_id"].startswith(prefix) and f["severity"] == severity for f in active),
                f"{name}: expected {prefix}* at {severity}; got {summary}",
            )
        if ceiling is not None:
            worst = [f for f in active if SEVERITY_RANK[f["severity"]] > SEVERITY_RANK[ceiling]]
            self.assertEqual(worst, [], f"{name}: false positives above {ceiling}: {summary}")
        self.assertEqual(code, exit_code, f"{name}: exit {code}; findings {summary}")
        self.assertEqual(report["exit_code"], exit_code)

    test.__name__ = f"test_{name.replace('-', '_')}"
    return test


for _name in EXPECTED:
    setattr(GoldenTests, f"test_{_name.replace('-', '_')}", _make_test(_name))


if __name__ == "__main__":
    unittest.main()
