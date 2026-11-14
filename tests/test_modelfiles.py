"""Tests for the model-file analyzer.

Safety: every malicious sample is hand-assembled from pickle opcode bytes and is never loaded.
Nothing in this file calls pickle.load/loads, torch.load, numpy.load, joblib.load or marshal.
`pickle.dumps` is used only to *produce* harmless samples.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import pickle
import random
import re
import struct
import tempfile
import unittest
import zipfile
import zlib
from collections import OrderedDict
from pathlib import Path
from unittest import mock

from aiterprise_scan import data, modelfiles
from aiterprise_scan.model import OWASP_POISONING, OWASP_SUPPLY_CHAIN, SEVERITIES

# --------------------------------------------------------------------------------------------
# Opcode / container builders
# --------------------------------------------------------------------------------------------


def sbu(s: str) -> bytes:
    """SHORT_BINUNICODE (protocol 4)."""
    b = s.encode()
    return b"\x8c" + bytes([len(b)]) + b


def sbs(s: str) -> bytes:
    """SHORT_BINSTRING (protocol 1+; unpickled as str)."""
    b = s.encode("latin-1")
    return b"U" + bytes([len(b)]) + b


def glob(module: str, name: str) -> bytes:
    """GLOBAL opcode."""
    return b"c" + module.encode() + b"\n" + name.encode() + b"\n"


# protocol 0: GLOBAL os system, MARK, STRING, TUPLE, REDUCE, STOP
OS_SYSTEM_P0 = b"cos\nsystem\n(S'echo pwned'\ntR."


def evil_p2(module: str = "posix", name: str = "system") -> bytes:
    return b"\x80\x02" + glob(module, name) + sbs("id") + b"\x85R."


def torch_data_pkl(extra: bytes = b"") -> bytes:
    """A data.pkl shaped like torch.save output (OrderedDict of one rebuilt tensor)."""
    p = b"\x80\x02"
    p += glob("collections", "OrderedDict") + b")R"
    p += sbs("weight")
    p += glob("torch._utils", "_rebuild_tensor_v2")
    p += b"("  # MARK: args of _rebuild_tensor_v2
    p += b"(" + sbs("storage") + glob("torch", "FloatStorage") + sbs("0") + sbs("cpu") + b"K\x04tQ"  # BINPERSID
    p += b"K\x00K\x02K\x02\x86K\x02K\x01\x86\x89" + glob("collections", "OrderedDict") + b")Rt"
    p += b"Rs" + extra + b"."
    return p


def torch_zip(data_pkl: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("archive/data.pkl", data_pkl)
        zf.writestr("archive/byteorder", "little")
        zf.writestr("archive/data/0", b"\x00" * 16)
        zf.writestr("archive/version", "3\n")
    return buf.getvalue()


def joblib_array_stream(tail: bytes) -> bytes:
    """joblib-style stream: a NumpyArrayWrapper whose raw float64[3] bytes follow its BUILD."""
    p = b"\x80\x04" + glob("joblib.numpy_pickle", "NumpyArrayWrapper") + b")\x81"  # NEWOBJ
    p += b"}("  # EMPTY_DICT, MARK
    p += sbu("subclass") + glob("numpy", "ndarray")
    p += sbu("shape") + b"K\x03\x85"
    p += sbu("order") + sbu("C")
    p += sbu("dtype") + glob("numpy", "dtype") + sbu("f8") + b"\x89\x88\x87R"
    p += b"(K\x03" + sbu("<") + b"NNNJ\xff\xff\xff\xffJ\xff\xff\xff\xffK\x00tb"  # dtype state, BUILD
    p += sbu("allow_mmap") + b"\x88"
    p += sbu("numpy_array_alignment_bytes") + b"K\x10"
    p += b"ub"  # SETITEMS, BUILD -> raw array bytes follow (padding byte, padding, data)
    pad = 16 - ((len(p) + 1) % 16)
    p += bytes([pad]) + b"\xff" * pad + struct.pack("<3d", 1.0, 2.0, 3.0)
    return p + tail


def npy(descr, shape, payload: bytes) -> bytes:
    header = repr({"descr": descr, "fortran_order": False, "shape": shape}).encode("latin-1")
    header += b" " * ((64 - (10 + len(header) + 1) % 64) % 64) + b"\n"
    return b"\x93NUMPY\x01\x00" + struct.pack("<H", len(header)) + header + payload


def safetensors(header: dict, payload: bytes) -> bytes:
    raw = json.dumps(header).encode()
    raw += b" " * ((8 - len(raw) % 8) % 8)
    return struct.pack("<Q", len(raw)) + raw + payload


def gstr(s: str) -> bytes:
    b = s.encode()
    return struct.pack("<Q", len(b)) + b


def kv_str(key: str, value: str) -> bytes:
    return gstr(key) + struct.pack("<I", 8) + gstr(value)


def kv_u32(key: str, value: int) -> bytes:
    return gstr(key) + struct.pack("<II", 4, value)


def kv_str_array(key: str, items: list[str]) -> bytes:
    return gstr(key) + struct.pack("<I", 9) + struct.pack("<IQ", 8, len(items)) + b"".join(gstr(i) for i in items)


def gguf(kvs: list[bytes], n_tensors: int = 0) -> bytes:
    return b"GGUF" + struct.pack("<IQQ", 3, n_tensors, len(kvs)) + b"".join(kvs)


def varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def pb_varint(field: int, value: int) -> bytes:
    return varint(field << 3) + varint(value)


def pb_bytes(field: int, payload: bytes) -> bytes:
    return varint(field << 3 | 2) + varint(len(payload)) + payload


def pb_str(field: int, s: str) -> bytes:
    return pb_bytes(field, s.encode())


def onnx_model() -> bytes:
    def node(op: str, domain: str = "") -> bytes:
        return pb_bytes(1, pb_str(4, op) + (pb_str(7, domain) if domain else b""))

    ext = pb_bytes(13, pb_str(1, "location") + pb_str(2, "../../etc/passwd"))
    ok_ext = pb_bytes(13, pb_str(1, "location") + pb_str(2, "weights.bin"))
    init_bad = pb_bytes(5, pb_str(8, "w") + pb_varint(14, 1) + ext)
    init_ok = pb_bytes(5, pb_str(8, "b") + pb_varint(14, 1) + ok_ext)
    graph = node("Relu") + node("EvilOp", "com.evil") + node("FusedGemm", "com.microsoft") + init_bad + init_ok
    opset = pb_bytes(8, pb_str(1, "") + pb_varint(2, 17)) + pb_bytes(8, pb_str(1, "com.evil") + pb_varint(2, 1))
    return pb_varint(1, 8) + pb_str(2, "unit-test") + opset + pb_bytes(7, graph)


def keras_zip(config: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("metadata.json", json.dumps({"keras_version": "3.5.0"}))
        zf.writestr("config.json", json.dumps(config))
        zf.writestr("model.weights.h5", b"\x89HDF\r\n\x1a\n" + b"\x00" * 32)
    return buf.getvalue()


def keras_config(layer: dict) -> dict:
    return {
        "module": "keras",
        "class_name": "Sequential",
        "config": {
            "name": "seq",
            "layers": [{"module": "keras.layers", "class_name": "InputLayer", "config": {"batch_shape": [None, 4]}}, layer],
        },
    }


def lambda_layer(code: bytes) -> dict:
    return {
        "module": "keras.layers",
        "class_name": "Lambda",
        "config": {
            "name": "lambda",
            "function": {"class_name": "__lambda__", "config": {"code": base64.b64encode(code).decode(), "defaults": None, "closure": None}},
        },
    }


def rule_ids(findings) -> list[str]:
    return sorted(f.rule_id for f in findings)


def by_rule(findings, rule_id: str):
    return [f for f in findings if f.rule_id == rule_id]


# --------------------------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------------------------


class ModelFilesTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def scan(self, name: str, payload: bytes):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        comp, findings = modelfiles.analyze_model_file(path, self.root)
        # Everything the analyzer returns must serialise (reporters emit it as JSON).
        json.dumps([f.to_dict() for f in findings])
        if comp is not None:
            json.dumps(comp.to_dict())
            for f in findings:
                self.assertIs(f.component, comp)
                self.assertEqual(f.location.path, comp.properties["path"])
        else:
            self.assertEqual(findings, [])
        return comp, findings

    # --- API surface / data ------------------------------------------------------------------

    def test_extensions_and_candidates(self):
        expected = {".pt", ".pth", ".bin", ".ckpt", ".pkl", ".pickle", ".joblib", ".safetensors", ".gguf",
                    ".onnx", ".h5", ".hdf5", ".keras", ".tflite", ".mar", ".pte", ".npy", ".npz"}
        self.assertEqual(set(modelfiles.MODEL_EXTENSIONS), expected)
        for ext in expected:
            self.assertTrue(modelfiles.is_model_candidate(Path("dir") / ("model" + ext.upper())))
        self.assertTrue(modelfiles.is_model_candidate(Path("clf.joblib.gz")))
        self.assertTrue(modelfiles.is_model_candidate(Path("clf.pkl.z")))
        self.assertFalse(modelfiles.is_model_candidate(Path("notes.txt")))
        self.assertFalse(modelfiles.is_model_candidate(Path("archive.tar.gz")))
        self.assertFalse(modelfiles.is_model_candidate(Path("Makefile")))
        covered = {e for f in data.load("model-rules.json")["formats"] for e in f["extensions"]}
        self.assertEqual(covered, expected)

    def test_rules_file_is_honest_and_complete(self):
        raw = data.load("model-rules.json")
        for rid, meta in raw["rules"].items():
            with self.subTest(rule=rid):
                self.assertIn(meta["severity"], SEVERITIES)
                self.assertIn("fp_rate_measured", meta["quality"])
                self.assertIsNone(meta["quality"]["fp_rate_measured"])
                self.assertTrue(meta["description"])
                self.assertTrue(meta["remediation"])
        src = Path(modelfiles.__file__).read_text(encoding="utf-8")
        used = set(re.findall(r'"(ait\.model\.[a-z0-9.\-]+)"', src))
        self.assertGreaterEqual(len(used), 10)
        self.assertLessEqual(used, set(raw["rules"]))

    # --- pickle ------------------------------------------------------------------------------

    def test_safe_pickle_gets_one_info_finding(self):
        payload = pickle.dumps(OrderedDict(a=1, b=[1, 2]), protocol=2)
        comp, findings = self.scan("models/weights.pkl", payload)
        self.assertEqual(comp.ctype, "model-file")
        self.assertEqual(comp.name, "weights.pkl")
        self.assertEqual(comp.source, "file")
        self.assertTrue(comp.ai)
        self.assertEqual(comp.locations[0].path, "models/weights.pkl")
        self.assertEqual(comp.hashes, {"sha256": hashlib.sha256(payload).hexdigest()})
        self.assertEqual(comp.properties["path"], "models/weights.pkl")
        self.assertEqual(comp.properties["format"], "pickle")
        self.assertEqual(comp.properties["size"], len(payload))
        self.assertEqual(comp.properties["pickle_protocol"], 2)
        self.assertIn("collections.OrderedDict", comp.properties["pickle_globals"])
        self.assertEqual(rule_ids(findings), ["ait.model.pickle.format"])
        self.assertEqual(findings[0].severity, "info")

    def test_global_os_system_reduce_is_critical(self):
        comp, findings = self.scan("model.pt", OS_SYSTEM_P0)
        self.assertEqual(comp.properties["format"], "pickle")
        dangerous = by_rule(findings, "ait.model.pickle.dangerous-global")
        self.assertEqual(len(dangerous), 1)
        f = dangerous[0]
        self.assertEqual((f.severity, f.verdict), ("critical", "malicious"))
        self.assertEqual(f.maps_to, [OWASP_SUPPLY_CHAIN, OWASP_POISONING])
        ev = f.evidence[0].to_dict()
        self.assertEqual(ev["callable"], "os.system")
        self.assertEqual(ev["opcode"], "GLOBAL")
        self.assertEqual(ev["offset"], 0)
        self.assertTrue(ev["invoked"])
        self.assertEqual(ev["category"], "os-command")
        self.assertNotIn("ait.model.pickle.format", rule_ids(findings))

    def test_stack_global_resolved_through_memo(self):
        p = b"\x80\x04"
        p += sbu("os") + b"\x94"  # MEMOIZE -> memo[0]
        p += sbu("system") + b"\x94"  # MEMOIZE -> memo[1]
        p += b"00"  # POP both
        p += sbu("collections") + sbu("OrderedDict") + b"00"  # decoys a naive look-back would pick
        p += b"h\x00h\x01"  # BINGET 0, BINGET 1
        offset = len(p)
        p += b"\x93" + sbu("id") + b"\x85R."  # STACK_GLOBAL, TUPLE1, REDUCE, STOP
        comp, findings = self.scan("model.pkl", p)
        dangerous = by_rule(findings, "ait.model.pickle.dangerous-global")
        self.assertEqual(len(dangerous), 1)
        ev = dangerous[0].evidence[0].to_dict()
        self.assertEqual((ev["callable"], ev["opcode"], ev["offset"]), ("os.system", "STACK_GLOBAL", offset))
        self.assertEqual(comp.properties["pickle_globals"], ["os.system"])

    def test_two_dangerous_callables_have_distinct_fingerprints(self):
        p = b"\x80\x02" + glob("posix", "system") + sbs("id") + b"\x85R0"
        p += glob("subprocess", "Popen") + sbs("id") + b"\x85R."
        _comp, findings = self.scan("model.bin", p)
        dangerous = by_rule(findings, "ait.model.pickle.dangerous-global")
        self.assertEqual(sorted(f.evidence[0].detail["callable"] for f in dangerous), ["posix.system", "subprocess.Popen"])
        self.assertEqual(len({f.fingerprint for f in dangerous}), 2)

    def test_dotted_traversal_and_py2_alias_are_denied(self):
        p = b"\x80\x04" + glob("torch", "serialization.os.system") + sbu("id") + b"\x85R."
        _c, findings = self.scan("a.pkl", p)
        f = by_rule(findings, "ait.model.pickle.dangerous-global")[0]
        self.assertEqual(f.evidence[0].detail["resolves_to"], "os.system")

        _c, findings = self.scan("b.pkl", b"c__builtin__\neval\n(S'1+1'\ntR.")
        f = by_rule(findings, "ait.model.pickle.dangerous-global")[0]
        self.assertEqual(f.evidence[0].detail["callable"], "__builtin__.eval")
        self.assertEqual(f.evidence[0].detail["resolves_to"], "builtins.eval")

    def test_unknown_globals_are_medium_and_grouped(self):
        p = b"\x80\x02" + glob("mypkg.models", "Net") + b")\x81" + glob("mypkg.layers", "Block") + b")\x81\x86."
        _c, findings = self.scan("full_model.pt", p)
        self.assertEqual(rule_ids(findings), ["ait.model.pickle.unknown-global"])
        f = findings[0]
        self.assertEqual((f.severity, f.verdict), ("medium", "suspicious"))
        self.assertEqual(sorted(e.detail["callable"] for e in f.evidence), ["mypkg.layers.Block", "mypkg.models.Net"])

    def test_unresolvable_stack_global_is_high(self):
        p = b"\x80\x04K\x01K\x02\x93)R."  # STACK_GLOBAL on two ints
        _c, findings = self.scan("x.pkl", p)
        self.assertEqual(rule_ids(findings), ["ait.model.pickle.unresolved-global"])
        self.assertEqual(findings[0].severity, "high")

    def test_large_opcode_argument_is_skipped_not_loaded(self):
        big = 2 << 20
        p = b"\x80\x04\x8e" + struct.pack("<Q", big) + b"\x00" * big + b"0"  # BINBYTES8, POP
        p += glob("posix", "system") + sbu("id") + b"\x85R."
        _c, findings = self.scan("big.pkl", p)
        self.assertEqual(rule_ids(findings), ["ait.model.pickle.dangerous-global"])

    def test_truncated_pickle_is_malformed(self):
        payload = pickle.dumps(OrderedDict(a=1, b=2), protocol=4)[:-3]
        comp, findings = self.scan("trunc.pkl", payload)
        self.assertIsNotNone(comp)
        malformed = by_rule(findings, "ait.model.malformed")
        self.assertEqual(len(malformed), 1)
        self.assertEqual(malformed[0].evidence[0].detail["issue"], "pickle-parse")

    def test_pickle_disguised_as_safetensors(self):
        comp, findings = self.scan("model.safetensors", OS_SYSTEM_P0)
        self.assertEqual(comp.properties["format"], "pickle")
        self.assertTrue(comp.properties["extension_mismatch"])
        self.assertIn("ait.model.pickle.dangerous-global", rule_ids(findings))
        issues = [f.evidence[0].detail["issue"] for f in by_rule(findings, "ait.model.malformed")]
        self.assertEqual(issues, ["extension-mismatch"])

    # --- PyTorch -----------------------------------------------------------------------------

    def test_torch_zip_safe(self):
        comp, findings = self.scan("pytorch_model.bin", torch_zip(torch_data_pkl()))
        self.assertEqual(comp.properties["format"], "pytorch-zip")
        self.assertEqual(comp.properties["archive_name"], "archive")
        self.assertEqual(comp.properties["torch_serialization_version"], 3)
        self.assertEqual(comp.properties["pickle_members"], ["archive/data.pkl"])
        self.assertEqual(rule_ids(findings), ["ait.model.pickle.format"])

    def test_torch_zip_malicious_member(self):
        evil = glob("posix", "system") + sbs("id") + b"\x85R0"
        comp, findings = self.scan("model.pt", torch_zip(torch_data_pkl(evil)))
        self.assertEqual(comp.properties["format"], "pytorch-zip")
        f = by_rule(findings, "ait.model.pickle.dangerous-global")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].evidence[0].detail["member"], "archive/data.pkl")
        self.assertEqual(f[0].evidence[0].detail["callable"], "posix.system")

    def test_zip_crc_mismatch_still_analysed(self):
        evil = glob("posix", "system") + sbs("id") + b"\x85R0"
        blob = bytearray(torch_zip(torch_data_pkl(evil)))
        i = blob.find(b"PK\x01\x02")  # first central-directory entry: archive/data.pkl
        blob[i + 16: i + 20] = bytes(b ^ 0xFF for b in blob[i + 16: i + 20])
        _c, findings = self.scan("model.pt", bytes(blob))
        self.assertIn("ait.model.pickle.dangerous-global", rule_ids(findings))
        issues = [f.evidence[0].detail["issue"] for f in by_rule(findings, "ait.model.malformed")]
        self.assertEqual(issues, ["zip-crc"])

    def test_legacy_torch_multi_pickle(self):
        magic = b"\x80\x02\x8a\x0a" + (0x1950A86A20F9469CFC6C).to_bytes(10, "little") + b"."
        version = b"\x80\x02M\xe9\x03."  # BININT2 1001
        sys_info = pickle.dumps({"protocol_version": 1001, "little_endian": True}, protocol=2)
        main = evil_p2()
        keys = pickle.dumps(["0"], protocol=2)
        storage = struct.pack("<q", 0x0280) + b"\x00" * 64  # raw storage: starts with bytes 80 02
        comp, findings = self.scan("legacy.pt", magic + version + sys_info + main + keys + storage)
        self.assertEqual(comp.properties["format"], "pytorch-legacy")
        self.assertEqual(comp.properties["pickle_count"], 5)
        f = by_rule(findings, "ait.model.pickle.dangerous-global")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].evidence[0].detail["pickle"], 3)
        self.assertEqual(by_rule(findings, "ait.model.malformed"), [])

    def test_pickles_past_the_stream_cap_are_reported(self):
        # loaders may read every pickle in a stream; one past the cap is unknown, not clean
        cap = data.load("model-rules.json")["limits"]["max_pickles_per_stream"]
        payload = pickle.dumps(1, protocol=2) * cap + evil_p2()
        _c, findings = self.scan("many.pkl", payload)
        gaps = by_rule(findings, "ait.model.not-analysable")
        self.assertEqual([f.evidence[0].detail["issue"] for f in gaps], ["pickle-incomplete"])

    def test_zip_slip(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("archive/data.pkl", torch_data_pkl())
            zf.writestr(zipfile.ZipInfo("../../evil.sh"), "echo")
            zf.writestr(zipfile.ZipInfo("C:/Windows/evil.dll"), "x")
        _c, findings = self.scan("model.pth", buf.getvalue())
        slip = by_rule(findings, "ait.model.zip-slip")
        self.assertEqual(len(slip), 1)
        self.assertEqual(slip[0].severity, "high")
        self.assertEqual(sorted(slip[0].evidence[0].detail["members"]), ["../../evil.sh", "C:/Windows/evil.dll"])

    # --- joblib ------------------------------------------------------------------------------

    def test_joblib_legacy_zlib(self):
        payload = evil_p2()
        blob = b"ZF" + ("0x%x" % len(payload)).ljust(9).encode() + zlib.compress(payload)
        comp, findings = self.scan("model.joblib", blob)
        self.assertEqual(comp.properties["format"], "joblib")
        self.assertEqual(comp.properties["compression"], "zlib-legacy")
        f = by_rule(findings, "ait.model.pickle.dangerous-global")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].evidence[0].detail["stream"], "zlib-legacy-decompressed")

    def test_joblib_zlib_array_payload_is_skipped(self):
        tail = glob("posix", "system") + sbu("id") + b"\x85R0."
        comp, findings = self.scan("clf.joblib", zlib.compress(joblib_array_stream(tail)))
        self.assertEqual(comp.properties["format"], "joblib")
        self.assertEqual(comp.properties["compression"], "zlib")
        # The dangerous global sits *after* the raw array bytes: finding it proves the skip.
        self.assertEqual(rule_ids(findings), ["ait.model.pickle.dangerous-global"])

    def test_joblib_uncompressed_safe(self):
        comp, findings = self.scan("clf.pkl", joblib_array_stream(b"0" + glob("collections", "OrderedDict") + b")R."))
        self.assertEqual(comp.properties["format"], "joblib")
        self.assertEqual(rule_ids(findings), ["ait.model.pickle.format"])

    def test_lz4_is_not_analysable(self):
        comp, findings = self.scan("model.joblib", b"\x04\x22\x4d\x18" + b"\x00" * 32)
        self.assertEqual(comp.properties["compression"], "lz4")
        self.assertEqual(rule_ids(findings), ["ait.model.not-analysable"])
        self.assertNotIn("ait.model.pickle.format", rule_ids(findings))

    # --- numpy -------------------------------------------------------------------------------

    def test_object_npy_payload_is_walked(self):
        payload = b"\x80\x03" + glob("posix", "system") + sbs("id") + b"\x85R."
        comp, findings = self.scan("arr.npy", npy("|O", (2,), payload))
        self.assertEqual(comp.properties["format"], "numpy-npy")
        self.assertTrue(comp.properties["object_dtype"])
        self.assertEqual(rule_ids(findings), ["ait.model.pickle.dangerous-global"])

    def test_plain_npy_and_npz_inventory(self):
        plain = npy("<f8", (2,), struct.pack("<2d", 1.0, 2.0))
        comp, findings = self.scan("arr.npy", plain)
        self.assertFalse(comp.properties["object_dtype"])
        self.assertEqual(comp.properties["shape"], [2])
        self.assertEqual(findings, [])

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("arr_0.npy", plain)
            zf.writestr("arr_1.npy", npy("|O", (1,), evil_p2()))
        comp, findings = self.scan("arrays.npz", buf.getvalue())
        self.assertEqual(comp.properties["format"], "numpy-npz")
        self.assertEqual(comp.properties["object_arrays"], ["arr_1.npy"])
        f = by_rule(findings, "ait.model.pickle.dangerous-global")
        self.assertEqual(f[0].evidence[0].detail["member"], "arr_1.npy")

    # --- safetensors -------------------------------------------------------------------------

    def test_safetensors_valid(self):
        header = {
            "__metadata__": {"format": "pt", "license": "apache-2.0"},
            "w": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]},
            "b": {"dtype": "BF16", "shape": [2], "data_offsets": [16, 20]},
        }
        comp, findings = self.scan("model.safetensors", safetensors(header, b"\x00" * 20))
        self.assertEqual(findings, [])
        self.assertEqual(comp.properties["format"], "safetensors")
        self.assertTrue(comp.properties["safe_by_format"])
        self.assertEqual(comp.properties["tensor_count"], 2)
        self.assertEqual(comp.properties["parameter_count"], 6)
        self.assertEqual(comp.properties["dtypes"], {"BF16": 1, "F32": 1})
        self.assertEqual(comp.properties["metadata"]["format"], "pt")
        self.assertEqual(comp.licence, "apache-2.0")

    def test_safetensors_corrupt_header(self):
        cases = {
            "bounds.safetensors": struct.pack("<Q", 10_000) + b'{"a": 1}',
            "json.safetensors": struct.pack("<Q", 8) + b"{not js}" + b"\x00" * 4,
            "offsets.safetensors": safetensors({"w": {"dtype": "F32", "shape": [4], "data_offsets": [0, 64]}}, b"\x00" * 16),
        }
        expected = {
            "bounds.safetensors": "safetensors-header-bounds",
            "json.safetensors": "safetensors-header-json",
            "offsets.safetensors": "safetensors-header-content",
        }
        for name, blob in cases.items():
            with self.subTest(name=name):
                comp, findings = self.scan(name, blob)
                self.assertEqual(comp.properties["format"], "safetensors")
                self.assertEqual(rule_ids(findings), ["ait.model.malformed"])
                self.assertEqual(findings[0].evidence[0].detail["issue"], expected[name])

    # --- GGUF --------------------------------------------------------------------------------

    def test_gguf_metadata_and_malicious_chat_template(self):
        evil = "{{ ''.__class__.__mro__[1].__subclasses__()[40]('id', shell=True) }}"
        blob = gguf([
            kv_str("general.architecture", "llama"),
            kv_str("general.name", "tiny"),
            kv_str("general.license", "mit"),
            kv_u32("general.quantization_version", 2),
            kv_str_array("tokenizer.ggml.tokens", ["<s>", "</s>", "a"]),
            kv_str("tokenizer.chat_template", evil),
        ], n_tensors=3)
        comp, findings = self.scan("tiny.gguf", blob)
        self.assertEqual(comp.properties["format"], "gguf")
        self.assertEqual(comp.properties["gguf_version"], 3)
        self.assertEqual(comp.properties["tensor_count"], 3)
        self.assertEqual(comp.properties["kv_count"], 6)
        self.assertEqual(comp.properties["architecture"], "llama")
        self.assertEqual(comp.properties["metadata"]["general.name"], "tiny")
        self.assertEqual(comp.properties["metadata"]["general.quantization_version"], 2)
        self.assertEqual(comp.licence, "mit")
        self.assertEqual(rule_ids(findings), ["ait.model.gguf.chat-template-ssti"])
        f = findings[0]
        self.assertEqual(f.severity, "high")
        self.assertIn("__subclasses__", f.evidence[0].detail["markers"])
        self.assertIn("CVE-2024-34359", f.evidence[0].url)

    def test_gguf_benign_template_and_truncation(self):
        tpl = "{% for m in messages %}<|{{ m['role'] }}|>{{ m['content'] }}\n{% endfor %}"
        blob = gguf([kv_str("general.architecture", "llama"), kv_str("tokenizer.chat_template", tpl)])
        comp, findings = self.scan("ok.gguf", blob)
        self.assertEqual(findings, [])
        self.assertTrue(comp.properties["chat_template_present"])
        comp, findings = self.scan("cut.gguf", blob[:-10])
        self.assertEqual(rule_ids(findings), ["ait.model.malformed"])

    # --- ONNX --------------------------------------------------------------------------------

    def test_onnx_custom_domain_and_external_data(self):
        comp, findings = self.scan("model.onnx", onnx_model())
        props = comp.properties
        self.assertEqual(props["format"], "onnx")
        self.assertEqual(props["ir_version"], 8)
        self.assertEqual(props["producer_name"], "unit-test")
        self.assertEqual(props["node_count"], 3)
        self.assertEqual(props["op_domains"], ["ai.onnx", "com.evil", "com.microsoft"])
        self.assertEqual(props["external_data_files"], ["../../etc/passwd", "weights.bin"])
        custom = by_rule(findings, "ait.model.onnx.custom-op-domain")
        self.assertEqual([f.evidence[0].detail["domain"] for f in custom], ["com.evil"])
        self.assertEqual(custom[0].severity, "medium")
        self.assertEqual(custom[0].evidence[0].detail["op_types"], ["EvilOp"])
        vendor = by_rule(findings, "ait.model.onnx.vendor-op-domain")
        self.assertEqual([f.evidence[0].detail["domain"] for f in vendor], ["com.microsoft"])
        ext = by_rule(findings, "ait.model.onnx.external-data-path")
        self.assertEqual(len(ext), 1)
        self.assertEqual(ext[0].severity, "high")
        self.assertEqual([e.detail["location"] for e in ext[0].evidence], ["../../etc/passwd"])

    def test_onnx_garbage_is_malformed(self):
        comp, findings = self.scan("broken.onnx", b"\x08\x08\x3a\xff\xff\xff\x0f")
        self.assertEqual(comp.properties["format"], "onnx")
        self.assertEqual(rule_ids(findings), ["ait.model.malformed"])

    # --- Keras / HDF5 ------------------------------------------------------------------------

    def test_keras_lambda_layer(self):
        comp, findings = self.scan("model.keras", keras_zip(keras_config(lambda_layer(b"\xe3fake-code-object"))))
        self.assertEqual(comp.properties["format"], "keras")
        self.assertEqual(comp.properties["keras_version"], "3.5.0")
        self.assertEqual(comp.properties["lambda_layers"], 1)
        self.assertEqual(rule_ids(findings), ["ait.model.keras.lambda-layer"])
        self.assertEqual((findings[0].severity, findings[0].verdict), ("high", "suspicious"))

        _c, findings = self.scan("bad.keras", keras_zip(keras_config(lambda_layer(b"\xe3\xda\x02os\xda\x06system"))))
        self.assertEqual((findings[0].severity, findings[0].verdict), ("critical", "malicious"))
        self.assertEqual(findings[0].evidence[0].detail["code_tokens"], ["system"])

    def test_keras_config_dangerous_callable(self):
        layer = {"module": "os", "class_name": "function", "config": "system", "registered_name": "function"}
        _c, findings = self.scan("rce.keras", keras_zip(keras_config(layer)))
        self.assertEqual(rule_ids(findings), ["ait.model.keras.dangerous-callable"])
        self.assertEqual(findings[0].evidence[0].detail["callable"], "os.system")
        self.assertEqual(findings[0].severity, "critical")

    def test_hdf5_lambda_byte_search(self):
        code = base64.b64encode(b"\xe3fake-code-object").decode()
        cfg = {"class_name": "Sequential", "config": {"layers": [
            {"class_name": "Lambda", "config": {"name": "lambda", "function": [code, None, None], "function_type": "lambda"}}
        ]}}
        blob = b"\x89HDF\r\n\x1a\n" + b"\x00" * 64 + b"keras_version\x002.12.0\x00model_config\x00"
        blob += json.dumps(cfg).encode() + b"\x00" * 64
        comp, findings = self.scan("model.h5", blob)
        self.assertEqual(comp.properties["format"], "keras-h5")
        self.assertEqual(comp.properties["detection"], "bounded-byte-search")
        self.assertEqual(comp.properties["lambda_layers"], 1)
        self.assertEqual(rule_ids(findings), ["ait.model.keras.lambda-layer"])

        comp, findings = self.scan("data.h5", b"\x89HDF\r\n\x1a\n" + b"\x00" * 128)
        self.assertEqual(comp.properties["format"], "hdf5")
        self.assertEqual(findings, [])

    # --- TorchServe / TFLite / ExecuTorch ----------------------------------------------------

    def test_mar_handler_and_nested_model(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            manifest = {"runtime": "python", "model": {"modelName": "m", "serializedFile": "model.pt", "handler": "handler.py"}}
            zf.writestr("MAR-INF/MANIFEST.json", json.dumps(manifest))
            zf.writestr("handler.py", "def handle(data, context):\n    return data\n")
            zf.writestr("model.pt", OS_SYSTEM_P0)
        comp, findings = self.scan("m.mar", buf.getvalue())
        self.assertEqual(comp.properties["format"], "torchserve-mar")
        self.assertEqual(comp.properties["mar_handler"], "handler.py")
        self.assertEqual(comp.properties["nested_models"], [{"member": "model.pt", "format": "pickle"}])
        self.assertEqual(rule_ids(findings), ["ait.model.mar.handler-code", "ait.model.pickle.dangerous-global"])
        dangerous = by_rule(findings, "ait.model.pickle.dangerous-global")[0]
        self.assertEqual(dangerous.evidence[0].detail["member"], "model.pt")
        self.assertEqual(by_rule(findings, "ait.model.mar.handler-code")[0].severity, "info")

    def test_tflite_and_pte_inventory(self):
        comp, findings = self.scan("m.tflite", b"\x00\x00\x00\x00TFL3" + b"\x00" * 64)
        self.assertEqual((comp.properties["format"], comp.properties["format_confidence"]), ("tflite", "magic"))
        self.assertEqual(findings, [])
        comp, findings = self.scan("m.pte", b"\x1c\x00\x00\x00ET12" + b"\x00" * 64)
        self.assertEqual(comp.properties["format"], "executorch")
        self.assertEqual(comp.properties["format_confidence"], "extension-only")
        self.assertEqual(comp.properties["flatbuffer_identifier"], "ET12")
        self.assertEqual(findings, [])

    # --- not a model / robustness ------------------------------------------------------------

    def test_random_bin_is_not_a_model(self):
        blob = b"\x00\x01\x02\x03" + random.Random(1234).randbytes(4092)
        self.assertEqual(self.scan("random.bin", blob), (None, []))
        self.assertEqual(self.scan("text.bin", b"hello world, not a model\n" * 20), (None, []))
        self.assertEqual(self.scan("empty.pt", b""), (None, []))

    def test_truncated_containers_never_raise(self):
        samples = {
            "t.pt": torch_zip(torch_data_pkl()),
            "m.gguf": gguf([kv_str("general.name", "x"), kv_str("tokenizer.chat_template", "{{ x }}")]),
            "m.safetensors": safetensors({"w": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]}}, b"\x00" * 8),
            "m.onnx": onnx_model(),
            "a.npy": npy("|O", (1,), evil_p2()),
            "m.joblib": zlib.compress(joblib_array_stream(b"0.")),
            "m.keras": keras_zip(keras_config(lambda_layer(b"x"))),
            "legacy.pt": b"\x80\x02\x8a\x0a" + (0x1950A86A20F9469CFC6C).to_bytes(10, "little") + b"." + evil_p2(),
        }
        for name, blob in samples.items():
            for cut in sorted({1, 3, 7, 9, 16, 40, len(blob) // 3, len(blob) // 2, len(blob) - 1}):
                with self.subTest(name=name, cut=cut):
                    comp, _findings = self.scan(name, blob[:cut])
                    if comp is not None:
                        self.assertEqual(comp.ctype, "model-file")

    # --- resource caps: they may cost precision but must never hide anything -----------------

    def limits(self, **overrides):
        return mock.patch.dict(modelfiles._compiled_rules().limits, overrides)

    def test_memo_cap_turns_memo_resolved_import_into_unresolved(self):
        p = b"\x80\x04" + sbu("os") + b"\x94" + sbu("system") + b"\x94" + b"00"
        p += b"h\x00h\x01\x93" + sbu("id") + b"\x85R."  # BINGET 0, BINGET 1, STACK_GLOBAL
        with self.limits(max_memo_entries=1):
            _c, findings = self.scan("memo.pkl", p)
        self.assertEqual(rule_ids(findings), ["ait.model.pickle.unresolved-global"])

    def test_string_budget_keeps_identifiers_then_reports_unresolved(self):
        filler = b"".join(sbu(f"filler text {i}!") + b"0" for i in range(20))
        p = b"\x80\x04" + filler + sbu("os") + sbu("system") + b"\x93" + sbu("id") + b"\x85R."
        with self.limits(max_tracked_string_bytes=64):  # filler spends it; identifiers still kept
            _c, findings = self.scan("s1.pkl", p)
        self.assertIn("ait.model.pickle.dangerous-global", rule_ids(findings))
        with self.limits(max_tracked_string_bytes=4):  # both allowances spent
            _c, findings = self.scan("s2.pkl", p)
        self.assertEqual(rule_ids(findings), ["ait.model.pickle.unresolved-global"])

    def test_compression_ratio_caps_decompression(self):
        p = b"\x80\x04\x8e" + struct.pack("<Q", 1 << 20) + b"\x00" * (1 << 20) + b"0"  # BINBYTES8, POP
        p += glob("posix", "system") + sbu("id") + b"\x85R."
        blob = zlib.compress(p, 9)
        self.assertLess(len(blob) * 200, len(p))
        with self.limits(compression_ratio_floor_bytes=0):
            comp, findings = self.scan("bomb.pkl.z", blob)
        self.assertEqual(rule_ids(findings), ["ait.model.not-analysable", "ait.model.pickle.format"])
        self.assertEqual(by_rule(findings, "ait.model.not-analysable")[0].evidence[0].detail["issue"], "pickle-incomplete")
        self.assertEqual(comp.properties["format"], "pickle")
        _c, findings = self.scan("bomb.pkl.z", blob)  # default floor: small files still open
        self.assertEqual(rule_ids(findings), ["ait.model.pickle.dangerous-global"])

    def test_oversized_or_surplus_gguf_templates_are_reported_unchecked(self):
        evil = "{{ cycler.__init__.__globals__.os.popen('id').read() }}"
        key = "tokenizer.chat_template"
        blob = gguf([kv_str(key, "ok"), kv_str(key + ".big", "x" * 100 + evil), kv_str(key + ".extra", evil)])
        with self.limits(max_gguf_template_bytes=64, max_gguf_templates=1):  # one too large, one surplus
            comp, findings = self.scan("big.gguf", blob)
        self.assertEqual(rule_ids(findings), ["ait.model.not-analysable"])
        detail = findings[0].evidence[0].detail
        self.assertEqual((detail["issue"], detail["count"]), ("gguf-template-unchecked", 2))
        self.assertTrue(comp.properties["chat_template_present"])

    def test_obfuscated_dunder_template_is_flagged(self):
        tpl = "{{ (lipsum|attr('__glo' ~ 'bals__'))['o' ~ 's'] }}"
        _c, findings = self.scan("obf.gguf", gguf([kv_str("tokenizer.chat_template", tpl)]))
        self.assertEqual(rule_ids(findings), ["ait.model.gguf.chat-template-ssti"])
        self.assertEqual(set(findings[0].evidence[0].detail["markers"]), {"attr-filter", "dunder-fragment"})

    def test_huge_safetensors_header_is_not_parsed(self):
        blob = safetensors({"w": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]}}, b"\x00" * 8)
        with self.limits(max_safetensors_header_parse_bytes=16):
            comp, findings = self.scan("h.safetensors", blob)
        self.assertEqual(rule_ids(findings), ["ait.model.not-analysable"])
        self.assertTrue(comp.properties["safe_by_format"])
        self.assertNotIn("tensor_count", comp.properties)


if __name__ == "__main__":
    unittest.main()
