#!/usr/bin/env python3
"""Model-file speed against design doc 13 §5.5: a 2 GB `.safetensors` inventoried in under 5 s, and
pickle-based files walked at under 30 s per GB.

    python tools/bench_models.py [--scale F] [--check] [--work DIR] [--exe BINARY] [--json FILE]

Three files are written, then each is scanned offline by the CLI in a new process (start-up, data
loading and the report included):

    safetensors   2 GiB of tensor data behind a safetensors header            budget 2.5 s per GiB
    pytorch-zip   a `torch.save` zip: data.pkl and 1 GiB of storage           budget 30 s per GiB
    pickle        a protocol-4 pickle of a 1 GiB numpy array (BINBYTES8)      budget 30 s per GiB

Every file is read in full (its SHA-256 and SHA-1 are looked up among known-bad model files), and
the pickles are walked opcode by opcode. The data is random bytes, written just before the scan, so
it is read from the operating system's file cache; a cold read from disk adds the disk's own time.
`--scale` multiplies the sizes (0.1 for a quick look; then the 1–2 s the CLI takes to start is most
of the time, so `--check` needs the full sizes). `--check` fails (exit 1) when a scan is over
its budget, does not exit 0, reports another finding than expected (only the pickle files' info
finding about their format), or does not inventory the file as its format.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import random
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GIB = 1 << 30
BLOCK = 1 << 20
FORMATS = {"safetensors": "safetensors", "pytorch-zip": "pytorch-zip", "pickle": "pickle"}
NAMES = {"safetensors": "model.safetensors", "pytorch-zip": "model.pt", "pickle": "model.pkl"}
SIZES = {"safetensors": 2 * GIB, "pytorch-zip": GIB, "pickle": GIB}
BUDGET_S_PER_GIB = {"safetensors": 2.5, "pytorch-zip": 30.0, "pickle": 30.0}
# a pickle-based file whose callables are all known-safe still gets the info finding about its format
EXPECTED_FINDINGS = {"safetensors": [], "pytorch-zip": ["ait.model.pickle.format"],
                     "pickle": ["ait.model.pickle.format"]}


def _write_data(fh, nbytes: int, seed: int = 7) -> None:
    block = random.Random(seed).randbytes(BLOCK)
    full, rest = divmod(nbytes, BLOCK)
    for _ in range(full):
        fh.write(block)
    fh.write(block[:rest])


def _glob(module: str, name: str) -> bytes:
    return b"c" + module.encode() + b"\n" + name.encode() + b"\n"


def _str(s: str) -> bytes:
    return b"X" + struct.pack("<I", len(s)) + s.encode()


def _int(n: int) -> bytes:
    if 0 <= n < 256:
        return b"K" + bytes([n])
    if -(1 << 31) <= n < (1 << 31):
        return b"J" + struct.pack("<i", n)
    return b"\x8a\x08" + struct.pack("<q", n)


def _torch_data_pkl(nbytes: int) -> bytes:
    """data.pkl as `torch.save` writes it for {"weight": a uint8 tensor of nbytes elements}."""
    p = b"\x80\x02" + _glob("collections", "OrderedDict") + b")R"
    p += _str("weight") + _glob("torch._utils", "_rebuild_tensor_v2") + b"("
    p += b"(" + _str("storage") + _glob("torch", "ByteStorage") + _str("0") + _str("cpu") + _int(nbytes) + b"tQ"
    p += _int(0) + _int(nbytes) + b"\x85" + _int(1) + b"\x85" + b"\x89"
    p += _glob("collections", "OrderedDict") + b")Rt" + b"Rs."
    return p


def build(case: str, dest: Path, nbytes: int) -> Path:
    """Write the `case` file holding `nbytes` of tensor data into directory `dest`; return its path."""
    dest.mkdir(parents=True, exist_ok=True)
    path = dest / NAMES[case]
    if case == "safetensors":
        header = json.dumps({"weight": {"dtype": "U8", "shape": [nbytes], "data_offsets": [0, nbytes]},
                             "__metadata__": {"format": "pt"}}).encode()
        header += b" " * (-len(header) % 8)
        with open(path, "wb") as fh:
            fh.write(struct.pack("<Q", len(header)) + header)
            _write_data(fh, nbytes)
    elif case == "pytorch-zip":
        with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("archive/data.pkl", _torch_data_pkl(nbytes))
            zf.writestr("archive/byteorder", "little")
            with zf.open("archive/data/0", "w", force_zip64=True) as fh:
                _write_data(fh, nbytes)
            zf.writestr("archive/version", "3\n")
    elif case == "pickle":
        # numpy.core.multiarray._reconstruct(ndarray, (0,), b"b"), then BUILD with the array's state
        head = b"\x80\x04" + _glob("numpy.core.multiarray", "_reconstruct")
        head += b"(" + _glob("numpy", "ndarray") + _int(0) + b"\x85" + b"C\x01b" + b"tR"
        head += b"(" + _int(1) + _int(nbytes) + b"\x85"
        head += _glob("numpy", "dtype") + _str("u1") + b"\x89\x88\x87R" + b"\x89"
        head += b"\x8e" + struct.pack("<Q", nbytes)
        with open(path, "wb") as fh:
            fh.write(head)
            _write_data(fh, nbytes)
            fh.write(b"tb.")
    else:
        raise ValueError(f"unknown case {case!r}; known: {', '.join(FORMATS)}")
    return path


def _scan(path: Path, out: Path, cache: Path, exe: list[str] | None) -> tuple[float, int, dict]:
    cmd = (exe or [sys.executable, "-m", "aiterprise_scan"]) + [
        "scan", str(path), "--offline", "--format", "json", "--out", str(out)]
    env = {**os.environ, "AITERPRISE_CACHE_DIR": str(cache), "AITERPRISE_DEFS": "bundled"}
    env.pop("AITERPRISE_API_KEY", None)
    if not exe:
        env["PYTHONPATH"] = os.pathsep.join([str(ROOT / "src")] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else []))
    t = time.perf_counter()
    code = subprocess.run(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1800).returncode
    seconds = time.perf_counter() - t
    report = json.loads((out / "report.json").read_text(encoding="utf-8")) if (out / "report.json").is_file() else {}
    return seconds, code, report


def run(work: Path, sizes: dict[str, int], exe: list[str] | None = None) -> dict:
    res: dict = {"python": platform.python_version(), "platform": platform.platform(terse=True), "cases": {}}
    for case, nbytes in sizes.items():
        path = build(case, work / case, nbytes)
        try:
            seconds, code, report = _scan(path, work / f"out-{case}", work / "cache", exe)
        finally:
            path.unlink()  # one file on disk at a time
        models = [c for c in report.get("components", []) if c.get("type") == "model-file"
                  or (c.get("properties") or {}).get("format")]
        res["cases"][case] = {
            "bytes": nbytes, "seconds": round(seconds, 2), "exit": code,
            "format": (models[0].get("properties") or {}).get("format") if models else None,
            "findings": sorted({f.get("rule_id") for f in report.get("findings", [])}),
        }
    res["peak_rss_mb"] = _children_peak_rss_mb()
    return res


def _children_peak_rss_mb() -> float | None:
    """Peak resident memory of the largest scan process (Linux and macOS; None elsewhere)."""
    try:
        import resource
    except ImportError:
        return None
    peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    return round(peak / (1024 * 1024 if sys.platform == "darwin" else 1024), 1)  # bytes on macOS, KiB on Linux


def budget(case: str, nbytes: int) -> float:
    return BUDGET_S_PER_GIB[case] * nbytes / GIB


def problems(res: dict) -> list[str]:
    out = []
    for case, r in res["cases"].items():
        limit = budget(case, r["bytes"])
        if r["seconds"] > limit:
            out.append(f"{case}: {r['seconds']:.1f} s for {r['bytes'] / GIB:.2f} GiB, over the {limit:.1f} s budget")
        if r["exit"] != 0:
            out.append(f"{case}: the scan exited {r['exit']}, not 0")
        if r["format"] != FORMATS[case]:
            out.append(f"{case}: inventoried as {r['format']!r}, not {FORMATS[case]!r}")
        if r["findings"] != EXPECTED_FINDINGS[case]:
            out.append(f"{case}: findings {r['findings']}, expected {EXPECTED_FINDINGS[case]}")
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--scale", type=float, default=1.0, help="multiply the file sizes (default 1)")
    ap.add_argument("--check", action="store_true", help="fail when a scan is over budget or wrong")
    ap.add_argument("--work", type=Path, help="working directory (default: a temporary one)")
    ap.add_argument("--exe", help="scan with this executable (e.g. a release binary) instead of this checkout")
    ap.add_argument("--json", type=Path, help="also write the result to this file")
    args = ap.parse_args(argv)
    if args.check and args.scale < 1:
        ap.error("--check holds the design's sizes to its budgets; below them the start-up time dominates "
                 "(drop --scale, or --check)")
    sizes = {case: max(BLOCK, int(n * args.scale)) for case, n in SIZES.items()}
    tmp = None
    work = args.work
    if work is None:
        tmp = tempfile.TemporaryDirectory(prefix="aiterprise-bench-models-")
        work = Path(tmp.name)
    try:
        res = run(work, sizes, [args.exe] if args.exe else None)
    finally:
        if tmp is not None:
            tmp.cleanup()
    print(f"Python {res['python']}; {res['platform']}")
    for case, r in res["cases"].items():
        print(f"{case:12} {r['bytes'] / GIB:5.2f} GiB {r['seconds']:7.1f} s (budget {budget(case, r['bytes']):5.1f} s)"
              f"  exit {r['exit']}  format {r['format']}" + (f"  findings {', '.join(r['findings'])}" if r["findings"] else ""))
    if res["peak_rss_mb"] is not None:
        print(f"peak memory of a scan: {res['peak_rss_mb']:.0f} MB")
    if args.json:
        args.json.write_text(json.dumps(res, indent=2), encoding="utf-8")
    found = problems(res) if args.check else []
    for p in found:
        print(f"  FAIL  {p}")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
