# PyInstaller spec: one self-contained `aiterprise-scan` binary per OS (no Python needed).
#   pyinstaller --clean --noconfirm packaging/aiterprise-scan.spec
# The binary carries the definition data under aiterprise_scan/data/ait, read through
# importlib.resources exactly as from the wheel.
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH).parent  # noqa: F821 - provided by PyInstaller
SRC = ROOT / "src"

a = Analysis(  # noqa: F821
    [str(ROOT / "packaging" / "entry.py")],
    pathex=[str(SRC)],
    datas=[(str(SRC / "aiterprise_scan" / "data" / "ait"), "aiterprise_scan/data/ait")],
    hiddenimports=collect_submodules("aiterprise_scan"),
    excludes=["tkinter", "unittest", "pydoc", "test"],
    noarchive=False,
)
pyz = PYZ(a.pure)  # noqa: F821
exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="aiterprise-scan",
    console=True,
    strip=False,
    upx=False,
)
