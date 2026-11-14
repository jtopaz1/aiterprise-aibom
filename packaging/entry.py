"""Entry point for the single-file binaries built by PyInstaller (packaging/aiterprise-scan.spec)."""

import sys

from aiterprise_scan.cli import main

if __name__ == "__main__":
    sys.exit(main())
