"""Build `src/aiterprise_scan/data/ait/kev.json` from the CISA Known Exploited Vulnerabilities catalog (CC0).

    python tools/build_kev.py --file known_exploited_vulnerabilities.json
    python tools/build_kev.py --url https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Only the fields the scanner uses are kept.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "src" / "aiterprise_scan" / "data" / "ait" / "kev.json"
CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def convert(catalog: dict) -> dict:
    cves = {}
    for v in catalog.get("vulnerabilities", []):
        cve = v.get("cveID")
        if not cve:
            continue
        cves[cve] = {
            "dateAdded": v.get("dateAdded"),
            "vendorProject": v.get("vendorProject"),
            "product": v.get("product"),
            "knownRansomwareCampaignUse": v.get("knownRansomwareCampaignUse"),
        }
    return {
        "schema": "ait-kev/1",
        "source": "CISA Known Exploited Vulnerabilities catalog",
        "licence": "CC0-1.0",
        "catalog_version": catalog.get("catalogVersion"),
        "date_released": catalog.get("dateReleased"),
        "count": len(cves),
        "cves": dict(sorted(cves.items())),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--file", type=Path)
    src.add_argument("--url", nargs="?", const=CISA_URL)
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args(argv)
    if args.file:
        catalog = json.loads(args.file.read_text(encoding="utf-8-sig"))
    else:
        req = urllib.request.Request(args.url, headers={"User-Agent": "aiterprise-scan-build"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            catalog = json.loads(resp.read().decode("utf-8-sig"))
    doc = convert(catalog)
    args.out.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {args.out}: {doc['count']} CVEs, catalog {doc['catalog_version']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
