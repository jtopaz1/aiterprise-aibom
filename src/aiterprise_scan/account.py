"""Account commands: `login`, `logout`, `status`, `report-fp`, `upload` (design doc 13 §4.6, §4.8).

A key is read from stdin or an interactive prompt — never from the command line, where it would
land in shell history — validated with `GET /v1/me`, and only then stored. Nothing here prints a
secret: output shows the key's prefix and last four characters.
"""

from __future__ import annotations

import argparse
import datetime as dt
import getpass
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

from . import TOOL_NAME, cloudpolicy, credentials, providers, reportdoc, secdb

CLOUD_ENV = cloudpolicy.CLOUD_ENV


def _err(msg: str) -> int:
    print(f"{TOOL_NAME}: error: {msg}", file=sys.stderr)
    return 2


def add_parsers(sub) -> None:
    login = sub.add_parser("login", help="store a SecDB API key (validated first) or register an install token")
    how = login.add_mutually_exclusive_group()
    how.add_argument("--key-stdin", action="store_true", help="read the API key from stdin (CI)")
    how.add_argument("--install", action="store_true",
                     help="register an anonymous install token instead of using an API key")
    sub.add_parser("logout", help="remove stored SecDB credentials")
    sub.add_parser("status", help="show the SecDB account, plan, limits and usage")

    fp = sub.add_parser("report-fp", help="report a false positive to AIterprise (needs your consent)")
    fp.add_argument("rule", help="rule id of the finding, e.g. ait.mcp.cmd.pipe-to-shell")
    fp.add_argument("--notes", default="", help="what is wrong with the finding (no secrets, no source code)")
    fp.add_argument("--yes", action="store_true", help="consent given: send the rule id and notes")

    up = sub.add_parser("upload", help="upload a JSON report to SecDB or an AIterprise cloud")
    up.add_argument("report", type=Path, help="report.json written by `scan --format json`")
    up.add_argument("--project", help="project name (default: the report's target directory name)")
    up.add_argument("--cloud", help=f"AIterprise cloud URL instead of SecDB (or set {CLOUD_ENV})")


def _client() -> secdb.Client:
    return secdb.Client(credentials.load())


def _show_me(me: dict) -> None:
    limits = me.get("limits") or {}
    shown = ", ".join(f"{k.replace('_', ' ')} {v}" for k, v in limits.items() if v is not None) or "fair use"
    print(f"plan: {me.get('plan', '?')} · credential: {me.get('credential', '?')}"
          + (f" · tenant {me['tenant_id']}" if me.get("tenant_id") else ""))
    print(f"limits: {shown}")
    if me.get("default_channel"):
        print(f"channel: {me['default_channel']}")


def _read_key(from_stdin: bool) -> str:
    if from_stdin or not sys.stdin.isatty():
        return sys.stdin.readline().strip()
    return getpass.getpass("SecDB API key (input hidden): ").strip()


def cmd_login(args: argparse.Namespace) -> int:
    if args.install:
        client = secdb.Client(None)
        try:
            inst = client.register_install()
        except secdb.SecDBError as err:
            return _err(str(err))
        token, install_id = inst.get("token"), inst.get("install_id")
        if not token or not install_id:
            return _err("SecDB returned no install token")
        credentials.save_install(token, install_id, str(inst.get("channel") or ""))
        print(f"install registered: {install_id} · token {credentials.mask(token)} saved")
        ent = inst.get("entitlements") or {}
        if ent.get("lookups_per_minute"):
            print(f"limits: {ent['lookups_per_minute']} lookups/min"
                  + (f", {ent['lookups_per_day']}/day" if ent.get("lookups_per_day") else ""))
        return 0
    key = _read_key(args.key_stdin)
    if not key:
        return _err("no API key given")
    if not key.startswith("aik_"):
        return _err("that is not a SecDB API key (they start with aik_)")
    try:
        me = secdb.Client(credentials.Credential("api_key", key, "stdin")).me()
    except secdb.SecDBError as err:
        return _err(f"{err} — key not saved")
    if me.get("credential") not in (None, "api_key"):
        return _err("that credential is not an API key — not saved")
    credentials.save_api_key(key)
    print(f"logged in · key {credentials.mask(key)} saved to {credentials.home()}")
    _show_me(me)
    if os.environ.get(credentials.ENV_KEY):
        print(f"note: {credentials.ENV_KEY} is set and takes precedence over the saved key")
    return 0


def cmd_logout(args: argparse.Namespace) -> int:
    removed = credentials.clear()
    print("SecDB credentials removed" if removed else "no stored SecDB credentials")
    if os.environ.get(credentials.ENV_KEY):
        print(f"note: {credentials.ENV_KEY} is still set in this environment")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    cred = credentials.load()
    if cred is None:
        print("not logged in · SecDB enrichment is off (run `aiterprise-scan login`)")
        return 0
    print(f"credential: {cred.kind} {cred.masked} ({'environment' if cred.origin == 'env' else 'stored'})")
    client = secdb.Client(cred)
    try:
        _show_me(client.me())
    except secdb.SecDBError as err:
        return _err(str(err))
    try:
        usage = client.usage()
    except secdb.SecDBError as err:
        print(f"usage: unavailable ({err.status} {err.type})".rstrip())
        return 0
    print(f"usage {usage.get('period_start', '')[:10]} → {usage.get('period_end', '')[:10]}:")
    for m in usage.get("meters") or []:
        print(f"  {m.get('meter')}: {m.get('used', 0):g} used of {m.get('included', 0):g} included"
              f" (hard stop {m.get('ceiling', 0):g})")
    return 0


CONSENT = ("This sends the rule id and your notes to AIterprise to improve the rules. It sends no source code, "
           "file contents, paths or package lists.")


def cmd_report_fp(args: argparse.Namespace) -> int:
    if providers.is_external(args.rule):
        who = providers.label_of(providers.provider_of(args.rule) or "the provider")
        return _err(f"{args.rule} is a {who} result, not an AIterprise rule: third-party provider results are "
                    f"never sent to AIterprise. Report a false positive to {who} itself.")
    cred = credentials.load()
    if cred is None:
        return _err("not logged in (run `aiterprise-scan login`)")
    print(CONSENT)
    if not args.yes:
        if not sys.stdin.isatty():
            return _err("consent needed: re-run with --yes")
        if input("Send? [y/N] ").strip().lower() not in ("y", "yes"):
            print("not sent")
            return 0
    try:
        res = _client().report("false_positive", rule_id=args.rule, notes=args.notes or None)
    except secdb.SecDBError as err:
        return _err(str(err))
    print(f"report received: {res.get('report_id', '?')} ({res.get('status', 'received')})")
    return 0


def _scanned_at(doc: dict, path: Path) -> str:
    started = doc.get("started_at") or doc.get("scanned_at")
    if isinstance(started, str) and started:
        return started
    ts = dt.datetime.fromtimestamp(path.stat().st_mtime, dt.timezone.utc)
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def upload_document(doc: dict, project: str, scanned_at: str, cloud: str | None = None) -> dict:
    """Send one report document. The client sends its upload view (`reportdoc.upload_view`): no
    local paths and no third-party provider results.

    Raises secdb.SecDBError, or cloudpolicy.CloudURLError before anything is sent."""
    cloud = cloudpolicy.cloud_url(cloud)
    client = secdb.Client(credentials.load(), base_url=cloud) if cloud else _client()
    return client.upload_scan(project, doc, scanned_at)


def cmd_upload(args: argparse.Namespace) -> int:
    try:
        doc = json.loads(args.report.read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        return _err(f"cannot read {args.report}: {err}")
    if not isinstance(doc, dict) or "findings" not in doc:
        return _err(f"{args.report} is not an aiterprise-scan JSON report")
    try:
        reportdoc.check_schema(doc)
    except reportdoc.SchemaError as err:
        return _err(f"{args.report}: {err}")
    if credentials.load() is None:
        return _err("not logged in (run `aiterprise-scan login`)")
    return report_upload(upload_document, doc, args.project or reportdoc.project_name(doc),
                         _scanned_at(doc, args.report), args.cloud)


def report_upload(send, doc: dict, project: str, scanned_at: str, cloud: str | None) -> int:
    try:
        target = cloudpolicy.cloud_url(cloud)
        res = send(doc, project, scanned_at, cloud)
    except cloudpolicy.CloudURLError as err:
        return _err(str(err))
    except secdb.SecDBError as err:
        if target:
            host = urlsplit(target).hostname
            if err.status is None:
                return _err(f"cannot reach the cloud at {host}: {err.cause}")
            if err.kind == "redirect":
                return _err(f"the cloud at {host} answered with a redirect, which is not followed: a request that "
                            "carries your key goes to one address only; use the cloud's final address")
            return _err(f"the cloud at {host} refused the upload ({err.status} {err.type}): "
                        f"{err.detail or err.title or 'no detail'}")
        if err.type == "plan_required":
            return _err(f"{err} — uploading scans needs a Pro plan or higher on SecDB; "
                        f"use --cloud with your AIterprise cloud instead")
        return _err(str(err))
    print(f"uploaded: {res.get('scan_id', '?')} · project {res.get('project', project)} · "
          f"{res.get('status', 'stored')} · {res.get('findings_new', 0)} new finding(s)", file=sys.stderr)
    # the client took BYO provider results out before sending (FD22): say how many stayed here
    for name, count in sorted(reportdoc.upload_view(doc)[1].items()):
        print(f"note: {count} {providers.label_of(name)} finding(s) kept local, not uploaded "
              "(third-party provider results are never sent to SecDB or a cloud)", file=sys.stderr)
    return 0
