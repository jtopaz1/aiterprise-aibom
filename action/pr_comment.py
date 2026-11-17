"""Post the scan's Markdown report as one pull-request comment, updated on every run (C42).

    python pr_comment.py aiterprise-report/report.md

Environment: GITHUB_TOKEN, GITHUB_REPOSITORY (owner/name), PR_NUMBER, GITHUB_API_URL. Stdlib only:
it runs before or without the scanner's own environment.

The comment is found again by the report's marker and by its author: the token's own login, or
`github-actions[bot]` for the Actions token, which may not read `/user`. A comment that carries the
marker but was written by anyone else is never edited. Whatever goes wrong, this exits 0 with a
`::warning::`: a pull request from a fork gets a read-only token, and the gate is the scan's exit
code, not the comment.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

MARKER = "<!-- aiterprise-scan report -->"
ACTIONS_BOT = "github-actions[bot]"
MAX_BODY = 65536  # GitHub's limit on a comment body, in characters
MAX_PAGES = 30
CUT_NOTE = "\n\n…the report was cut to fit a comment; the job summary and the SARIF upload have all of it.\n"

Request = Callable[[str, str, Any], "tuple[int, Any]"]


def _warn(msg: str) -> int:
    print(f"::warning::aiterprise-scan PR comment: {msg}")
    return 0


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # never carry the token to another URL
        return None


def _http(token: str) -> Request:
    opener = urllib.request.build_opener(_NoRedirect)

    def request(method: str, url: str, payload: Any = None) -> tuple[int, Any]:
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "aiterprise-scan-action",
            **({"Content-Type": "application/json"} if data is not None else {}),
        })
        try:
            with opener.open(req, timeout=30) as resp:
                raw = resp.read()
                return resp.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            return exc.code, None

    return request


def _fit(body: str) -> str:
    if not body.startswith(MARKER):
        body = f"{MARKER}\n{body}"
    if len(body) <= MAX_BODY:
        return body
    cut = body[: MAX_BODY - len(CUT_NOTE)]
    return cut[: cut.rfind("\n") + 1].rstrip("\n") + CUT_NOTE


def _own_comment(request: Request, api: str, repo: str, pr: str, me: str) -> int | None:
    for page in range(1, MAX_PAGES + 1):
        status, comments = request("GET", f"{api}/repos/{repo}/issues/{pr}/comments?per_page=100&page={page}")
        if status != 200 or not isinstance(comments, list):
            return None
        for c in comments:
            user = c.get("user") or {}
            if user.get("login") == me and MARKER in (c.get("body") or ""):
                return c.get("id")
        if len(comments) < 100:
            return None
    return None


def publish(body: str, env: dict[str, str], request: Request | None = None) -> int:
    token = env.get("GITHUB_TOKEN") or ""
    repo = env.get("GITHUB_REPOSITORY") or ""
    pr = env.get("PR_NUMBER") or ""
    api = (env.get("GITHUB_API_URL") or "https://api.github.com").rstrip("/")
    if not token:
        return _warn("no token; set the `github-token` input")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo) or ".." in repo:
        return _warn("GITHUB_REPOSITORY is not owner/name")
    if not pr.isdigit():
        return _warn("not a pull_request event; nothing to comment on")
    if not api.startswith("https://"):
        return _warn("GITHUB_API_URL is not https")
    request = request or _http(token)
    status, user = request("GET", f"{api}/user")
    me = user.get("login") if status == 200 and isinstance(user, dict) and user.get("login") else ACTIONS_BOT
    body = _fit(body)
    existing = _own_comment(request, api, repo, pr, me)
    if existing is not None:
        status, resp = request("PATCH", f"{api}/repos/{repo}/issues/comments/{existing}", {"body": body})
        done = "updated"
    else:
        status, resp = request("POST", f"{api}/repos/{repo}/issues/{pr}/comments", {"body": body})
        done = "posted"
    if status not in (200, 201):
        return _warn(f"GitHub answered {status}. The workflow needs `permissions: pull-requests: write`; "
                     "a pull request from a fork gets a read-only token, so only the job summary has the report")
    url = resp.get("html_url") if isinstance(resp, dict) else None
    print(f"aiterprise-scan: {done} the pull-request comment" + (f" {url}" if url else ""))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: pr_comment.py REPORT.md", file=sys.stderr)
        return 2
    path = Path(args[0])
    if not path.is_file():
        return _warn(f"{path} was not written; the scan did not get that far")
    return publish(path.read_text(encoding="utf-8"), dict(os.environ))


if __name__ == "__main__":
    sys.exit(main())
