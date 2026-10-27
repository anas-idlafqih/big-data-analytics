"""Fetch prose advisories from the GitHub Advisory Database for the selected CVEs.

Idempotent: every CVE is looked up once. A CVE with no GHSA entry is cached as an
empty list ([]), so re-running never repeats the request (GitHub's anonymous quota
is only 60 requests/hour).

Optional: set GITHUB_TOKEN (no scopes needed) to raise the quota to 5000/hour.

Usage:
    python pipeline/fetch_advisories.py
"""
import json
import logging
import os
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
MANIFEST = BASE_DIR / "data" / "manifest.json"
ADVISORIES_DIR = BASE_DIR / "data" / "raw" / "advisories"

GHA_URL = "https://api.github.com/advisories?cve_id={cve}"
USER_AGENT = "cyber-projet-academic/0.1 (student project)"
TIMEOUT = 15
REQUEST_DELAY = 1.0  # seconds between network requests
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")

log = logging.getLogger("advisories")


class RateLimited(Exception):
    """GitHub quota exhausted: stop cleanly instead of failing on every CVE."""


def write_atomic(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def request_advisories(cve: str) -> list:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    req = urllib.request.Request(GHA_URL.format(cve=cve), headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code in (403, 429) and e.headers.get("x-ratelimit-remaining") == "0":
            reset = e.headers.get("x-ratelimit-reset")
            when = datetime.fromtimestamp(int(reset)).strftime("%H:%M") if reset else "later"
            raise RateLimited(f"GitHub rate limit reached, resets around {when}") from e
        raise


def fetch_ghsa(cve: str) -> str:
    """Return 'cached', 'found', 'none' or 'error'."""
    out_file = ADVISORIES_DIR / f"{cve}_ghsa.json"
    if out_file.exists():
        log.info("%s: already cached.", cve)
        return "cached"

    log.info("%s: fetching GitHub advisory...", cve)
    try:
        data = request_advisories(cve)
    except RateLimited:
        raise
    except Exception as e:
        log.error("%s: %s", cve, e)
        return "error"
    finally:
        time.sleep(REQUEST_DELAY)

    # Cache the result even when empty, so we never ask again.
    write_atomic(out_file, json.dumps(data, indent=2, ensure_ascii=False))
    if not data:
        log.warning("%s: no GHSA entry (cached as empty).", cve)
        return "none"
    log.info("%s: %d advisory(ies) saved.", cve, len(data))
    return "found"


def main() -> None:
    ADVISORIES_DIR.mkdir(parents=True, exist_ok=True)
    if not MANIFEST.exists():
        log.error("Manifest not found. Run ingest.py first.")
        return

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    cves = [item["cve"] for item in manifest.get("selected", [])]
    if not cves:
        log.error("Manifest has no selected CVEs.")
        return

    log.info("Fetching advisories for %d CVEs...", len(cves))
    counts = {"cached": 0, "found": 0, "none": 0, "error": 0}
    try:
        for cve in cves:
            counts[fetch_ghsa(cve)] += 1
    except RateLimited as e:
        log.error("%s. Re-run later (cached CVEs are skipped) or set GITHUB_TOKEN.", e)

    log.info("Summary: %s", counts)
    with_ghsa = 0
    for c in cves:
        f = ADVISORIES_DIR / f"{c}_ghsa.json"
        if f.exists() and json.loads(f.read_text(encoding="utf-8")):
            with_ghsa += 1
    log.info("GHSA coverage: %d/%d CVEs have at least one advisory.", with_ghsa, len(cves))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    main()