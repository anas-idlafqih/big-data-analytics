"""Ingestion step: CISA KEV -> NVD CVE records.

Idempotent and reproducible:
  * every download is cached (KEV file and one JSON per CVE);
  * writes are atomic, so a failed download never leaves a corrupt file;
  * the selection is deterministic given the cached files;
  * data/manifest.json records exactly which CVEs form the corpus.

Usage:
    python pipeline/ingest.py                  # 5 usable CVEs
    python pipeline/ingest.py --count 30       # bigger corpus
    python pipeline/ingest.py --refresh        # re-download the KEV catalogue

Optional: set NVD_API_KEY (free key from NVD) to go from ~5 to ~50 requests/30s.
"""
import argparse
import csv
import hashlib
import json
import logging
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
RAW_DIR = BASE_DIR / "data" / "raw"
NVD_DIR = RAW_DIR / "nvd"
ADVISORIES_DIR = RAW_DIR / "advisories"  # reserved for vendor advisories (prose)
KEV_FILE = RAW_DIR / "kev.csv"
MANIFEST = BASE_DIR / "data" / "manifest.json"

KEV_URLS = [
    "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv",
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.csv",
]
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
USER_AGENT = "cyber-projet-academic/0.1 (student project)"
TIMEOUT = 30
MAX_RETRIES = 3
RETRY_STATUS = {403, 429, 500, 502, 503, 504}  # NVD answers 403 when rate limited
USABLE_STATUS = {"Analyzed", "Modified"}

NVD_API_KEY = os.environ.get("NVD_API_KEY")
REQUEST_DELAY = 0.7 if NVD_API_KEY else 6.5  # seconds between NVD requests

log = logging.getLogger("ingest")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def http_get(url: str, headers: dict | None = None) -> bytes:
    """GET with timeout and retries (rate limits, transient server errors)."""
    req = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, **(headers or {})}
    )
    last_err = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code not in RETRY_STATUS:
                break
        except (urllib.error.URLError, TimeoutError) as e:
            last_err = e
        wait = 10 * attempt
        log.warning("GET failed (%s), retry %d/%d in %ds", last_err, attempt, MAX_RETRIES, wait)
        time.sleep(wait)
    raise RuntimeError(f"GET failed for {url}: {last_err}")


def write_atomic(path: Path, data: bytes) -> None:
    """Write to a temp file then rename, so readers never see a partial file."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    tmp.replace(path)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --------------------------------------------------------------------------- #
# Steps
# --------------------------------------------------------------------------- #
def fetch_kev(refresh: bool) -> None:
    if KEV_FILE.exists() and not refresh:
        log.info("KEV catalogue cached: %s", KEV_FILE.name)
        return
    for url in KEV_URLS:
        try:
            data = http_get(url)
            if b"cveID" not in data[:500]:
                raise ValueError("unexpected content (no cveID header)")
            write_atomic(KEV_FILE, data)
            log.info("KEV catalogue downloaded from %s", url)
            return
        except Exception as e:  # try the next source
            log.warning("KEV source failed (%s): %s", url, e)
    raise SystemExit("Could not download the KEV catalogue from any source.")


def kev_candidates() -> list[dict]:
    """KEV rows, newest first. Sorted explicitly: we do not trust file order."""
    with open(KEV_FILE, encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    rows.sort(key=lambda r: (r["dateAdded"], r["cveID"]), reverse=True)
    return rows


def get_nvd_record(cve: str) -> dict | None:
    """Return the NVD API response for a CVE (from cache if present)."""
    path = NVD_DIR / f"{cve}.json"
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))

    log.info("Fetching %s from NVD...", cve)
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    raw = http_get(NVD_URL.format(cve=cve), headers)
    time.sleep(REQUEST_DELAY)  # respect the NVD rate limit

    data = json.loads(raw)
    if not data.get("vulnerabilities"):
        log.warning("%s: no record returned by NVD", cve)
        return None
    write_atomic(path, json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8"))
    return data


def is_usable(data: dict) -> bool:
    """Keep only CVEs that have a text description AND structured ground truth
    (affected products via CPE configurations, weaknesses via CWE)."""
    cve = data["vulnerabilities"][0]["cve"]
    return (
        cve.get("vulnStatus") in USABLE_STATUS
        and bool(cve.get("configurations"))
        and bool(cve.get("weaknesses"))
    )


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--count", type=int, default=5, help="usable CVEs to select")
    parser.add_argument("--max-candidates", type=int, default=60,
                        help="max KEV entries to examine")
    parser.add_argument("--refresh", action="store_true",
                        help="re-download the KEV catalogue")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    for d in (NVD_DIR, ADVISORIES_DIR, MANIFEST.parent):
        d.mkdir(parents=True, exist_ok=True)

    fetch_kev(args.refresh)

    selected, examined = [], 0
    for row in kev_candidates():
        if len(selected) >= args.count or examined >= args.max_candidates:
            break
        cve = row["cveID"]
        examined += 1
        try:
            data = get_nvd_record(cve)
        except Exception as e:
            log.error("%s: %s", cve, e)
            continue
        if data is None:
            continue
        if not is_usable(data):
            log.info("%s skipped (not analyzed yet / no CPE or CWE)", cve)
            continue
        selected.append({
            "cve": cve,
            "date_added": row["dateAdded"],
            "vendor": row.get("vendorProject"),
            "product": row.get("product"),
        })

    manifest = {
        "source": "CISA KEV + NVD API 2.0",
        "kev_sha256": sha256(KEV_FILE),
        "requested": args.count,
        "selected": selected,
    }
    write_atomic(MANIFEST, json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8"))

    if len(selected) < args.count:
        log.warning("Only %d/%d usable CVEs found; raise --max-candidates.",
                    len(selected), args.count)
    log.info("Done: %d CVEs selected, manifest at %s", len(selected), MANIFEST)


if __name__ == "__main__":
    main()