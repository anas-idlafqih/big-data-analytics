"""LLM extraction: advisory text -> validated structured JSON.

For each selected CVE:
  1. build the prose input (GHSA summary + description, else NVD description,
     plus the CISA KEV one-line note);
  2. ask a local Ollama model for JSON constrained by a Pydantic schema;
  3. also extract with regex what needs no LLM (explicit CWE ids, "chained with" CVEs);
     validate (retry on failure), then apply a grounding filter: every product,
     vendor, version and CWE id must appear literally in the source text, otherwise
     it is dropped from "extraction_grounded" (the raw output stays in "extraction");
  4. save data/extracted/<model>/<CVE>.json and print the extraction next to
     the NVD ground truth.

The structured fields of NVD/GHSA (CPE, CWE) are NEVER given to the model:
they are the ground truth used for evaluation.

Idempotent: existing outputs are skipped (use --force). One folder per model,
so several models can be compared.

Usage:
    python pipeline/03_extract.py --limit 2
    python pipeline/03_extract.py
    python pipeline/03_extract.py --model qwen2.5:7b
"""
import argparse
import csv
import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

from pydantic import BaseModel, ValidationError

BASE_DIR = Path(__file__).resolve().parent.parent
MANIFEST = BASE_DIR / "data" / "manifest.json"
RAW_DIR = BASE_DIR / "data" / "raw"
NVD_DIR = RAW_DIR / "nvd"
ADV_DIR = RAW_DIR / "advisories"
KEV_FILE = RAW_DIR / "kev.csv"
OUT_ROOT = BASE_DIR / "data" / "extracted"

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
DEFAULT_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2")
MAX_CHARS = 6000
MAX_ATTEMPTS = 3
PROMPT_VERSION = "v3"  # bump when the prompt/schema changes: old outputs are then redone

log = logging.getLogger("extract")


# --------------------------------------------------------------------------- #
# Schema (all fields required, so the model always fills them)
# --------------------------------------------------------------------------- #
class Product(BaseModel):
    name: str
    vendor: str
    versions: list[str]


class Extraction(BaseModel):
    products: list[Product]
    weakness_types: list[str]


SYSTEM = """You extract structured data from security advisories.
Rules:
- Use ONLY information explicitly written in the text. Never guess or use outside knowledge.
- products: only products that ARE affected. Ignore products stated as not affected.
  name = product name as written. vendor = company name only if written in the text, else "".
  versions = version numbers or ranges exactly as written (e.g. "before 4.2.7"). Not deployment types,
  not dates. If no version is written, use [].
- weakness_types: the kind of vulnerability as written (e.g. "SQL injection", "authentication bypass").
Answer with JSON only."""

EXAMPLE_IN = (
    "CVE: CVE-0000-0000\n\nAcme WidgetServer versions 4.0 through 4.2.6 contain a stack-based buffer "
    "overflow in the license parser that lets remote attackers execute arbitrary code. "
    "The Acme Gadget Agent is not affected."
)
EXAMPLE_OUT = json.dumps({
    "products": [{"name": "WidgetServer", "vendor": "Acme", "versions": ["4.0 through 4.2.6"]}],
    "weakness_types": ["stack-based buffer overflow"],
})


# --------------------------------------------------------------------------- #
# Inputs and ground truth
# --------------------------------------------------------------------------- #
def load_kev() -> dict[str, dict]:
    with open(KEV_FILE, encoding="utf-8-sig", newline="") as f:
        return {r["cveID"]: r for r in csv.DictReader(f)}


def load_nvd_cve(cve: str) -> dict:
    data = json.loads((NVD_DIR / f"{cve}.json").read_text(encoding="utf-8"))
    return data["vulnerabilities"][0]["cve"]


def nvd_description(nvd: dict) -> str:
    return next((d["value"] for d in nvd.get("descriptions", []) if d.get("lang") == "en"), "")


def nvd_ground_truth(nvd: dict) -> dict:
    vendors, products = set(), set()
    for conf in nvd.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if m.get("vulnerable"):
                    parts = m["criteria"].split(":")  # cpe:2.3:a:vendor:product:version:...
                    vendors.add(parts[3])
                    products.add(parts[4])
    cwes = {d["value"] for w in nvd.get("weaknesses", []) for d in w.get("description", [])}
    return {"vendors": sorted(vendors), "products": sorted(products), "cwes": sorted(cwes)}


def build_text(cve: str, nvd: dict, kev: dict) -> str:
    summary, desc = "", ""
    adv_file = ADV_DIR / f"{cve}_ghsa.json"
    if adv_file.exists():
        advs = json.loads(adv_file.read_text(encoding="utf-8"))
        if advs:
            summary = advs[0].get("summary") or ""
            desc = advs[0].get("description") or ""
    if not desc:
        desc = nvd_description(nvd)
    lines = [f"CVE: {cve}"]
    if summary and not desc.startswith(summary.rstrip(".").rstrip()):
        lines.append(f"Title: {summary}")
    lines += ["", desc]
    note = (kev.get(cve) or {}).get("shortDescription")
    if note:
        lines.append(f"\nCISA note: {note}")
    return "\n".join(lines)[:MAX_CHARS]


# --------------------------------------------------------------------------- #
# LLM call
# --------------------------------------------------------------------------- #
def call_ollama(model: str, text: str, temperature: float) -> tuple[str, dict]:
    payload = {
        "model": model,
        "stream": False,
        "format": Extraction.model_json_schema(),
        "options": {"temperature": temperature, "num_ctx": 4096},
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": EXAMPLE_IN},
            {"role": "assistant", "content": EXAMPLE_OUT},
            {"role": "user", "content": text},
        ],
    }
    req = urllib.request.Request(
        f"{OLLAMA_URL}/api/chat",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=900) as resp:
            out = json.load(resp)
    except urllib.error.HTTPError as e:
        hint = f" Try: ollama pull {model}" if e.code == 404 else ""
        raise SystemExit(f"Ollama returned HTTP {e.code}.{hint}")
    except urllib.error.URLError as e:
        raise SystemExit(f"Cannot reach Ollama at {OLLAMA_URL} ({e.reason}). Is Ollama running?")
    metrics = {
        "wall_s": round(time.time() - t0, 2),
        "model_s": round(out.get("total_duration", 0) / 1e9, 2),
        "prompt_tokens": out.get("prompt_eval_count"),
        "output_tokens": out.get("eval_count"),
    }
    return out["message"]["content"], metrics


def extract_one(model: str, text: str):
    """Return (Extraction | None, metrics, attempts, error)."""
    error, metrics = None, {}
    for attempt in range(1, MAX_ATTEMPTS + 1):
        temperature = 0 if attempt == 1 else 0.3  # temp 0 would just repeat the same failure
        content, metrics = call_ollama(model, text, temperature)
        try:
            return Extraction.model_validate_json(content), metrics, attempt, None
        except ValidationError as e:
            error = str(e)
            log.warning("Invalid output (attempt %d/%d)", attempt, MAX_ATTEMPTS)
    return None, metrics, MAX_ATTEMPTS, error


# --------------------------------------------------------------------------- #
# Grounding checks (provenance): is each extracted item present in the text?
# --------------------------------------------------------------------------- #
def norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", s.lower()).strip()


def contains(text_norm: str, item: str) -> bool:
    """Whole-word match, so 'cwe 50' does not match inside 'cwe 502'."""
    n = norm(item)
    return bool(n) and f" {n} " in f" {text_norm} "


def version_grounded(version: str, text: str, text_norm: str) -> bool:
    nums = re.findall(r"\d+(?:\.\d+)*", version)
    if not nums:
        return contains(text_norm, version)
    # each number must appear as a complete version number, not as a prefix of a longer one
    return all(re.search(r"(?<![\d.])" + re.escape(n) + r"(?!\d|\.\d)", text) for n in nums)


def ground(ext: Extraction, text: str) -> tuple[Extraction, dict]:
    """Drop every extracted item that is not literally supported by the source text.
    weakness_types are paraphrases, so they are kept as they are."""
    t = norm(text)
    dropped = {"products": 0, "vendors": 0, "versions": 0}
    products = []
    for p in ext.products:
        if not contains(t, p.name):
            dropped["products"] += 1
            continue
        vendor = p.vendor
        if vendor and not contains(t, vendor):
            dropped["vendors"] += 1
            vendor = ""
        versions = [v for v in p.versions if version_grounded(v, text, t)]
        dropped["versions"] += len(p.versions) - len(versions)
        products.append(Product(name=p.name, vendor=vendor, versions=versions))
    grounded = Extraction(products=products, weakness_types=ext.weakness_types)
    return grounded, dropped


def rule_based(cve: str, text: str) -> dict:
    """Deterministic extraction (100% precise, no LLM): explicit CWE ids and exploit chains.
    CISA notes say e.g. 'can be chained with CVE-X, CVE-Y, and CVE-Z.'"""
    cwe_ids = sorted(set(re.findall(r"\bCWE-\d+\b", text)))
    chained = set()
    for sentence in re.findall(r"chained with ([^\n]*?)(?:\.\s|\.$|$)", text, flags=re.I):
        chained.update(re.findall(r"CVE-\d{4}-\d{4,}", sentence))
    chained.discard(cve)
    return {"cwe_ids": cwe_ids, "chained_with": sorted(chained)}


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def write_atomic(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def show(cve: str, text: str, record: dict, gt: dict) -> None:
    print("\n" + "=" * 78)
    print(f"{cve}  |  valid={record['valid']}  attempts={record['attempts']}  {record['metrics']}")
    print("-" * 78 + "\nSOURCE TEXT:\n" + text)
    print("-" * 78 + "\nEXTRACTED:")
    print(json.dumps(record["extraction"], indent=2, ensure_ascii=False))
    print("AFTER GROUNDING FILTER:", json.dumps(record["extraction_grounded"], ensure_ascii=False))
    print("DROPPED (not found in the text):", record["dropped"])
    print("RULE-BASED (regex):", json.dumps(record["rules"]))
    print("-" * 78 + "\nGROUND TRUTH (NVD):", json.dumps(gt, ensure_ascii=False))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--limit", type=int, default=None, help="process only the first N CVEs")
    parser.add_argument("--force", action="store_true", help="redo existing extractions")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    if not MANIFEST.exists():
        raise SystemExit("Manifest not found. Run the ingestion step first.")
    cves = [c["cve"] for c in json.loads(MANIFEST.read_text(encoding="utf-8"))["selected"]]
    if args.limit:
        cves = cves[: args.limit]

    out_dir = OUT_ROOT / re.sub(r"[^A-Za-z0-9._-]", "_", args.model)
    out_dir.mkdir(parents=True, exist_ok=True)
    kev = load_kev()

    done = failed = skipped = 0
    for cve in cves:
        out_file = out_dir / f"{cve}.json"
        if out_file.exists() and not args.force:
            prev = json.loads(out_file.read_text(encoding="utf-8"))
            if prev.get("valid") and prev.get("prompt_version") == PROMPT_VERSION:
                log.info("%s: already extracted, skipping.", cve)
                skipped += 1
                continue
            log.info("%s: previous result invalid or from an older prompt, redoing.", cve)

        nvd = load_nvd_cve(cve)
        text = build_text(cve, nvd, kev)
        log.info("%s: extracting with %s...", cve, args.model)
        ext, metrics, attempts, error = extract_one(args.model, text)

        grounded, dropped = ground(ext, text) if ext else (None, None)
        record = {
            "cve": cve,
            "model": args.model,
            "prompt_version": PROMPT_VERSION,
            "valid": ext is not None,
            "attempts": attempts,
            "error": error,
            "source_text": text,
            "extraction": ext.model_dump() if ext else None,
            "extraction_grounded": grounded.model_dump() if grounded else None,
            "rules": rule_based(cve, text),
            "dropped": dropped,
            "metrics": metrics,
        }
        write_atomic(out_file, json.dumps(record, indent=2, ensure_ascii=False))
        show(cve, text, record, nvd_ground_truth(nvd))
        done += 1
        failed += 0 if ext else 1

    log.info("Done: %d extracted (%d invalid), %d skipped. Output: %s", done, failed, skipped, out_dir)


if __name__ == "__main__":
    main()