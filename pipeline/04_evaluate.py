"""Evaluate LLM extraction against the NVD ground truth (no LLM call, instant).

Reads data/extracted/<dir>/*.json (written by 03_extract.py) and reports:
  * product / vendor precision, recall and F1, on the raw output and after the grounding filter;
  * what the grounding filter removed (versions, CWE ids, ...);
  * the regex-based extraction (explicit CWE ids, exploit chains);
  * latency and token usage.
Writes benchmark/extraction_eval_<dir>.md.

Recall is computed on the *recoverable* ground truth only: an NVD product or vendor counts
as a target only if it is actually mentioned in the advisory text. NVD analysts add CPE
entries (other vendors, OS versions...) that no text-reading system could know; counting
them would punish the LLM for information it never saw. Precision is computed against ALL
the NVD ground truth. Several "false positives" are naming differences (aliases,
abbreviations), not hallucinations: they are listed so you can classify them.

Usage:
    python pipeline/04_evaluate.py
    python pipeline/04_evaluate.py --dir qwen2.5_7b
"""
import argparse
import importlib
import json
import statistics
from pathlib import Path

ex = importlib.import_module("03_extract")  # reuses norm(), NVD loaders and rule_based()

BASE_DIR = Path(__file__).resolve().parent.parent
BENCH_DIR = BASE_DIR / "benchmark"


# --------------------------------------------------------------------------- #
# Matching rules
# --------------------------------------------------------------------------- #
def tokens(s: str) -> set[str]:
    return set(ex.norm(s).split())


def compact(s: str) -> str:
    return ex.norm(s).replace(" ", "")


def ngram_set(text: str, nmax: int = 4) -> set[str]:
    toks = ex.norm(text).split()
    return {"".join(toks[i:i + n]) for n in range(1, nmax + 1) for i in range(len(toks) - n + 1)}


def recoverable(item: str, text_tokens: set[str], grams: set[str]) -> bool:
    """Is the NVD item mentioned in the text? (all its words appear, or it equals a short word run)"""
    return tokens(item) <= text_tokens or compact(item) in grams


def product_match(extracted_name: str, gt_product: str) -> bool:
    """NVD 'media_server' matches 'Plex Media Server': all NVD words are in the extracted name."""
    return bool(tokens(gt_product)) and tokens(gt_product) <= tokens(extracted_name)


def vendor_match(extracted: str, gt_vendor: str) -> bool:
    a, b = compact(extracted), compact(gt_vendor)
    if not a or not b:
        return False
    return a == b or (min(len(a), len(b)) >= 4 and (a in b or b in a))


def f1(p: float, r: float) -> float:
    return 2 * p * r / (p + r) if p + r else 0.0


def ratio(a: int, b: int) -> float:
    return a / b if b else 0.0


# --------------------------------------------------------------------------- #
# Evaluation
# --------------------------------------------------------------------------- #
def evaluate(records: list[dict], view: str) -> dict:
    c = dict(p_hit=0, p_rec_total=0, p_prec_hit=0, p_total=0,
             v_hit=0, v_rec_total=0, v_prec_hit=0, v_total=0)
    details = []
    for r in records:
        if not r["valid"] or not r.get(view):
            continue
        gt = ex.nvd_ground_truth(ex.load_nvd_cve(r["cve"]))
        text = r["source_text"]
        tt, grams = tokens(text), ngram_set(text)
        prods = r[view]["products"]
        vendors = sorted({p["vendor"] for p in prods if p["vendor"]})

        # products
        gt_rec = [g for g in gt["products"] if recoverable(g, tt, grams)]
        hit = [g for g in gt_rec if any(product_match(p["name"], g) for p in prods)]
        prec_hit = [p["name"] for p in prods if any(product_match(p["name"], g) for g in gt["products"])]
        c["p_rec_total"] += len(gt_rec)
        c["p_hit"] += len(hit)
        c["p_total"] += len(prods)
        c["p_prec_hit"] += len(prec_hit)

        # vendors
        gv_rec = [g for g in gt["vendors"] if recoverable(g, tt, grams)]
        v_hit = [g for g in gv_rec if any(vendor_match(v, g) for v in vendors)]
        v_prec_hit = [v for v in vendors if any(vendor_match(v, g) for g in gt["vendors"])]
        c["v_rec_total"] += len(gv_rec)
        c["v_hit"] += len(v_hit)
        c["v_total"] += len(vendors)
        c["v_prec_hit"] += len(v_prec_hit)

        details.append({
            "cve": r["cve"],
            "fp_products": [p["name"] for p in prods if p["name"] not in prec_hit],
            "fn_products": [g for g in gt_rec if g not in hit],
            "fp_vendors": [v for v in vendors if v not in v_prec_hit],
            "fn_vendors": [g for g in gv_rec if g not in v_hit],
        })

    out = {"details": details}
    for k, (hit, rec_t, ph, tot) in {
        "product": ("p_hit", "p_rec_total", "p_prec_hit", "p_total"),
        "vendor": ("v_hit", "v_rec_total", "v_prec_hit", "v_total"),
    }.items():
        p, rcl = ratio(c[ph], c[tot]), ratio(c[hit], c[rec_t])
        out[k] = {"precision": p, "recall": rcl, "f1": f1(p, rcl),
                  "n_extracted": c[tot], "n_recoverable_gt": c[rec_t]}
    return out


def pct(x: float) -> str:
    return f"{100 * x:.0f}%"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--dir", default="llama3.2", help="folder name under data/extracted")
    args = parser.parse_args()

    folder = ex.OUT_ROOT / args.dir
    records = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(folder.glob("*.json"))]
    if not records:
        raise SystemExit(f"No extraction found in {folder}")
    valid = [r for r in records if r["valid"]]
    versions = sorted({r.get("prompt_version", "?") for r in records})

    lines = [f"# Extraction evaluation: `{args.dir}`", "",
             f"- Documents: {len(records)} ({len(valid)} valid JSON, prompt version(s): {', '.join(versions)})", ""]

    # 1. product / vendor quality
    lines += ["## Products and vendors vs NVD ground truth", "",
              "| Entity | View | Precision | Recall (recoverable GT) | F1 | Extracted | Recoverable GT |",
              "|---|---|---|---|---|---|---|"]
    results = {}
    for view, label in (("extraction", "raw LLM"), ("extraction_grounded", "after grounding filter")):
        res = evaluate(records, view)
        results[view] = res
        for ent in ("product", "vendor"):
            m = res[ent]
            lines.append(f"| {ent} | {label} | {pct(m['precision'])} | {pct(m['recall'])} | "
                         f"{pct(m['f1'])} | {m['n_extracted']} | {m['n_recoverable_gt']} |")

    # 2. grounding filter effect
    n_ver = sum(len(p["versions"]) for r in valid for p in r["extraction"]["products"])
    d = {k: sum((r.get("dropped") or {}).get(k, 0) for r in valid) for k in ("products", "vendors", "versions", "cwe_ids")}
    n_cwe = sum(len(r["extraction"].get("cwe_ids", [])) for r in valid)
    lines += ["", "## What the grounding filter removed (items not found in the text)", "",
              f"- Versions: {d['versions']} dropped out of {n_ver} extracted",
              f"- Products: {d['products']} dropped; vendors: {d['vendors']} dropped"]
    if n_cwe:
        lines.append(f"- CWE ids written by the LLM: {n_cwe}, of which {d['cwe_ids']} were not in the text "
                     "(LLM-written CWE ids are unreliable; v3 extracts explicit ones by regex instead)")

    # 3. rule-based extraction
    explicit_ok = explicit_total = n_with_cwe = chain_edges = 0
    for r in valid:
        rules = ex.rule_based(r["cve"], r["source_text"])
        gt_cwes = set(ex.nvd_ground_truth(ex.load_nvd_cve(r["cve"]))["cwes"])
        if rules["cwe_ids"]:
            n_with_cwe += 1
        explicit_total += len(rules["cwe_ids"])
        explicit_ok += len(set(rules["cwe_ids"]) & gt_cwes)
        chain_edges += len(rules["chained_with"])
    lines += ["", "## Rule-based extraction (regex, no LLM)", "",
              f"- Explicit CWE ids in the text: {explicit_total} in {n_with_cwe}/{len(valid)} documents, "
              f"{explicit_ok} confirmed by NVD",
              f"- Exploit-chain edges (CVE chained with CVE): {chain_edges}"]

    # 4. latency and cost
    wall = [r["metrics"]["wall_s"] for r in valid if r.get("metrics")]
    ptok = [r["metrics"]["prompt_tokens"] or 0 for r in valid if r.get("metrics")]
    otok = [r["metrics"]["output_tokens"] or 0 for r in valid if r.get("metrics")]
    if wall:
        w = sorted(wall)
        p95 = w[min(len(w) - 1, int(0.95 * len(w)))]
        lines += ["", "## Latency and cost (local CPU)", "",
                  f"- Latency per document: median {statistics.median(w):.1f}s, p95 {p95:.1f}s, total {sum(w) / 60:.1f} min",
                  f"- Tokens per document: prompt {statistics.mean(ptok):.0f} (mean), output {statistics.mean(otok):.0f} (mean)",
                  "- Output length drives latency: long multi-product advisories are the slowest."]

    # 5. error listing for manual classification
    lines += ["", "## Mismatches to classify (alias / granularity vs real error)", ""]
    for d_ in results["extraction_grounded"]["details"]:
        parts = []
        for key, label in (("fp_products", "extracted product not in NVD"), ("fn_products", "NVD product missed"),
                           ("fp_vendors", "extracted vendor not in NVD"), ("fn_vendors", "NVD vendor missed")):
            if d_[key]:
                parts.append(f"{label}: {', '.join(d_[key])}")
        if parts:
            lines.append(f"- `{d_['cve']}`: " + " | ".join(parts))

    report = "\n".join(lines) + "\n"
    print(report)
    BENCH_DIR.mkdir(exist_ok=True)
    out_file = BENCH_DIR / f"extraction_eval_{args.dir}.md"
    out_file.write_text(report, encoding="utf-8")
    print(f"Report written to {out_file}")


if __name__ == "__main__":
    main()