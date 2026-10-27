"""Entity resolution: turn per-document mentions into canonical vendors and products.

Rules (all deterministic, standard library only, so they can also run inside Spark):
  1. Vendor key: lower-case, punctuation removed, legal suffixes dropped
     ("Zammad GmbH" -> "zammad", "Palo Alto Networks" -> "paloaltonetworks").
  2. Product key: the vendor prefix is removed, as CPE does ("Apache Struts" -> "struts",
     "Ahsay AhsayCBS" -> "ahsaycbs").
  3. Abbreviations are merged ONLY inside one document: "ICS" is merged with
     "Ivanti Connect Secure" when both appear in the same advisory. Across documents the same
     acronym can mean different things, so it is never merged blindly.
  4. Same vendor + near-identical product key (similarity >= 0.92, key >= 6 chars) -> same product.
  5. A product with no vendor joins the unique vendor-known product with the same key,
     otherwise it stays vendor-less (nothing is guessed).
  6. Aliases with a different naming scheme (CPE "cloud_backup_suite" vs "AhsayCBS",
     "NetScaler ADC" vs "Application Delivery Controller") need a reference catalogue: out of scope.

Outputs:
  data/resolved/<dir>.json                 canonical vendors, products and links (feeds the Spark ETL)
  data/extracted/<dir>_resolved/*.json     same records with canonical products, so that
                                           04_evaluate.py --dir <dir>_resolved measures the effect

Usage:
    python pipeline/05_resolve_entities.py
    python pipeline/04_evaluate.py --dir llama3.2_resolved
"""
import argparse
import difflib
import importlib
import json
from collections import Counter, defaultdict
from pathlib import Path

ex = importlib.import_module("03_extract")  # reuses norm(), OUT_ROOT and rule_based()

BASE_DIR = Path(__file__).resolve().parent.parent
RESOLVED_DIR = BASE_DIR / "data" / "resolved"
LEGAL_SUFFIXES = {"gmbh", "inc", "ltd", "llc", "corp", "corporation", "co", "company",
                  "sa", "ag", "bv", "plc", "limited"}
FUZZY_THRESHOLD = 0.92
FUZZY_MIN_LEN = 6


# --------------------------------------------------------------------------- #
# Normalisation
# --------------------------------------------------------------------------- #
def toks(s: str) -> list[str]:
    return ex.norm(s).split()


def vendor_tokens(vendor: str) -> list[str]:
    return [t for t in toks(vendor) if t not in LEGAL_SUFFIXES]


def vendor_key(vendor: str) -> str:
    return "".join(vendor_tokens(vendor))


def product_key(name: str, vendor: str) -> str:
    t, vt = toks(name), vendor_tokens(vendor)
    if vt and t[: len(vt)] == vt and len(t) > len(vt):
        t = t[len(vt):]
    return "".join(t)


def is_acronym_of(short: str, long: str) -> bool:
    s, lg = toks(short), toks(long)
    return len(s) == 1 and 2 <= len(s[0]) <= 6 and len(lg) >= 2 and s[0] == "".join(w[0] for w in lg)


def best_surface(counter: Counter) -> str:
    """Most frequent surface form; ties go to the longest."""
    return max(counter.items(), key=lambda kv: (kv[1], len(kv[0])))[0]


def write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


# --------------------------------------------------------------------------- #
# Resolution
# --------------------------------------------------------------------------- #
def resolve(records: list[dict]):
    merges = []
    raw_mentions = 0
    mentions = []  # one per (document, product) after in-document abbreviation merge

    for r in records:
        prods = [{**p, "aliases": []} for p in r["extraction_grounded"]["products"]]
        raw_mentions += len(prods)
        absorbed = set()
        for i, a in enumerate(prods):
            for j, b in enumerate(prods):
                if i != j and j not in absorbed and is_acronym_of(a["name"], b["name"]):
                    b["vendor"] = b["vendor"] or a["vendor"]
                    b["versions"] = list(dict.fromkeys(b["versions"] + a["versions"]))
                    b["aliases"].append(a["name"])
                    absorbed.add(i)
                    merges.append({"type": "abbreviation (same document)", "cve": r["cve"],
                                   "merged": a["name"], "into": b["name"]})
                    break
        for i, p in enumerate(prods):
            if i not in absorbed:
                mentions.append({"cve": r["cve"], **p,
                                 "vkey": vendor_key(p["vendor"]),
                                 "pkey": product_key(p["name"], p["vendor"])})

    # exact groups for vendor-known mentions
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for m in mentions:
        if m["vkey"]:
            groups[(m["vkey"], m["pkey"])].append(m)

    # fuzzy merge within the same vendor
    by_vendor = defaultdict(list)
    for vk, pk in groups:
        by_vendor[vk].append(pk)
    for vk, pks in by_vendor.items():
        pks.sort()
        for i, a in enumerate(pks):
            if (vk, a) not in groups:
                continue
            for b in pks[i + 1:]:
                if (vk, b) in groups and min(len(a), len(b)) >= FUZZY_MIN_LEN and \
                        difflib.SequenceMatcher(None, a, b).ratio() >= FUZZY_THRESHOLD:
                    groups[(vk, a)] += groups.pop((vk, b))
                    merges.append({"type": "fuzzy (same vendor)", "merged": b, "into": a})

    # vendor-less mentions: attach to the unique vendor-known product with the same key
    for m in mentions:
        if m["vkey"]:
            continue
        candidates = [k for k in groups if k[1] == m["pkey"] and k[0]]
        if len(candidates) == 1:
            groups[candidates[0]].append(m)
            merges.append({"type": "vendor-less attached", "cve": m["cve"], "merged": m["name"],
                           "into": f"{candidates[0][0]} / {candidates[0][1]}"})
        else:
            groups[("", m["pkey"])].append(m)

    # canonical objects
    vendor_surfaces: dict[str, Counter] = defaultdict(Counter)
    products, mention_to_pid = [], {}
    for (vk, pk), ms in sorted(groups.items()):
        pid = f"p:{vk or 'unknown'}:{pk}"
        names = Counter(m["name"] for m in ms)
        for m in ms:
            if vk and m["vendor"]:
                vendor_surfaces[vk][m["vendor"]] += 1
            mention_to_pid[(m["cve"], m["name"], m["vendor"])] = pid
        aliases = sorted(set(names) | {a for m in ms for a in m["aliases"]})
        products.append({"id": pid, "name": best_surface(names),
                         "vendor_id": f"v:{vk}" if vk else None, "aliases": aliases})
    vendors = [{"id": f"v:{vk}", "name": best_surface(c), "aliases": sorted(c)}
               for vk, c in sorted(vendor_surfaces.items())]
    return mentions, raw_mentions, products, vendors, mention_to_pid, merges


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--dir", default="llama3.2", help="folder name under data/extracted")
    args = parser.parse_args()

    folder = ex.OUT_ROOT / args.dir
    records = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(folder.glob("*.json"))]
    records = [r for r in records if r["valid"] and r.get("extraction_grounded")]
    if not records:
        raise SystemExit(f"No valid extraction in {folder}")

    mentions, raw_mentions, products, vendors, mention_to_pid, merges = resolve(records)
    pname = {p["id"]: p for p in products}
    vname = {v["id"]: v["name"] for v in vendors}

    # links per document + resolved view for evaluation
    affects, chained, weakness, cwe_explicit = [], [], [], []
    view_dir = ex.OUT_ROOT / f"{args.dir}_resolved"
    for r in records:
        by_pid: dict[str, dict] = {}
        for m in (m for m in mentions if m["cve"] == r["cve"]):
            pid = mention_to_pid[(m["cve"], m["name"], m["vendor"])]
            entry = by_pid.setdefault(pid, {"cve": r["cve"], "product_id": pid, "versions_raw": []})
            entry["versions_raw"] = list(dict.fromkeys(entry["versions_raw"] + m["versions"]))
        affects += list(by_pid.values())
        rules = r.get("rules") or ex.rule_based(r["cve"], r["source_text"])
        chained += [{"cve": r["cve"], "other": o} for o in rules["chained_with"]]
        cwe_explicit += [{"cve": r["cve"], "cwe": c} for c in rules["cwe_ids"]]
        weakness += [{"cve": r["cve"], "phrase": w} for w in r["extraction_grounded"]["weakness_types"]]

        resolved_products = [
            {"name": pname[pid]["name"], "vendor": vname.get(pname[pid]["vendor_id"], ""),
             "versions": e["versions_raw"]}
            for pid, e in by_pid.items()
        ]
        view = {**r, "resolved_from": args.dir,
                "extraction": {"products": resolved_products, "weakness_types": r["extraction_grounded"]["weakness_types"]}}
        view["extraction_grounded"] = view["extraction"]
        write_atomic(view_dir / f"{r['cve']}.json", json.dumps(view, indent=2, ensure_ascii=False))

    distinct_raw = len({(m["vendor"], m["name"]) for r in records for m in r["extraction_grounded"]["products"]})
    stats = {
        "documents": len(records),
        "product_mentions_raw": raw_mentions,
        "product_mentions_after_abbreviation_merge": len(mentions),
        "distinct_raw_product_strings": distinct_raw,
        "canonical_products": len(products),
        "canonical_vendors": len(vendors),
        "vendorless_products": sum(1 for p in products if not p["vendor_id"]),
        "merges": merges,
    }
    out = {"stats": stats, "vendors": vendors, "products": products, "affects": affects,
           "chained_with": chained, "weakness_phrases": weakness, "cwe_explicit": cwe_explicit}
    write_atomic(RESOLVED_DIR / f"{args.dir}.json", json.dumps(out, indent=2, ensure_ascii=False))

    print("ENTITY RESOLUTION")
    for k, v in stats.items():
        if k != "merges":
            print(f"  {k}: {v}")
    print(f"  merges applied: {len(merges)}")
    for m in merges:
        print("   -", m)
    print("\nVendors with several surface forms:")
    for v in vendors:
        if len(v["aliases"]) > 1:
            print("   -", v["name"], "<=", v["aliases"])
    print(f"\nWritten: {RESOLVED_DIR / (args.dir + '.json')}")
    print(f"Next: python pipeline/04_evaluate.py --dir {args.dir}_resolved")


if __name__ == "__main__":
    main()