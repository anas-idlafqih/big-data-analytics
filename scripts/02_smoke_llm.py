"""Smoke test of the local LLM (Ollama): structured extraction on one real advisory.

Prints the structure of the advisory file, the extracted JSON and basic metrics
(latency, token counts). Standard library only.

Usage (Ollama must be running):
    python scripts/smoke_llm.py
    $env:OLLAMA_MODEL = "qwen2.5:7b"; python scripts/smoke_llm.py   # try another model
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
ADV_DIR = BASE_DIR / "data" / "raw" / "advisories"
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2")
MAX_CHARS = 6000  # keep the prompt inside the context window

SCHEMA = {
    "type": "object",
    "properties": {
        "cve_id": {"type": "string"},
        "products": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "vendor": {"type": "string"},
                    "affected_versions": {"type": "string"},
                },
                "required": ["name", "vendor", "affected_versions"],
            },
        },
        "weaknesses": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["cve_id", "products", "weaknesses"],
}

SYSTEM = (
    "You extract structured data from security advisories. "
    "Use ONLY information explicitly stated in the text. "
    "If a value is not stated, use an empty string. Never guess."
)


def load_first_advisory() -> dict:
    files = sorted(p for p in ADV_DIR.glob("*_ghsa.json") if p.read_text(encoding="utf-8").strip() != "[]")
    if not files:
        sys.exit(f"No non-empty advisory found in {ADV_DIR}. Run the advisories script first.")
    data = json.loads(files[0].read_text(encoding="utf-8"))
    print(f"Advisory file: {files[0].name} ({len(data)} entry)")
    return data[0]


def main() -> None:
    adv = load_first_advisory()
    print("Top-level keys:", sorted(adv.keys()))

    text = f"CVE: {adv.get('cve_id', '')}\nTitle: {adv.get('summary', '')}\n\n{adv.get('description', '')}"
    text = text[:MAX_CHARS]
    print(f"Prompt text length: {len(text)} chars\n")

    payload = {
        "model": MODEL,
        "stream": False,
        "format": SCHEMA,  # constrains the output to this JSON schema
        "options": {"temperature": 0, "num_ctx": 4096},
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": text},
        ],
    }
    req = urllib.request.Request(
        f"{OLLAMA_URL}/api/chat",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    print(f"Calling {MODEL} (first call loads the model, this can take a while)...")
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=900) as resp:
            out = json.load(resp)
    except urllib.error.HTTPError as e:
        hint = f" Try: ollama pull {MODEL}" if e.code == 404 else ""
        sys.exit(f"Ollama returned HTTP {e.code}.{hint}")
    except urllib.error.URLError as e:
        sys.exit(f"Cannot reach Ollama at {OLLAMA_URL} ({e.reason}). Is Ollama running?")
    elapsed = time.time() - t0

    try:
        data = json.loads(out["message"]["content"])
    except (KeyError, json.JSONDecodeError) as e:
        sys.exit(f"Model output is not valid JSON ({e}):\n{out}")

    print("\nExtracted JSON:")
    print(json.dumps(data, indent=2, ensure_ascii=False))
    print(
        f"\nWall time: {elapsed:.1f}s | model time: {out.get('total_duration', 0) / 1e9:.1f}s"
        f" | prompt tokens: {out.get('prompt_eval_count')} | output tokens: {out.get('eval_count')}"
    )
    print("LLM SMOKE TEST OK")


if __name__ == "__main__":
    main()