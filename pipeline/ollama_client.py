"""Minimal Ollama client (standard library only), shared by the embedding, GraphRAG and
benchmark scripts.

Environment variables:
    OLLAMA_URL          default http://localhost:11434
    OLLAMA_MODEL        chat model, default llama3.2
    OLLAMA_EMBED_MODEL  embedding model, default nomic-embed-text   (ollama pull nomic-embed-text)
"""
import json
import os
import time
import urllib.error
import urllib.request

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
EMBED_MODEL = os.environ.get("OLLAMA_EMBED_MODEL", "nomic-embed-text")
CHAT_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2")


class OllamaError(RuntimeError):
    """Ollama unreachable, or model not installed."""


def _post(path: str, payload: dict, timeout: int = 900) -> dict:
    req = urllib.request.Request(
        f"{OLLAMA_URL}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        hint = f" Try: ollama pull {payload.get('model')}" if e.code == 404 else ""
        raise OllamaError(f"Ollama returned HTTP {e.code}.{hint}") from e
    except urllib.error.URLError as e:
        raise OllamaError(f"Cannot reach Ollama at {OLLAMA_URL} ({e.reason}). Is Ollama running?") from e


def embed(texts: list[str], model: str | None = None) -> list[list[float]]:
    """One embedding vector per input text."""
    out = _post("/api/embed", {"model": model or EMBED_MODEL, "input": texts})
    return out["embeddings"]


def chat(system: str, user: str, model: str | None = None, num_ctx: int = 8192,
         temperature: float = 0, schema: dict | None = None) -> dict:
    """Single-turn chat. Returns the text plus latency and token counts.
    With `schema` (a JSON schema) the output is constrained to valid JSON of that shape."""
    t0 = time.time()
    payload = {
        "model": model or CHAT_MODEL,
        "stream": False,
        "options": {"temperature": temperature, "num_ctx": num_ctx},
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
    }
    if schema is not None:
        payload["format"] = schema
    out = _post("/api/chat", payload)
    return {
        "text": out["message"]["content"],
        "wall_s": round(time.time() - t0, 2),
        "prompt_tokens": out.get("prompt_eval_count"),
        "output_tokens": out.get("eval_count"),
    }


def chat_stream(system: str, user: str, model: str | None = None, num_ctx: int = 8192,
                temperature: float = 0, schema: dict | None = None, timeout: int = 900):
    """Same request as chat() but streamed. Yields ("delta", text) for every chunk, then one
    ("done", {"text", "wall_s", "prompt_tokens", "output_tokens"}). Closing the generator
    closes the HTTP connection, which stops the generation on the Ollama side."""
    t0 = time.time()
    payload = {
        "model": model or CHAT_MODEL,
        "stream": True,
        "options": {"temperature": temperature, "num_ctx": num_ctx},
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
    }
    if schema is not None:
        payload["format"] = schema
    req = urllib.request.Request(f"{OLLAMA_URL}/api/chat", data=json.dumps(payload).encode("utf-8"),
                                 headers={"Content-Type": "application/json"})
    text, last = [], {}
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            for line in resp:
                if not line.strip():
                    continue
                chunk = json.loads(line)
                delta = chunk.get("message", {}).get("content", "")
                if delta:
                    text.append(delta)
                    yield "delta", delta
                if chunk.get("done"):
                    last = chunk
    except urllib.error.HTTPError as e:
        hint = f" Try: ollama pull {payload.get('model')}" if e.code == 404 else ""
        raise OllamaError(f"Ollama returned HTTP {e.code}.{hint}") from e
    except urllib.error.URLError as e:
        raise OllamaError(f"Cannot reach Ollama at {OLLAMA_URL} ({e.reason}). Is Ollama running?") from e
    yield "done", {
        "text": "".join(text),
        "wall_s": round(time.time() - t0, 2),
        "prompt_tokens": last.get("prompt_eval_count"),
        "output_tokens": last.get("eval_count"),
    }