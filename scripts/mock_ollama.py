"""A tiny stand-in for Ollama, for testing the API plumbing (embeddings, chat, streaming)
without a model. Its answers are canned from the context it receives, NOT real LLM output.

    python scripts/mock_ollama.py            # listens on 127.0.0.1:11434
"""
import importlib.util
import json
import re
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "pipeline"))
spec = importlib.util.spec_from_file_location("seed", Path(__file__).with_name("seed_demo_graph.py"))
seed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(seed)


def canned(user: str) -> dict:
    ids = list(dict.fromkeys(re.findall(r"^\[(CVE-\d{4}-\d{4,})\]", user, re.M)))
    m = re.search(r"Affects: (.+)", user)
    if not ids:
        return {"answer": "The context does not contain enough information.", "sources": []}
    return {"answer": (m.group(1) if m else "See the cited CVE.").strip(), "sources": ids[:1]}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._json({"models": [{"name": "mock"}]})

    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path == "/api/embed":
            return self._json({"embeddings": [seed.fake_embed(t) for t in req["input"]]})
        text = json.dumps(canned(req["messages"][-1]["content"]))
        if not req.get("stream"):
            return self._json({"message": {"content": text}, "prompt_eval_count": 10, "eval_count": 5})
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.end_headers()
        for i in range(0, len(text), 6):
            self.wfile.write(json.dumps({"message": {"content": text[i:i + 6]}, "done": False}).encode() + b"\n")
            self.wfile.flush()
            time.sleep(0.04)
        self.wfile.write(json.dumps({"message": {"content": ""}, "done": True,
                                     "prompt_eval_count": 10, "eval_count": 5}).encode() + b"\n")


if __name__ == "__main__":
    print("mock ollama on http://127.0.0.1:11434")
    ThreadingHTTPServer(("127.0.0.1", 11434), Handler).serve_forever()
