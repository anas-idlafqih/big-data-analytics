"""API FastAPI au-dessus de pipeline/09_graphrag.py (GraphRAG sur le graphe de CVE).

Lancement (depuis la racine du depot, venv active, Neo4j et Ollama demarres) :
    python -m uvicorn api.app:app --host 127.0.0.1 --port 8000

    
    
Documentation interactive : http://127.0.0.1:8000/docs

Tests PowerShell. Invoke-RestMethod est la forme fiable : PowerShell deforme les guillemets
JSON passes a curl.exe.
    Invoke-RestMethod http://127.0.0.1:8000/health

    $body = @{question = "Which CVEs are chained with CVE-2026-105133?"; mode = "graph"} | ConvertTo-Json
    Invoke-RestMethod -Uri http://127.0.0.1:8000/ask -Method Post -ContentType "application/json" -Body $body | ConvertTo-Json -Depth 4

    # meme question en RAG vectoriel classique, pour comparer : mode = "vector"

    # avec curl.exe : ecrire le corps dans un fichier, puis l'envoyer
    $body | Set-Content -Encoding ascii body.json
    curl.exe -X POST http://127.0.0.1:8000/ask -H "Content-Type: application/json" --data-binary "@body.json"

Controle d'acces : si la variable API_KEY est definie, /ask exige l'en-tete X-API-Key
(/health reste ouvert pour la supervision). Sans API_KEY l'API est ouverte (developpement).
    $env:API_KEY = "une-cle-longue-et-secrete"     # avant de lancer uvicorn
    Invoke-RestMethod -Uri http://127.0.0.1:8000/ask -Method Post -ContentType "application/json" `
        -Headers @{"X-API-Key" = $env:API_KEY} -Body $body

Codes d'erreur : 401 (cle absente ou invalide), 422 (question vide ou trop longue, mode invalide,
JSON illisible), 503 (Neo4j ou Ollama injoignable), 500 (erreur interne inattendue).
Le corps d'erreur est toujours {"detail": "message"}.

Variables d'environnement facultatives :
    API_KEY          active le controle d'acces sur /ask
    API_WARMUP=0     desactive le prechauffage des modeles Ollama au demarrage
    ASK_CACHE_TTL    duree (s) du cache des reponses identiques, defaut 300 (0 = desactive)
    RATE_LIMIT_PER_MIN  requetes /ask par minute et par client, defaut 60 (0 = desactive)
    OLLAMA_HOST      adresse d'Ollama pour /health (defaut http://127.0.0.1:11434)
"""
import importlib
import json
import logging
import os
import queue
import secrets
import sys
import threading
import time
import urllib.request
from collections import OrderedDict, defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal, Optional

from fastapi import Depends, FastAPI, HTTPException, Request, Security
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.security import APIKeyHeader
from neo4j.exceptions import AuthError, Neo4jError, ServiceUnavailable, SessionExpired
from pydantic import BaseModel, field_validator

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "pipeline"))  # les scripts importent "ollama_client" directement

import ollama_client  # noqa: E402
from api import routing  # noqa: E402

loader = importlib.import_module("06_load_neo4j")  # URI, USER, get_password(), GraphDatabase
rag = importlib.import_module("09_graphrag")       # answer()

log = logging.getLogger("api")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

TOP_K = 5  # meme valeur que le benchmark


_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(key: Optional[str] = Security(_api_key_header)) -> None:
    """Sans API_KEY dans l'environnement : acces libre. Avec API_KEY : l'en-tete doit correspondre."""
    expected = os.getenv("API_KEY")
    if not expected:
        return
    if not key or not secrets.compare_digest(key.encode("utf-8"), expected.encode("utf-8")):
        raise HTTPException(status_code=401, detail="Cle d'API absente ou invalide (en-tete X-API-Key)")


class AskRequest(BaseModel):
    question: str
    # auto : le routeur choisit (agregation -> Cypher exact, sinon GraphRAG)
    mode: Literal["auto", "graph", "vector"] = "auto"

    @field_validator("question")
    @classmethod
    def not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("la question ne peut pas etre vide")
        if len(v) > 1000:
            raise ValueError("la question depasse 1000 caracteres")
        return v


class AskResponse(BaseModel):
    answer: str
    mode: str                              # mode effectivement execute : graph | vector | cypher
    sources: list[str]
    context_cves: list[str]
    retrieval_s: float
    generation_s: float
    route: Optional[dict] = None           # {kind, label, reason} quand mode == auto
    cypher: Optional[str] = None           # requete executee (route aggregate)
    context: Optional[str] = None          # contexte texte donne au modele
    ungrounded: list[str] = []             # CVE citees dans la reponse mais absentes du contexte
    cached: bool = False


def _warm_up() -> None:
    """Charge les modeles Ollama en arriere-plan pour que le premier /ask ne paie pas le chargement."""
    try:
        ollama_client.embed(["warm-up"])
        ollama_client.chat("Reply OK.", "OK")
        log.info("Ollama warm-up done")
    except Exception as e:
        log.warning("Ollama warm-up failed: %s", e)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Un seul driver partage pour toute la vie du serveur (thread-safe, pool de connexions interne).
    driver = loader.GraphDatabase.driver(loader.URI, auth=(loader.USER, loader.get_password()))
    app.state.driver = driver
    if not os.getenv("API_KEY"):
        log.warning("API_KEY non definie : /ask est ouvert (mode developpement)")
    try:
        driver.verify_connectivity()
        log.info("Neo4j reachable")
    except Exception as e:  # le serveur demarre quand meme : /health et /ask le signaleront
        log.warning("Neo4j not reachable at startup: %s", e)
    if os.getenv("API_WARMUP", "1") == "1":
        threading.Thread(target=_warm_up, daemon=True).start()
    yield
    driver.close()


app = FastAPI(title="CVE Knowledge Graph - GraphRAG API", version="1.0", lifespan=lifespan)

# Frontend React (web/) : origines autorisees, separees par des virgules.
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(","),
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key"],
)


@app.exception_handler(RequestValidationError)
async def validation_error(request, exc: RequestValidationError) -> JSONResponse:
    """422 avec un message lisible : {"detail": "question: la question ne peut pas etre vide"}."""
    parts = []
    for e in exc.errors():
        loc = ".".join(x for x in e["loc"] if isinstance(x, str) and x != "body")
        msg = str(e["msg"]).removeprefix("Value error, ")
        parts.append(f"{loc}: {msg}" if loc else msg)
    return JSONResponse(status_code=422, content={"detail": "; ".join(parts)})


def _neo4j_ok() -> bool:
    try:
        app.state.driver.verify_connectivity()
        return True
    except Exception:
        return False


def _ollama_ok() -> bool:
    host = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")
    if not host.startswith("http"):
        host = "http://" + host
    try:
        with urllib.request.urlopen(host.rstrip("/") + "/api/tags", timeout=2):
            return True
    except Exception:
        return False


@app.get("/health")
def health() -> dict:
    neo, oll = _neo4j_ok(), _ollama_ok()
    return {"status": "ok" if neo and oll else "degraded", "neo4j": neo, "ollama": oll}


GRAPH_NODES_QUERY = """
MATCH (n) WHERE n:CVE OR n:Product OR n:Vendor OR n:Weakness
RETURN labels(n)[0] AS label, coalesce(n.cve_id, n.name) AS key, coalesce(n.name, n.cve_id) AS name,
       n.in_corpus AS in_corpus, n.text AS text, n.ransomware_use AS ransomware,
       toString(n.date_added) AS date_added"""

GRAPH_EDGES_QUERY = """
MATCH (a)-[r:AFFECTS|PRODUCES|HAS_WEAKNESS|CHAINED_WITH]->(b)
RETURN labels(a)[0] AS la, coalesce(a.cve_id, a.name) AS ka,
       labels(b)[0] AS lb, coalesce(b.cve_id, b.name) AS kb, type(r) AS type"""


@app.get("/graph", dependencies=[Depends(require_api_key)])
def graph() -> dict:
    """Le graphe complet (noeuds + relations) pour la vue Explorer du frontend."""
    try:
        with app.state.driver.session() as session:
            nodes = [
                {"id": f"{r['label']}:{r['key']}", "label": r["label"], "name": r["name"],
                 "in_corpus": r["in_corpus"] is not False,
                 "text": " ".join((r["text"] or "").split())[:600] or None,
                 "ransomware": r["ransomware"], "date_added": r["date_added"]}
                for r in session.run(GRAPH_NODES_QUERY).data() if r["key"]
            ]
            edges = [
                {"source": f"{r['la']}:{r['ka']}", "target": f"{r['lb']}:{r['kb']}", "type": r["type"]}
                for r in session.run(GRAPH_EDGES_QUERY).data()
            ]
    except (ServiceUnavailable, SessionExpired, AuthError):
        raise HTTPException(status_code=503, detail="Neo4j indisponible ou authentification refusee")
    return {"nodes": nodes, "edges": edges}


# --------------------------------------------------------------------------- #
# Garde-fous : cache des reponses identiques et limitation de debit par client
# --------------------------------------------------------------------------- #
CACHE_TTL = float(os.getenv("ASK_CACHE_TTL", "300"))
CACHE_MAX = 256
RATE_LIMIT = int(os.getenv("RATE_LIMIT_PER_MIN", "60"))
_cache: "OrderedDict[tuple, tuple[float, dict]]" = OrderedDict()
_cache_lock = threading.Lock()
_hits: dict[str, deque] = defaultdict(deque)
_hits_lock = threading.Lock()


def _cache_get(key: tuple) -> Optional[dict]:
    if CACHE_TTL <= 0:
        return None
    with _cache_lock:
        item = _cache.get(key)
        if item and time.time() - item[0] < CACHE_TTL:
            _cache.move_to_end(key)
            return dict(item[1])
        _cache.pop(key, None)
    return None


def _cache_put(key: tuple, payload: dict) -> None:
    if CACHE_TTL <= 0:
        return
    with _cache_lock:
        _cache[key] = (time.time(), payload)
        while len(_cache) > CACHE_MAX:
            _cache.popitem(last=False)


def rate_limit(request: Request) -> None:
    if RATE_LIMIT <= 0:
        return
    who = request.client.host if request.client else "?"
    now = time.time()
    with _hits_lock:
        q = _hits[who]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= RATE_LIMIT:
            raise HTTPException(status_code=429, detail=f"Trop de requetes : maximum {RATE_LIMIT} par minute.")
        q.append(now)


# --------------------------------------------------------------------------- #
# Execution d'une question (partagee par /ask et /ask/stream)
# --------------------------------------------------------------------------- #
def _payload(mode: str, r: dict, *, route: Optional[dict] = None, cypher: Optional[str] = None) -> dict:
    return {
        "answer": r["answer"], "mode": mode,
        "sources": list(r["sources"]), "context_cves": list(r["context_cves"]),
        "retrieval_s": round(r["retrieval_s"], 2), "generation_s": round(r.get("generation_s", 0.0), 2),
        "route": route, "cypher": cypher, "context": r.get("context"),
        "ungrounded": list(r.get("cited_outside_context", [])), "cached": False,
    }


def run_ask(question: str, mode: str, driver, emit=None, cancelled=lambda: False) -> dict:
    """Route the question, run it and return the AskResponse fields as a dict.
    `emit(event, data)` receives progress events: route, retrieval, token."""
    emit = emit or (lambda *_: None)
    key = (mode, " ".join(question.lower().split()))
    hit = _cache_get(key)
    if hit:
        if hit.get("route"):
            emit("route", hit["route"])
        hit["cached"] = True
        return hit

    route = routing.classify(question) if mode == "auto" else None
    public = route.public() if route else None
    if public:
        emit("route", public)

    if route and route.kind == "aggregate":
        t0 = time.time()
        with driver.session() as session:
            res = routing.execute(session, route)
        if res is not None:
            res["retrieval_s"] = time.time() - t0
            payload = _payload("cypher", res, route=public, cypher=res["cypher"])
            _cache_put(key, payload)
            return payload
        # template could not be resolved (unknown vendor...): fall back to graph retrieval
        public = {**public, "label": "Hybrid retrieval", "reason": "The aggregation could not be resolved in the graph; falling back to retrieval."}
        emit("route", public)

    effective = "vector" if mode == "vector" else "graph"
    final = None
    for kind, data in rag.answer_stream(question, mode=effective, k=TOP_K, driver=driver):
        if cancelled():
            raise InterruptedError("client disconnected")
        if kind == "retrieval":
            emit("retrieval", {"context_cves": data["context_ids"], "retrieval_s": data["retrieval_s"]})
        elif kind == "token":
            emit("token", data)
        else:
            final = data
    payload = _payload(effective, final, route=public)
    _cache_put(key, payload)
    return payload


def _http_error(e: Exception) -> HTTPException:
    if isinstance(e, ollama_client.OllamaError):
        log.warning("Ollama error: %s", e)
        return HTTPException(status_code=503, detail=f"Ollama indisponible : {e}")
    if isinstance(e, (ServiceUnavailable, SessionExpired, AuthError)):
        log.warning("Neo4j error: %s", e)
        return HTTPException(status_code=503, detail="Neo4j indisponible ou authentification refusee")
    if isinstance(e, Neo4jError):
        log.exception("Neo4j query error")
        return HTTPException(status_code=500, detail=f"Erreur Neo4j : {e.code}")
    log.exception("Unexpected error")
    return HTTPException(status_code=500, detail="Erreur interne inattendue (voir les logs du serveur)")


@app.post("/ask", response_model=AskResponse, dependencies=[Depends(require_api_key), Depends(rate_limit)])
def ask(req: AskRequest) -> AskResponse:
    # "def" (et non "async def") : FastAPI l'execute dans un thread, le serveur reste reactif
    # pendant les 10 a 60 s de generation sur CPU.
    t0 = time.time()
    try:
        r = run_ask(req.question, req.mode, app.state.driver)
    except Exception as e:
        raise _http_error(e)
    log.info("ask mode=%s->%s %.1fs sources=%d q=%r", req.mode, r["mode"], time.time() - t0, len(r["sources"]), req.question[:80])
    return AskResponse(**r)


def _sse(event: str, data) -> str:
    return "event: " + event + "\ndata: " + json.dumps(data, ensure_ascii=False) + "\n\n"


@app.post("/ask/stream", dependencies=[Depends(require_api_key), Depends(rate_limit)])
def ask_stream(req: AskRequest) -> StreamingResponse:
    """Server-sent events: route, retrieval, token (answer text as it is generated), result, error.
    Closing the connection cancels the generation."""
    events: "queue.Queue[tuple[str, object] | None]" = queue.Queue()
    stop = threading.Event()

    def work() -> None:
        try:
            r = run_ask(req.question, req.mode, app.state.driver, emit=lambda e, d: events.put((e, d)), cancelled=stop.is_set)
            events.put(("result", AskResponse(**r).model_dump()))
        except InterruptedError:
            pass
        except Exception as e:
            err = _http_error(e)
            events.put(("error", {"status": err.status_code, "detail": err.detail}))
        finally:
            events.put(None)

    threading.Thread(target=work, daemon=True).start()

    def stream():
        try:
            while True:
                try:
                    item = events.get(timeout=15)
                except queue.Empty:
                    yield ": keep-alive\n\n"
                    continue
                if item is None:
                    return
                yield _sse(*item)
        finally:
            stop.set()  # client gone or finished: stop generating

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
