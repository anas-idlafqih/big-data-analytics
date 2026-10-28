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
    OLLAMA_HOST      adresse d'Ollama pour /health (defaut http://127.0.0.1:11434)
"""
import importlib
import logging
import os
import secrets
import sys
import threading
import time
import urllib.request
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal, Optional

from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from neo4j.exceptions import AuthError, Neo4jError, ServiceUnavailable, SessionExpired
from pydantic import BaseModel, field_validator

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "pipeline"))  # les scripts importent "ollama_client" directement

import ollama_client  # noqa: E402

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
    mode: Literal["graph", "vector"] = "graph"

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
    mode: str
    sources: list[str]
    context_cves: list[str]
    retrieval_s: float
    generation_s: float


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


@app.post("/ask", response_model=AskResponse, dependencies=[Depends(require_api_key)])
def ask(req: AskRequest) -> AskResponse:
    # "def" (et non "async def") : FastAPI l'execute dans un thread, le serveur reste reactif
    # pendant les 10 a 60 s de generation sur CPU.
    t0 = time.time()
    try:
        r = rag.answer(req.question, mode=req.mode, k=TOP_K, driver=app.state.driver)
    except ollama_client.OllamaError as e:
        log.warning("Ollama error: %s", e)
        raise HTTPException(status_code=503, detail=f"Ollama indisponible : {e}")
    except (ServiceUnavailable, SessionExpired, AuthError) as e:
        log.warning("Neo4j error: %s", e)
        raise HTTPException(status_code=503, detail="Neo4j indisponible ou authentification refusee")
    except Neo4jError as e:
        log.exception("Neo4j query error")
        raise HTTPException(status_code=500, detail=f"Erreur Neo4j : {e.code}")
    except Exception:
        log.exception("Unexpected error")
        raise HTTPException(status_code=500, detail="Erreur interne inattendue (voir les logs du serveur)")
    log.info("ask mode=%s %.1fs sources=%d q=%r", req.mode, time.time() - t0, len(r["sources"]), req.question[:80])
    return AskResponse(
        answer=r["answer"],
        mode=req.mode,
        sources=list(r["sources"]),
        context_cves=list(r["context_cves"]),
        retrieval_s=round(r["retrieval_s"], 2),
        generation_s=round(r["generation_s"], 2),
    )