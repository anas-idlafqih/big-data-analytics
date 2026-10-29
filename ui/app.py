"""Interface Streamlit pour l'API GraphRAG (api/app.py) — version professionnelle.

Lancement (depuis la racine du depot, venv active, API demarree sur le port 8000) :
    python -m streamlit run ui/app.py

L'interface n'appelle que l'API HTTP (POST /ask, GET /health) : elle ne touche ni Neo4j
ni Ollama, ce qui garde le controle d'acces cote API.
Variables d'environnement facultatives (valeurs par defaut des champs de la barre laterale) :
    API_URL   adresse de l'API (defaut http://127.0.0.1:8000)
    API_KEY   cle d'API a envoyer dans l'en-tete X-API-Key

Fonctions projet couvertes (Phase 7) :
  - Monitoring   : st.metric pour la latence de recuperation, de generation, taille du contexte
  - Explainability: reponse mise en valeur, sources en badges verts, CVE du contexte cliquables (NVD)
  - Access control: cle X-API-Key + pastille de statut (accessible / 401 / injoignable)
  - Comparaison  : mode graph vs vector cote a cote, liseres vert/rouge, conclusion automatique
  - Theme        : commutable clair/sombre, conserve en session
"""
import html
import os
import re

import requests
import streamlit as st

TIMEOUT_S = 180  # la generation sur CPU prend 10 a 60 s
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")

# (icone, titre, description courte, question) — les trois familles du benchmark
EXAMPLES = [
    ("🎯", "Factual (1 hop)", "Products affected by one CVE", "Which products does CVE-2026-21589 affect?"),
    ("🔗", "Multi-hop (exploit chain)", "CVEs chained with a given CVE", "Which CVEs are chained with CVE-2026-105133?"),
    ("📊", "Aggregation", "Products hit by more than one CVE", "Which products are affected by more than one CVE?"),
]
MODE_HELP = {
    "graph": "GraphRAG: CVE ids cited in the question are resolved exactly in the graph, then the exploit chain is followed.",
    "vector": "Classic RAG: the 5 CVE texts closest to the question by embedding similarity.",
}
NVD_URL = "https://nvd.nist.gov/vuln/detail/{}"

st.set_page_config(page_title="CVE Knowledge Graph — GraphRAG", layout="wide",
                   initial_sidebar_state="expanded")
st.session_state.setdefault("question", "")
st.session_state.setdefault("theme", "dark")        # "dark" ou "light"
st.session_state.setdefault("last", None)            # dernier resultat affiche
st.session_state.setdefault("auth_state", None)      # None | "ok" | "401" | "unreachable"
st.session_state.setdefault("health", None)          # dernier GET /health


# --------------------------------------------------------------------------- #
# CSS : deux palettes, un theme par variable de session
# --------------------------------------------------------------------------- #
PALETTES = {
    "dark": ":root{--bg:#0E1117;--card:#161B22;--text:#E6EDF3;--muted:#9BA3AF;"
            "--accent:#00FFCC;--accent-dim:rgba(0,255,204,.12);--border:#2B313B;"
            "--ok:#22C55E;--ok-dim:rgba(34,197,94,.12);--danger:#FF6B6B;--danger-dim:rgba(255,107,107,.10);}",
    "light": ":root{--bg:#FAFBFC;--card:#FFFFFF;--text:#1F2328;--muted:#57606A;"
             "--accent:#00875A;--accent-dim:rgba(0,135,90,.08);--border:#D8DEE4;"
             "--ok:#1A7F37;--ok-dim:rgba(26,127,55,.10);--danger:#CF222E;--danger-dim:rgba(207,34,46,.08);}",
}

BASE_CSS = """
<style>
%PALETTE%
.stApp { background: var(--bg); color: var(--text); }
section[data-testid="stSidebar"] { background: var(--card); border-right: 1px solid var(--border); }
section[data-testid="stSidebar"] * { color: var(--text); }
h1, h2, h3, h4, h5, h6, p, span, label, li { color: var(--text) !important; }
.stButton > button {
    background: var(--card); color: var(--text); border: 1px solid var(--border);
    border-radius: 10px; padding: .45rem .9rem; font-weight: 500;
    transition: border-color .15s, box-shadow .15s; width: 100%;
}
.stButton > button:hover { border-color: var(--accent); box-shadow: 0 0 0 1px var(--accent); color: var(--text); }
.stButton > button[kind="primary"] {
    background: var(--accent-dim); color: var(--accent); border: 1px solid var(--accent); font-weight: 600;
}
div[data-testid="stMetric"] {
    background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: .8rem;
}
div[data-testid="stMetricLabel"] p { color: var(--muted) !important; font-size: .8rem; }
div[data-testid="stMetricValue"] { color: var(--text); }
[data-baseweb="input"], [data-baseweb="textarea"] {
    background: var(--card) !important; border-radius: 8px;
}
div[data-testid="stExpander"] { background: var(--card); border: 1px solid var(--border); border-radius: 10px; }
div[data-testid="stExpander"] details { border: none; }
hr { border-color: var(--border); }

/* Cartes d'exemples */
.ex-card {
    background: var(--card); border: 1px solid var(--border); border-radius: 12px;
    padding: .8rem 1rem; height: 100%; margin-bottom: .4rem;
}
.ex-card .ex-icon { font-size: 1.6rem; }
.ex-card .ex-title { font-weight: 700; color: var(--text); margin-top: .25rem; }
.ex-card .ex-desc { color: var(--muted); font-size: .82rem; margin-top: .15rem; }

/* Encadre de reponse : point focal de la page */
.answer-box {
    background: var(--card); border: 1px solid var(--accent); border-left: 4px solid var(--accent);
    border-radius: 10px; padding: 1rem 1.1rem; font-size: 1.05rem; line-height: 1.55;
    color: var(--text); box-shadow: 0 0 12px var(--accent-dim);
}

/* Badges sources (verts) et CVE du contexte (neutres, cliquables) */
.badge {
    display: inline-block; margin: .15rem .25rem .15rem 0; padding: .18rem .6rem;
    border-radius: 999px; font-size: .82rem; font-family: ui-monospace, Consolas, monospace;
    text-decoration: none;
}
.badge-src { background: var(--ok-dim); color: var(--ok); border: 1px solid var(--ok); }
.badge-ctx { background: var(--card); color: var(--text); border: 1px solid var(--border); }
.badge-ctx:hover { border-color: var(--accent); }
.muted { color: var(--muted); font-size: .85rem; }

/* Bandeaux des colonnes de comparaison */
.banner {
    border-radius: 10px; padding: .5rem .9rem; font-weight: 700; margin-bottom: .6rem;
}
.banner-graph { background: var(--ok-dim); color: var(--ok); border-left: 4px solid var(--ok); }
.banner-vector { background: var(--danger-dim); color: var(--danger); border-left: 4px solid var(--danger); }

/* Pastille de statut (controle d'acces) */
.pill {
    display: inline-flex; align-items: center; gap: .45rem; padding: .3rem .75rem;
    border-radius: 999px; font-size: .85rem; font-weight: 600; border: 1px solid;
}
.pill-ok { background: var(--ok-dim); color: var(--ok); border-color: var(--ok); }
.pill-bad { background: var(--danger-dim); color: var(--danger); border-color: var(--danger); }
.pill-off { background: var(--card); color: var(--muted); border-color: var(--border); }
.dot { width: .55rem; height: .55rem; border-radius: 50%; display: inline-block; }
.dot-ok { background: var(--ok); } .dot-bad { background: var(--danger); } .dot-off { background: var(--muted); }
</style>
"""

st.markdown(BASE_CSS.replace("%PALETTE%", PALETTES[st.session_state.theme]),
            unsafe_allow_html=True)


def inject_html(fragment: str) -> None:
    st.markdown(fragment, unsafe_allow_html=True)


def badges(items, css_class: str, link: bool = False) -> str:
    """Badges HTML ; si link=True, chaque badge pointe vers la fiche NVD."""
    if not items:
        return '<span class="muted">none</span>'
    out = []
    for c in items:
        if link:
            out.append(f'<a class="badge {css_class}" href="{NVD_URL.format(c)}" target="_blank">{html.escape(c)}</a>')
        else:
            out.append(f'<span class="badge {css_class}">{html.escape(c)}</span>')
    return " ".join(out)


def set_question(text: str) -> None:
    st.session_state.question = text


def toggle_theme() -> None:
    st.session_state.theme = "light" if st.session_state.theme == "dark" else "dark"


def call_api(base_url: str, api_key: str, question: str, mode: str):
    """Renvoie (donnees, None) ou (None, message d'erreur lisible)."""
    headers = {"X-API-Key": api_key} if api_key else {}
    try:
        r = requests.post(base_url.rstrip("/") + "/ask", json={"question": question, "mode": mode},
                          headers=headers, timeout=TIMEOUT_S)
    except requests.exceptions.ConnectionError:
        return None, "API unreachable. Start it: python -m uvicorn api.app:app --port 8000"
    except requests.exceptions.Timeout:
        return None, f"Timeout ({TIMEOUT_S} s): the local model may be overloaded."
    except requests.exceptions.RequestException as e:
        return None, f"Network error: {e}"
    if r.status_code == 200:
        st.session_state.auth_state = "ok"
        return r.json(), None
    if r.status_code == 401:
        st.session_state.auth_state = "401"
    try:
        detail = r.json().get("detail", r.text)
    except ValueError:
        detail = r.text[:200]
    return None, f"Error {r.status_code}: {detail}"


def check_health(base_url: str) -> dict | None:
    """GET /health (public). Renvoie le JSON ou None si injoignable."""
    try:
        h = requests.get(base_url.rstrip("/") + "/health", timeout=5)
        if h.status_code == 200:
            return h.json()
        return None
    except requests.exceptions.RequestException:
        return None


def auth_pill_html() -> str:
    """Pastille de statut du controle d'acces, basee sur /health et le dernier /ask."""
    if st.session_state.health is None:
        return ('<span class="pill pill-off"><span class="dot dot-off"></span>API offline</span>')
    if st.session_state.auth_state == "401":
        return ('<span class="pill pill-bad"><span class="dot dot-bad"></span>Unauthorized (401)</span>')
    return ('<span class="pill pill-ok"><span class="dot dot-ok"></span>API online</span>')


def show_result(mode: str, data, error) -> None:
    """Un panneau de resultat : encadre de reponse, badges, 3 metriques, contexte."""
    banner = ('<div class="banner banner-graph">🟢 GraphRAG (recommended)</div>' if mode == "graph"
              else '<div class="banner banner-vector">⚪ RAG vector (baseline)</div>')
    inject_html(banner)
    if error:
        st.error(error)
        return
    inject_html(f'<div class="answer-box">{html.escape(data["answer"] or "(empty answer)")}</div>')

    inject_html('<p class="muted" style="margin:.6rem 0 .2rem 0">Sources declared by the model '
                '— restricted to the CVEs of the retrieved context: a source cannot be invented.</p>')
    inject_html(badges(data["sources"], "badge-src"))
    st.markdown("")

    c1, c2, c3 = st.columns(3)
    c1.metric("Graph retrieval", f"{data['retrieval_s']:.1f} s")
    c2.metric("LLM generation", f"{data['generation_s']:.1f} s")
    c3.metric("CVEs in context", len(data["context_cves"]))

    with st.expander(f"CVEs given to the model ({len(data['context_cves'])}) — click a badge to open its NVD page"):
        inject_html(badges(data["context_cves"], "badge-ctx", link=True))


def comparison_conclusion(question: str, outcome: dict) -> None:
    """Conclusion automatique (heuristique, sans LLM) du mode comparaison."""
    g, v = outcome.get("graph", (None, None)), outcome.get("vector", (None, None))
    if g[1] or v[1]:  # au moins une erreur : pas de conclusion
        return
    q_ids = set(CVE_RE.findall(question))
    if q_ids:
        in_graph = q_ids & set(g[0]["context_cves"])
        in_vector = q_ids & set(v[0]["context_cves"])
        if in_graph and not in_vector:
            st.success("The **graph** mode resolved the exact CVE id cited in the question and followed its "
                       "exploit chain — the vector mode did not even retrieve it. "
                       "This is the core benefit of the knowledge graph.")
            return
        if in_graph and in_vector:
            st.info("Both modes retrieved the CVE id cited in the question; compare the answers and sources above.")
            return
    st.info("Answers from both modes are shown side by side. Compare the sources: only the graph mode "
            "can walk the exploit chain between CVEs.")


# --------------------------------------------------------------------------- #
# Barre laterale
# --------------------------------------------------------------------------- #
with st.sidebar:
    st.header("⚙️ Configuration")
    st.button("🌙 Dark mode" if st.session_state.theme == "light" else "☀️ Light mode",
              on_click=toggle_theme, use_container_width=True)
    api_url = st.text_input("API URL", os.getenv("API_URL", "http://127.0.0.1:8000"))
    api_key = st.text_input("API key (X-API-Key)", os.getenv("API_KEY", ""), type="password",
                            help="Leave empty if the API is not protected.")
    mode = st.radio("Mode", ["graph", "vector"], help="Used by the 'Ask' button.")
    st.caption(MODE_HELP[mode])

    if "health" not in st.session_state or st.session_state.health is None:
        st.session_state.health = check_health(api_url)
    inject_html(auth_pill_html())
    st.markdown("")

    if st.button("Test connection", key="health_btn", use_container_width=True):
        st.session_state.health = check_health(api_url)
        if st.session_state.health is None:
            st.error("API unreachable.")
        else:
            h = st.session_state.health
            line = f"Neo4j: {'ok' if h['neo4j'] else 'KO'} | Ollama: {'ok' if h['ollama'] else 'KO'}"
            (st.success if h["status"] == "ok" else st.warning)(line)

# --------------------------------------------------------------------------- #
# Page principale
# --------------------------------------------------------------------------- #
st.title("🛡️ CVE Knowledge Graph — GraphRAG")
st.caption("Questions in English, as in the benchmark test set. The corpus holds 60 CVE.")

cols = st.columns(len(EXAMPLES))
for i, (icon, title, desc, question) in enumerate(EXAMPLES):
    with cols[i]:
        inject_html(f'<div class="ex-card"><div class="ex-icon">{icon}</div>'
                    f'<div class="ex-title">{html.escape(title)}</div>'
                    f'<div class="ex-desc">{html.escape(desc)}</div></div>')
        st.button(title, key=f"ex{i}", on_click=set_question, args=(question,),
                  use_container_width=True)

st.text_area("Question", key="question", height=90)
b1, b2, _ = st.columns([1, 1.4, 4])
ask_clicked = b1.button("Ask", key="ask", type="primary", use_container_width=True)
compare_clicked = b2.button("Compare graph vs vector", key="compare", use_container_width=True)

if ask_clicked or compare_clicked:
    question = st.session_state.question.strip()
    if not question:
        st.warning("Enter a question first.")
    else:
        modes = [mode] if ask_clicked else ["graph", "vector"]
        outcome = {}
        with st.spinner("Generating (10–60 s on CPU)..."):
            for m in modes:
                outcome[m] = call_api(api_url, api_key, question, m)
        st.session_state.last = {"question": question, "outcome": outcome}

last = st.session_state.get("last")
if last:
    st.divider()
    inject_html(f'<p><strong>Question:</strong> {html.escape(last["question"])}</p>')
    results = list(last["outcome"].items())
    for col, (m, (data, error)) in zip(st.columns(len(results)), results):
        with col:
            show_result(m, data, error)
    if len(results) == 2:
        comparison_conclusion(last["question"], last["outcome"])