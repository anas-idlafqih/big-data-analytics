# État du projet — CVE Knowledge Graph & GraphRAG

Document de reprise : état consolidé au 28 octobre 2026. Le projet est au stade
de validation du benchmark ; le rescoring des réponses déjà mises en cache est
la prochaine action. Ce document est la seule modification effectuée pour cette
reprise.

## 1. Architecture (résumée)

Le pipeline suit ces étapes :

1. `pipeline/01_ingest.py` sélectionne et télécharge les CVE depuis CISA KEV et
   NVD, puis fige le corpus dans `data/manifest.json`.
2. `pipeline/02_collect_advisories.py` collecte les avis GHSA associés aux CVE.
3. `pipeline/03_extract.py` utilise Ollama en local avec Llama 3.2 pour extraire
   les produits, éditeurs, versions et types de faiblesses des textes. Les
   sorties sont validées, ancrées dans le texte source et conservées avec leur
   provenance.
4. `pipeline/04_evaluate.py` évalue les extractions contre les données NVD ;
   `pipeline/05_resolve_entities.py` normalise et fusionne les entités.
5. `scripts/03_run_etl.ps1` transfère les données locales vers HDFS, lance Spark
   dans Docker et exporte les tables CSV. `spark_jobs/build_graph.py` valide,
   déduplique et transforme les données en tables de graphe.
6. `pipeline/06_load_neo4j.py` charge ces tables dans Neo4j. `--reset` vide la
   base avant le chargement.
7. `pipeline/07_graph_analytics.py` exécute les analyses Cypher et GDS.
8. `pipeline/08_build_vector_index.py` construit dans Neo4j l’index vectoriel
   des textes de CVE avec `nomic-embed-text` (768 dimensions, similarité cosinus).
9. `pipeline/09_graphrag.py` répond en mode `graph` ou `vector` ; il est
   importable, notamment par le benchmark.
10. `pipeline/10_make_questions.py` génère les questions et leurs réponses
    gold depuis le graphe.
11. `pipeline/11_benchmark.py` compare quatre bras : `oracle_cypher`, `graph`,
    `text2cypher` et `vector`.

Schéma principal :

```text
(CVE)-[:AFFECTS]->(Product)<-[:PRODUCES]-(Vendor)
(CVE)-[:HAS_WEAKNESS]->(Weakness)
(CVE)-[:CHAINED_WITH]-(CVE)
```

Le graphe contient aussi des relations `MENTIONS_CWE` vers des nœuds `CWE`.
Les CVE citées dans une chaîne mais hors corpus deviennent des nœuds stub
(`in_corpus = false`).

## 2. État du projet (VALIDÉ — ne rien refaire)

- **Corpus et graphe :** 60 CVE dans le corpus ; 61 nœuds CVE chargés (60 du
  corpus et un stub cité dans une chaîne), 59 produits, 31 éditeurs,
  80 relations `AFFECTS` et 9 relations `CHAINED_WITH`. Le pipeline est conçu
  pour être idempotent.
- **Extraction :** le prompt v3 est figé comme référence. Pour les produits,
  précision/rappel/F1 = 75/86/80 % ; pour les éditeurs = 98/92/95 %. Le filtre
  d’ancrage a écarté zéro produit (0/81 non retrouvés dans le texte) ; les
  écarts CPE relèvent du nommage, pas de l’invention. 24 versions sur 154 ont
  été retirées, soit environ 16 %.
- **Résolution d’entités :** la fusion des formes MikroTik/Mikrotik est validée.
- **Analytics (07) :** les 10 analyses ont réussi. Les résultats, requêtes et
  limites observées sont consignés dans
  [benchmark/graph_analytics.md](./benchmark/graph_analytics.md).
- **GraphRAG (09) :** validé sur le graphe réel. En mode `graph`, les identifiants
  CVE cités dans la question sont résolus par correspondance exacte ; lorsqu’une
  CVE existe, ce lookup définit le contexte et les hits vectoriels sont écartés
  (comportement « graph v2 », ajusté après un pilote). Les réponses sont en JSON
  `{answer, sources}` ; le schéma limite les sources aux CVE du contexte fourni.
- **Questions (10) :** 22 questions, seed 42, en quatre types : A factuel,
  B multi-sauts, C agrégations et D sémantique « silver ». Les golds sont
  calculés en Python avec un oracle Cypher ; `--verify` a donné 22/22
  `ALL CONSISTENT`. Les golds ont été vérifiés manuellement contre les textes
  sources.
- **Benchmark (11) :** exécution complète ; les scores actuellement publiés
  avant rescoring sont dans
  [benchmark/results.json](./benchmark/results.json) et
  [benchmark/results.md](./benchmark/results.md). F1 avant rescoring : oracle
  Cypher 100 %, GraphRAG 53 %, Text2Cypher 50 %, vector RAG 32 %. F1 par type :
  A — GraphRAG 98 %, vector 67 %, Text2Cypher 83 % ; B — GraphRAG 84 %, vector
  34 %, Text2Cypher 50 % ; C — oracle 100 %, LLM environ 0 % ; D — Text2Cypher
  49 %, vector 23 %, GraphRAG 13 %. GraphRAG est aussi meilleur en précision
  des sources (85 % contre 70 %) et en latence médiane (15,9 s contre 23,3 s).
- **Scoring à actualiser :** les réponses en cache ont été notées avant le
  correctif de matching sensible à la casse des noms courts (par ex. `F5`).
  C’est pourquoi B2-1 donne encore 0,91 pour l’oracle dans les résultats
  actuels. Le fichier `pipeline/11_benchmark.py` présent dans l’arbre de travail
  contient déjà ce correctif ainsi que `--rescore` : le rescoring du cache
  reste à faire. La prochaine commande est
  `python pipeline/11_benchmark.py --rescore` (après activation du venv et
  démarrage de Neo4j ; aucun appel au modèle LLM n’est requis). Elle doit faire
  passer B2-1 à 1,00 pour l’oracle et recalculer également les bras vector et
  GraphRAG.

## 3. Décisions méthodologiques à respecter

- Le gold décrit **le graphe construit à partir de l’extraction LLM**, pas la
  réalité indépendante de ce graphe.
- Les questions de type D sont des golds « silver », obtenus par matching de
  mots-clés dans le texte des CVE.
- Les prompts GraphRAG et Text2Cypher ont été ajustés une fois après un pilote
  de quatre questions ; ces questions font partie du benchmark et cet ajustement
  doit être déclaré dans le rapport.
- Il n’y a qu’un run par question et par bras : les écarts sont indicatifs et
  ne constituent pas des résultats statistiques.
- L’extraction reste figée en v3. Un éventuel prompt v4 ne doit être envisagé
  qu’en fin de projet, avec une comparaison avant/après.

## 4. Ce qui reste à faire (dans l’ordre)

1. **Rescorer le cache existant.** Le remplacement par la version patchée n’est
   pas à refaire : `pipeline/11_benchmark.py` dans l’arbre de travail contient
   déjà le matching `F5` sensible à la casse et l’option `--rescore`. Depuis la
   racine, venv activé et Neo4j disponible :

   ```powershell
   python pipeline/11_benchmark.py --rescore
   ```

   Vérifier dans la sortie et les fichiers de résultats que B2-1 passe à 1,00
   pour l’oracle et que les scores vector/GraphRAG sont recalculés. Cette option
   recalcule les scores des réponses en cache sans relancer les modèles ; coller
   la sortie pour confirmer le rescoring.
2. **Commit + push** les changements voulus sur la branche `main`. Vérifier
   d’abord les changements à inclure : l’arbre de travail contient déjà des
   modifications locales hors de ce document, notamment
   `benchmark/questions.json`, `benchmark/results.md`, `pipeline/09_graphrag.py`,
   `pipeline/10_make_questions.py`, ainsi que `benchmark/results.json` et
   `pipeline/11_benchmark.py` non suivis.
   Ne pas les écraser ni les inclure sans les avoir revus.
3. **API :** créer une API FastAPI avec `POST /ask` appelant
   `pipeline/09_graphrag.answer(question, mode)` (déjà importable) et renvoyant
   `{answer, sources, latency, context_cves}`.
4. **Interface :** ajouter une page simple ou une application Streamlit qui
   interroge `/ask` et permet de choisir le mode.
5. **README final :** documenter l’architecture, les commandes de relance de
   bout en bout et un tableau des résultats du benchmark.
6. **Rapport final :** présenter le contexte, le pipeline, l’évaluation de
   l’extraction, les analytics et le benchmark. Le tableau F1 par type est la
   figure centrale ; discuter les échecs qualitatifs de Text2Cypher et des
   agrégations, ainsi que les limites méthodologiques de la section 3.

## 5. Environnement

- **OS et Python :** Windows + PowerShell. Activer le venv `.venv` avant les
  commandes Python, sinon l’import Neo4j échoue (`No module named 'neo4j'`).
  Depuis la racine du dépôt :

  ```powershell
  .\.venv\Scripts\Activate.ps1
  ```

- **Docker Compose :** Neo4j répond sur `bolt://localhost:7687` ; son mot de
  passe est dans `docker/.env`, exclu du dépôt. HDFS et Spark tournent également
  dans Docker. Après `docker compose start`, le namenode met une à deux minutes
  à accepter les connexions ; le script ETL attend sa disponibilité.
- **Ollama local :** Llama 3.2 pour le chat et `nomic-embed-text` pour les
  embeddings. Pour les exécutions LLM, garder le PC branché et fermer les autres
  applications ; arrêter les conteneurs Spark/HDFS libère de la mémoire.
- **Git :** dépôt GitHub, branche `main`, commits découpés par fonctionnalité.

## 6. Règles de collaboration

- Ne jamais réécrire de scratch un script existant : faire des patchs ciblés.
- Toujours tester avec de faux serveurs ou des données de test avant de demander
  une exécution réelle.
- Donner les commandes PowerShell une par ligne et demander à l’utilisateur de
  coller la sortie.
- Signaler explicitement tout ajustement fait après avoir vu des questions du
  jeu de test, notamment les ajustements du pilote de quatre questions.

## Décalages observés dans les fichiers actuels

- Le README actuel est un aperçu anglais ancien : il indique notamment Mistral,
  laisse la procédure « How to Run » à compléter et ne reflète pas le pipeline
  validé ci-dessus. Il devra être mis à jour à l’étape 5.
- Les docstrings de `pipeline/01_ingest.py` et `pipeline/02_collect_advisories.py`
  citent encore des noms de scripts antérieurs (`ingest.py` et
  `fetch_advisories.py`) dans leurs exemples ; les fichiers exécutables actuels
  sont numérotés.
- Le rapport `benchmark/results.md` n’a pas encore été régénéré après le
  correctif de scoring ; ses valeurs reflètent donc le cache avant `--rescore`.
