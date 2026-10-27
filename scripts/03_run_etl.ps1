# ETL: local files -> HDFS -> Spark -> graph CSV tables exported to data/processed.
# Run from the repo root, with the stack up:   .\scripts\03_run_etl.ps1
# Optional:                                    .\scripts\03_run_etl.ps1 -Dir llama3.2
# Prerequisites: 05_resolve_entities.py has been run (data/resolved/<Dir>.json exists).
param([string]$Dir = "llama3.2")
$ErrorActionPreference = "Stop"

function dk {
    docker @args
    if ($LASTEXITCODE -ne 0) { throw "docker command failed: docker $args" }
}
function Step($name) { Write-Host "`n=== $name" -ForegroundColor Cyan }

if (-not (Test-Path "data/resolved/$Dir.json")) {
    throw "data/resolved/$Dir.json not found. Run: python pipeline/05_resolve_entities.py"
}

Step "Waiting for HDFS (the namenode needs 1-2 minutes after a start)"
$prev = $ErrorActionPreference
$ErrorActionPreference = "Continue"   # native-command errors must not stop the retry loop
$ready = $false
for ($i = 0; $i -lt 36; $i++) {
    docker exec namenode hdfs dfs -ls / *> $null
    if ($LASTEXITCODE -eq 0) { $ready = $true; break }
    Start-Sleep -Seconds 5
}
$ErrorActionPreference = $prev
if (-not $ready) { throw "HDFS not reachable after 3 minutes. Check: docker compose -f docker/docker-compose.yml ps" }
dk exec namenode hdfs dfsadmin -safemode wait

Step "HDFS: create folders"
dk exec namenode hdfs dfs -mkdir -p /data/raw /data/extracted /data/resolved /data/processed

Step "HDFS: upload (idempotent, -f overwrites)"
dk exec namenode hdfs dfs -put -f /host-data/raw/kev.csv /data/raw/
dk exec namenode hdfs dfs -put -f /host-data/raw/nvd /data/raw/
dk exec namenode hdfs dfs -put -f /host-data/raw/advisories /data/raw/
dk exec namenode hdfs dfs -put -f /host-data/extracted/$Dir /data/extracted/
dk exec namenode hdfs dfs -put -f /host-data/resolved/$Dir.json /data/resolved/
dk exec namenode hdfs dfs -ls -R /data/raw /data/extracted /data/resolved | Select-Object -First 15

Step "Spark: build the graph tables"
dk exec spark-master /opt/spark/bin/spark-submit --master spark://spark-master:7077 --driver-memory 512m --executor-memory 512m /opt/spark/jobs/build_graph.py --dir $Dir

Step "HDFS -> data/processed (CSV for Neo4j)"
$tables = "cves", "vendors", "products", "weaknesses", "cwes", "affects", "chained", "has_weakness", "mentions_cwe"
foreach ($t in $tables) {
    dk exec namenode bash -c "rm -f /host-data/processed/$t.csv && hdfs dfs -getmerge /data/processed/graph/$t /host-data/processed/$t.csv"
    Write-Host "  exported $t.csv"
}

Write-Host "`nETL DONE. Next: python pipeline/06_load_neo4j.py" -ForegroundColor Green