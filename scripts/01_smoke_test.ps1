# Smoke test of the stack. Run from the repo root:  .\scripts\smoke_test.ps1
$pw = ((Get-Content docker/.env | Select-String '^NEO4J_PASSWORD=').Line -split '=', 2)[1]

function Step($name, [scriptblock]$cmd) {
    Write-Host "`n=== $name" -ForegroundColor Cyan
    & $cmd
    if ($LASTEXITCODE -ne 0) { Write-Host "FAILED: $name" -ForegroundColor Red; exit 1 }
    Write-Host "OK: $name" -ForegroundColor Green
}

Step "HDFS: write a file" {
    docker exec namenode hdfs dfs -mkdir -p /data/raw /data/processed
    docker exec namenode bash -c "echo hello-hdfs > /tmp/hello.txt && hdfs dfs -put -f /tmp/hello.txt /data/raw/hello.txt"
}
Step "HDFS: read it back" {
    docker exec namenode hdfs dfs -cat /data/raw/hello.txt
}
Step "Spark: job reading and writing HDFS" {
    docker exec spark-master /opt/spark/bin/spark-submit --master spark://spark-master:7077 --driver-memory 512m --executor-memory 512m /opt/spark/jobs/smoke_test.py
}
Step "Neo4j: Cypher + plugins" {
    docker exec neo4j cypher-shell -u neo4j -p $pw "RETURN 1 AS ok, gds.version() AS gds, apoc.version() AS apoc"
}
Write-Host "`nStack OK. Last check (LLM call) depends on your chosen model." -ForegroundColor Green