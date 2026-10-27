"""Spark ETL: build the graph tables (nodes and edges) from the pipeline outputs stored in HDFS.

Inputs (under --base, default hdfs://namenode:9000/data):
  resolved/<dir>.json      canonical vendors, products and links (05_resolve_entities.py)
  extracted/<dir>/*.json   one record per CVE, with the source text (03_extract.py)
  raw/kev.csv              CISA Known Exploited Vulnerabilities catalogue (01_ingest.py)

What Spark does (validation, deduplication, transformation):
  * explicit schemas: a missing or empty array never breaks the job;
  * validation: drops rows with a null key or a dangling reference (counted and printed);
  * deduplication: one row per node id, one row per edge;
  * transformation: CHAINED_WITH edges are made undirected (a < b), weakness phrases are
    normalised into shared Weakness nodes, CVEs mentioned only in a chain become stub nodes,
    CVE nodes are enriched with KEV fields (a join between JSON and CSV);
  * output: one CSV per table in <base>/processed/graph/<table>/ (arrays joined with '|').

Run (from the repo root, stack running):
    .\\scripts\\03_run_etl.ps1
or by hand:
    docker exec spark-master /opt/spark/bin/spark-submit --master spark://spark-master:7077 \\
        --driver-memory 512m --executor-memory 512m /opt/spark/jobs/build_graph.py
"""
import argparse

from pyspark.sql import SparkSession, functions as F
from pyspark.sql.types import ArrayType, BooleanType, StringType, StructField, StructType

CVE_RE = r"^CVE-\d{4}-\d{4,}$"


def struct(*names, arrays=()):
    return ArrayType(StructType([
        StructField(n, ArrayType(StringType()) if n in arrays else StringType()) for n in names
    ]))


RESOLVED_SCHEMA = StructType([
    StructField("vendors", struct("id", "name", "aliases", arrays=("aliases",))),
    StructField("products", struct("id", "name", "vendor_id", "aliases", arrays=("aliases",))),
    StructField("affects", struct("cve", "product_id", "versions_raw", arrays=("versions_raw",))),
    StructField("chained_with", struct("cve", "other")),
    StructField("weakness_phrases", struct("cve", "phrase")),
    StructField("cwe_explicit", struct("cve", "cwe")),
])

RECORD_SCHEMA = StructType([
    StructField("cve", StringType()),
    StructField("valid", BooleanType()),
    StructField("source_text", StringType()),
])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--base", default="hdfs://namenode:9000/data")
    parser.add_argument("--dir", default="llama3.2")
    args = parser.parse_args()
    base = args.base.rstrip("/")

    spark = SparkSession.builder.appName("build-graph").getOrCreate()
    spark.sparkContext.setLogLevel("WARN")
    report = {}

    # ------------------------------------------------------------------ read
    res = spark.read.schema(RESOLVED_SCHEMA).option("multiLine", True).json(f"{base}/resolved/{args.dir}.json")
    records = (spark.read.schema(RECORD_SCHEMA).option("multiLine", True)
               .json(f"{base}/extracted/{args.dir}/*.json").filter(F.col("valid")))
    kev = (spark.read.option("header", True).option("multiLine", True).option("escape", '"')
           .csv(f"{base}/raw/kev.csv"))
    kev = kev.toDF(*[c.lstrip("\ufeff") for c in kev.columns])  # drop a possible BOM in the header

    def table(col: str, alias: str):
        return res.select(F.explode(col).alias(alias)).select(f"{alias}.*")

    # ----------------------------------------------------------- nodes: CVE
    corpus = records.select(F.col("cve").alias("cve_id"), F.col("source_text").alias("text")).dropDuplicates(["cve_id"])
    corpus_ids = corpus.select("cve_id")
    report["cve_in_corpus"] = corpus.count()

    chained_raw = table("chained_with", "c")
    chained = (chained_raw
               .filter(F.col("cve").rlike(CVE_RE) & F.col("other").rlike(CVE_RE) & (F.col("cve") != F.col("other")))
               .select(F.least("cve", "other").alias("cve_a"), F.greatest("cve", "other").alias("cve_b"))
               .distinct())  # undirected: (a,b) and (b,a) become one edge
    report["chained_edges_raw"] = chained_raw.count()
    report["chained_edges"] = chained.count()

    stubs = (chained.select(F.col("cve_a").alias("cve_id"))
             .union(chained.select(F.col("cve_b").alias("cve_id"))).distinct()
             .join(corpus_ids, "cve_id", "left_anti"))
    cves = (corpus.withColumn("in_corpus", F.lit(True))
            .unionByName(stubs.withColumn("text", F.lit(None).cast("string")).withColumn("in_corpus", F.lit(False))))
    kev_cols = kev.select(F.col("cveID").alias("cve_id"), F.col("dateAdded").alias("date_added"),
                          F.col("knownRansomwareCampaignUse").alias("ransomware_use"))
    cves = cves.join(kev_cols, "cve_id", "left")
    report["cve_stub_nodes"] = stubs.count()

    # --------------------------------------------- nodes: Vendor and Product
    vendors = (table("vendors", "v").filter(F.col("id").isNotNull()).dropDuplicates(["id"])
               .select(F.col("id").alias("vendor_id"), "name", F.concat_ws("|", "aliases").alias("aliases")))
    products_all = (table("products", "p").filter(F.col("id").isNotNull()).dropDuplicates(["id"])
                    .select(F.col("id").alias("product_id"), "name", "vendor_id",
                            F.concat_ws("|", "aliases").alias("aliases")))
    dangling_vendor = (products_all.filter(F.col("vendor_id").isNotNull())
                       .join(vendors.select("vendor_id"), "vendor_id", "left_anti").count())
    report["products_with_dangling_vendor"] = dangling_vendor
    products = products_all

    # ---------------------------------------------------------- edges: AFFECTS
    affects_raw = table("affects", "a").filter(F.col("cve").isNotNull() & F.col("product_id").isNotNull())
    affects = (affects_raw.dropDuplicates(["cve", "product_id"])
               .join(products.select("product_id"), "product_id", "left_semi")
               .join(corpus_ids.withColumnRenamed("cve_id", "cve"), "cve", "left_semi")
               .select(F.col("cve").alias("cve_id"), "product_id",
                       F.concat_ws("|", "versions_raw").alias("versions_raw")))
    report["affects_edges_dropped_invalid"] = affects_raw.dropDuplicates(["cve", "product_id"]).count() - affects.count()

    # ------------------------------------- nodes and edges: Weakness phrases
    wp = (table("weakness_phrases", "w").filter(F.col("cve").isNotNull() & F.col("phrase").isNotNull())
          .withColumn("weakness_id", F.trim(F.regexp_replace(F.lower("phrase"), r"[^a-z0-9]+", " ")))
          .filter(F.col("weakness_id") != ""))
    weaknesses = wp.groupBy("weakness_id").agg(F.min("phrase").alias("name"))
    has_weakness = (wp.select(F.col("cve").alias("cve_id"), "weakness_id").distinct()
                    .join(corpus_ids, "cve_id", "left_semi"))

    # ------------------------------------------ nodes and edges: explicit CWE
    cwe_edges = (table("cwe_explicit", "x").filter(F.col("cwe").isNotNull())
                 .select(F.col("cve").alias("cve_id"), F.col("cwe").alias("cwe_id")).distinct()
                 .join(corpus_ids, "cve_id", "left_semi"))
    cwes = cwe_edges.select("cwe_id").distinct()

    # ------------------------------------------------------------------ write
    outputs = {
        "cves": cves, "vendors": vendors, "products": products, "weaknesses": weaknesses, "cwes": cwes,
        "affects": affects, "chained": chained, "has_weakness": has_weakness, "mentions_cwe": cwe_edges,
    }
    for name, df in outputs.items():
        df = df.cache()
        path = f"{base}/processed/graph/{name}"
        (df.coalesce(1).write.mode("overwrite").option("header", True)
         .option("quoteAll", True).option("escape", '"').csv(path))
        report[f"rows_{name}"] = df.count()
        print(f"[write] {name}: {report[f'rows_{name}']} rows -> {path}")

    print("\nETL REPORT")
    for k, v in report.items():
        print(f"  {k}: {v}")
    print("SPARK ETL OK")
    spark.stop()


if __name__ == "__main__":
    main()