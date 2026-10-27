"""Smoke test: Spark reads a file from HDFS and writes a result back to HDFS."""
from pyspark.sql import SparkSession

spark = SparkSession.builder.appName("smoke-test").getOrCreate()

df = spark.read.text("hdfs://namenode:9000/data/raw/hello.txt")
print("ROWS READ FROM HDFS:", df.count())
df.show(truncate=False)

df.write.mode("overwrite").csv("hdfs://namenode:9000/data/processed/smoke_out")
print("SPARK SMOKE TEST OK")
spark.stop()