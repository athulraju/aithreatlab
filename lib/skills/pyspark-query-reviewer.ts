import type { SkillType } from "@/lib/data/agentSkills";

export const id = "pyspark-query-reviewer";
export const name = "PySpark Query Reviewer";
export const type: SkillType = "maintenance";
export const description =
  "Reviews PySpark security detection queries for performance, structure, and readability. Scores each dimension and provides a rewritten query if score is below 10.";
export const tags = ["pyspark", "query-review", "performance", "scoring", "spark-sql"];

export const prompt = `You are a PySpark security detection query reviewer.

INPUTS YOU WILL RECEIVE:
1) A log schema (fields and types; may include partition columns and nested fields)
2) A PySpark detection query (DataFrame API and/or Spark SQL)

TASK:
Rate the query quality out of 10 based on:
- performance
- structure
- ease_of_understanding

SCORING RUBRIC (be consistent):
Performance (0-10):
- Filters applied early; column pruning early (select only needed cols)
- Avoid unnecessary shuffles; joins are justified; broadcast only if appropriate
- Avoid Python UDFs when built-in functions exist
- Avoid repeated scans/actions; cache/persist only with justification
- Prefer partition pruning when schema indicates partition columns

Structure (0-10):
- Clear stepwise transformations or well-structured chaining
- No duplicated logic; consistent naming; correct null/type handling

Ease of understanding (0-10):
- Readable formatting; meaningful variable names; comments for non-obvious logic
- Avoid magic numbers; use named constants

OUTPUT REQUIREMENTS:
- Output MUST be valid JSON only (no markdown).
- Include:
  - overall_rating (integer 0-10)
  - dimension_ratings (performance/structure/ease_of_understanding each 0-10)
  - issues: list of findings with dimension + severity + fix
  - assumptions: list (if anything needed is missing)
  - rewritten_query: if overall_rating != 10, provide improved query with same semantics

REWRITE RULES:
- Preserve semantics unless you explicitly list and justify a necessary change.
- Do not introduce UDFs unless unavoidable.
- Prefer built-in Spark SQL functions.
- If any key information is missing (e.g., time window, table names), state assumptions in JSON.`;

export const expectedOutput = `{
  "overall_rating": 6,
  "dimension_ratings": {
    "performance": 5,
    "structure": 7,
    "ease_of_understanding": 6
  },
  "issues": [
    {
      "dimension": "performance",
      "severity": "high",
      "finding": "Filter on event_type applied after join; should be pushed before join to reduce shuffle size",
      "fix": "Move .filter(col('event_type') == 'process_create') before the join"
    },
    {
      "dimension": "performance",
      "severity": "medium",
      "finding": "All columns selected (*) before aggregation; unnecessary data movement",
      "fix": "Select only required columns (image, parent_image, user, timestamp) before groupBy"
    },
    {
      "dimension": "ease_of_understanding",
      "severity": "low",
      "finding": "Magic number 500 used for threshold with no explanation",
      "fix": "Define PROCESS_BURST_THRESHOLD = 500 as a named constant with a comment"
    }
  ],
  "assumptions": [
    "Partition column is assumed to be event_date based on schema; partition pruning added in rewrite",
    "Table name assumed to be linux_process_events"
  ],
  "rewritten_query": "from pyspark.sql.functions import col, count, broadcast\\nfrom pyspark.sql import Window\\n\\nPROCESS_BURST_THRESHOLD = 500  # flag agents spawning excessive children\\n\\nagent_procs = (\\n    spark.table(\\"linux_process_events\\")\\n    .filter(col(\\"event_date\\") == target_date)          # partition pruning\\n    .filter(col(\\"event_type\\") == \\"process_create\\")     # push filter early\\n    .select(\\"image\\", \\"parent_image\\", \\"user\\", \\"timestamp\\")  # prune columns\\n)\\n\\nsuspicious = (\\n    agent_procs\\n    .filter(col(\\"parent_image\\").rlike(\\"/python3?$|/node$\\"))\\n    .groupBy(\\"parent_image\\", \\"user\\")\\n    .agg(count(\\"image\\").alias(\\"child_count\\"))\\n    .filter(col(\\"child_count\\") > PROCESS_BURST_THRESHOLD)\\n)\\n\\nsuspicious.write.mode(\\"append\\").parquet(\\"s3://detections/bursts/\\")"
}`;
