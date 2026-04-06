import { ConversionResult } from "./sigmaToSplunk";

export function sigmaToPySpark(sigma: string): ConversionResult {
  const notes: string[] = [];
  const warnings: string[] = [];

  try {
    const titleMatch = sigma.match(/^title:\s*(.+)$/m);
    const title = titleMatch ? titleMatch[1].trim() : "Unknown Detection";

    const productMatch = sigma.match(/^\s+product:\s*(.+)$/m);
    const product = productMatch ? productMatch[1].trim() : "generic";

    const categoryMatch = sigma.match(/^\s+category:\s*(.+)$/m);
    const category = categoryMatch ? categoryMatch[1].trim() : "";

    // Map data source
    let dataPath = "s3://security-lake/events/";
    let schemaComment = "# Adjust schema and data path to your environment";

    if (product === "windows") {
      dataPath = "s3://security-lake/windows/process_creation/";
      notes.push("Mapped to Windows process creation events in security lake.");
    } else if (product === "aws") {
      dataPath = "s3://security-lake/cloudtrail/";
      notes.push("Mapped to CloudTrail events in security lake.");
    } else if (product === "linux") {
      dataPath = "s3://security-lake/linux/auditd/";
    }

    // Parse detection conditions
    const detectionSection = sigma
      .split(/^detection:/m)[1]
      ?.split(/^\w+:/m)[0] || "";

    const filterClauses = buildPySparkFilters(detectionSection);

    const idMatch = sigma.match(/^id:\s*(.+)$/m);
    const ruleId = idMatch ? idMatch[1].trim() : "rule-001";

    const output = `from pyspark.sql import SparkSession
from pyspark.sql.functions import col, lower, lit
from pyspark.sql.types import StringType
from datetime import datetime, timedelta

# Detection: ${title}
# Rule ID: ${ruleId}
# Converted from Sigma rule

spark = SparkSession.builder \\
    .appName("Detection_${ruleId.replace(/-/g, "_")}") \\
    .getOrCreate()

${schemaComment}

# Load events — adjust partition filter for your time window
end_time = datetime.utcnow()
start_time = end_time - timedelta(hours=1)

df = spark.read.parquet("${dataPath}") \\
    .filter(
        (col("timestamp") >= start_time.isoformat()) &
        (col("timestamp") <= end_time.isoformat())
    )

# Apply detection logic
detections = df${filterClauses}

# Add metadata
detections = detections.withColumn("detection_id", lit("${ruleId}")) \\
    .withColumn("detection_name", lit("${title}")) \\
    .withColumn("severity", lit("high")) \\
    .withColumn("detection_time", lit(datetime.utcnow().isoformat()))

# Output findings
detections.select(
    "timestamp", "host", "user",
    "command_line", "process_image",
    "detection_id", "detection_name", "severity"
).show(50, truncate=False)

# Write to detection output store
detections.write \\
    .mode("append") \\
    .partitionBy("detection_id") \\
    .parquet("s3://detections/findings/")

print(f"Detection complete. Found {detections.count()} events.")`;

    notes.push(`Converted from Sigma rule: "${title}"`);
    notes.push("Adjust data path, schema, and partition filters to match your environment.");
    notes.push("Field names follow common security lake schema conventions.");
    warnings.push("PySpark conversion requires manual field name verification against your schema.");
    warnings.push("Time window defaults to 1 hour — adjust for production deployment.");

    return { output, notes, warnings, valid: true };
  } catch (e) {
    return {
      output: "# Conversion failed. Check Sigma rule syntax.",
      notes: [],
      warnings: ["Failed to parse Sigma rule."],
      valid: false,
    };
  }
}

function buildPySparkFilters(detection: string): string {
  const filters: string[] = [];

  // Look for image/path conditions
  if (detection.includes("endswith")) {
    const endswithMatches = detection.matchAll(/(\w+)\|endswith:\s*'([^']+)'/g);
    for (const match of endswithMatches) {
      filters.push(`    col("${snakeCase(match[1])}").endswith("${match[2]}")`);
    }
  }

  if (detection.includes("contains")) {
    const containsMatches = detection.matchAll(/(\w+)\|contains:\s*['"]([^'"]+)['"]/g);
    for (const match of containsMatches) {
      filters.push(`    lower(col("${snakeCase(match[1])}")).contains("${match[2].toLowerCase()}")`);
    }
  }

  if (filters.length === 0) {
    filters.push('    col("event_type").isNotNull()  # TODO: Add specific filter conditions');
  }

  const filterStr = filters.join(" &\n    ");
  return `.filter(\n    ${filterStr}\n)`;
}

function snakeCase(str: string): string {
  return str.replace(/([A-Z])/g, "_$1").toLowerCase().replace(/^_/, "");
}
