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

    const idMatch = sigma.match(/^id:\s*(.+)$/m);
    const ruleId = idMatch ? idMatch[1].trim() : "rule-001";

    // Map table name from product/category
    let tableName = "security_events";
    if (product === "windows" && category === "process_creation") {
      tableName = "windows_process_creation";
    } else if (product === "windows") {
      tableName = "windows_events";
    } else if (product === "aws") {
      tableName = "cloudtrail_events";
    } else if (product === "linux") {
      tableName = "linux_audit_events";
    } else if (product === "api_gateway" || category === "application_log") {
      tableName = "api_gateway_logs";
    }

    // Parse detection section for SQL WHERE conditions
    const detectionSection = sigma
      .split(/^detection:/m)[1]
      ?.split(/^(?:falsepositives|level|tags|fields|references|author|date|status|logsource|title|id|description):/m)[0] || "";

    const whereClause = buildSQLWhere(detectionSection);

    // Determine SELECT fields based on category
    let selectFields = "timestamp, host, user, source_ip";
    if (category === "process_creation") {
      selectFields = "timestamp, computer_name AS host, user, image, command_line, parent_image, parent_command_line";
    } else if (category === "network_connection") {
      selectFields = "timestamp, computer_name AS host, user, image, destination_ip, destination_hostname, destination_port";
    } else if (category === "file_event" || category === "file_access") {
      selectFields = "timestamp, computer_name AS host, user, image, target_filename";
    } else if (product === "aws") {
      selectFields = "event_time AS timestamp, source_ip_address AS source_ip, user_identity_arn, event_name, request_parameters";
    }

    const output = `from pyspark.sql import SparkSession

# Detection: ${title}
# Rule ID:   ${ruleId}

spark = SparkSession.builder \\
    .appName("Detection_${ruleId.replace(/-/g, "_")}") \\
    .getOrCreate()

# Adjust table name and time filter to your environment
result = spark.sql("""
    SELECT ${selectFields},
           '${ruleId}' AS detection_id,
           '${title.replace(/'/g, "\\'")}' AS detection_name,
           'high' AS severity
    FROM ${tableName}
    WHERE ${whereClause}
""")

result.show(50, truncate=False)

# Write findings to output store
result.write \\
    .mode("append") \\
    .partitionBy("detection_id") \\
    .parquet("s3://detections/findings/")`;

    notes.push(`Converted from Sigma rule: "${title}"`);
    notes.push("Adjust table name and column names to match your security lake schema.");
    notes.push("Add a time-range filter (e.g., WHERE dt = '2025-01-01') for partition pruning.");
    warnings.push("Field names follow common security lake conventions — verify against your schema.");

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

function buildSQLWhere(detection: string): string {
  const conditions: string[] = [];

  // endswith conditions
  const endswithRegex = /(\w+)\|endswith:\s*\n?((?:\s+- '[^']+'\n?)+)/g;
  let m: RegExpExecArray | null;

  while ((m = endswithRegex.exec(detection)) !== null) {
    const field = snakeCase(m[1]);
    const values = [...m[2].matchAll(/- '([^']+)'/g)].map((v) => v[1]);
    if (values.length === 1) {
      conditions.push(`${field} LIKE '%${values[0]}'`);
    } else {
      const likes = values.map((v) => `${field} LIKE '%${v}'`).join(" OR ");
      conditions.push(`(${likes})`);
    }
  }

  // contains conditions
  const containsRegex = /(\w+)\|contains:\s*\n?((?:\s+- '[^']+'\n?)+)/g;
  while ((m = containsRegex.exec(detection)) !== null) {
    const field = snakeCase(m[1]);
    const values = [...m[2].matchAll(/- '([^']+)'/g)].map((v) => v[1]);
    if (values.length === 1) {
      conditions.push(`LOWER(${field}) LIKE '%${values[0].toLowerCase()}%'`);
    } else {
      const likes = values
        .map((v) => `LOWER(${field}) LIKE '%${v.toLowerCase()}%'`)
        .join("\n           OR ");
      conditions.push(`(\n           ${likes}\n           )`);
    }
  }

  // isin / equals conditions
  const equalsRegex = /(\w+):\s*\n?((?:\s+- '[^']+'\n?)+)/g;
  while ((m = equalsRegex.exec(detection)) !== null) {
    if (m[1].includes("|")) continue;
    const field = snakeCase(m[1]);
    const values = [...m[2].matchAll(/- '([^']+)'/g)].map((v) => v[1]);
    if (values.length === 1) {
      conditions.push(`${field} = '${values[0]}'`);
    } else {
      const inList = values.map((v) => `'${v}'`).join(", ");
      conditions.push(`${field} IN (${inList})`);
    }
  }

  if (conditions.length === 0) {
    return "1=1  -- TODO: add specific filter conditions";
  }

  return conditions.join("\n      AND ");
}

function snakeCase(str: string): string {
  return str.replace(/([A-Z])/g, "_$1").toLowerCase().replace(/^_/, "");
}
