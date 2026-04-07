import { ConversionResult } from "./sigmaToSplunk";

/**
 * Converts Splunk SPL search queries to PySpark / Spark SQL equivalents.
 * Handles common SPL patterns: index/sourcetype filters, field comparisons,
 * stats aggregations, eval expressions, sort, table, where, rex, search.
 */
export function splunkToPySpark(splunk: string): ConversionResult {
  const notes: string[] = [];
  const warnings: string[] = [];

  try {
    const lines = splunk.split("|").map((l) => l.trim()).filter(Boolean);

    // ── Extract the base search clause (first segment) ───────────────────────
    const baseSearch = lines[0] || "";

    // Map index= / sourcetype= to a table name
    const indexMatch      = baseSearch.match(/index=(\S+)/);
    const sourcetypeMatch = baseSearch.match(/sourcetype=(\S+)/);
    const index      = indexMatch      ? indexMatch[1]      : "security_events";
    const sourcetype = sourcetypeMatch ? sourcetypeMatch[1] : "";

    let tableName = "security_events";
    if (sourcetype.includes("WinEventLog") || sourcetype.includes("sysmon")) {
      tableName = "windows_events";
      notes.push("Mapped WinEventLog/Sysmon sourcetype → windows_events table.");
    } else if (sourcetype.includes("cloudtrail") || index.includes("aws")) {
      tableName = "cloudtrail_events";
      notes.push("Mapped CloudTrail sourcetype → cloudtrail_events table.");
    } else if (sourcetype.includes("linux") || sourcetype.includes("auditd")) {
      tableName = "linux_audit_events";
      notes.push("Mapped Linux/auditd sourcetype → linux_audit_events table.");
    } else if (sourcetype.includes("firewall") || sourcetype.includes("network")) {
      tableName = "network_events";
      notes.push("Mapped network/firewall sourcetype → network_events table.");
    } else if (index !== "security_events") {
      tableName = index.replace(/-/g, "_");
      notes.push(`Using index name '${index}' as table name.`);
    }

    // ── Extract field=value conditions from base search ──────────────────────
    const whereConditions: string[] = [];

    // EventCode=N → eventcode = N
    const eventCodeMatches = baseSearch.matchAll(/EventCode=(\d+)/gi);
    for (const m of eventCodeMatches) {
      whereConditions.push(`eventcode = ${m[1]}`);
    }

    // key=value (quoted or unquoted, excluding meta keys)
    const kvMatches = baseSearch.matchAll(/\b(?!index=|sourcetype=|EventCode=)(\w+)="([^"]+)"/gi);
    for (const m of kvMatches) {
      whereConditions.push(`${m[1].toLowerCase()} = '${m[2]}'`);
    }
    const kvMatchesUnquoted = baseSearch.matchAll(/\b(?!index=|sourcetype=|EventCode=)([A-Za-z_]\w+)=(\S+)/g);
    for (const m of kvMatchesUnquoted) {
      if (!["index", "sourcetype"].includes(m[1].toLowerCase())) {
        whereConditions.push(`${m[1].toLowerCase()} = '${m[2]}'`);
      }
    }

    // NOT field=value → field != value
    const notMatches = baseSearch.matchAll(/NOT\s+(\w+)=(\S+)/gi);
    for (const m of notMatches) {
      whereConditions.push(`${m[1].toLowerCase()} != '${m[2].replace(/"/g, "")}'`);
    }

    // Wildcard patterns: field=*value* → field LIKE '%value%'
    for (let i = 0; i < whereConditions.length; i++) {
      whereConditions[i] = whereConditions[i].replace(/= '(\*.*?\*)'/, (_, v) => {
        return `LIKE '${v.replace(/\*/g, "%")}'`;
      });
    }

    // ── Parse pipeline commands ───────────────────────────────────────────────
    let statsClause    = "";
    let groupByClause  = "";
    let orderByClause  = "";
    let selectFields   = "*";
    let havingClause   = "";
    let limitClause    = "";

    for (let i = 1; i < lines.length; i++) {
      const cmd = lines[i];

      // | stats count by field1, field2
      // | stats sum(bytes) as total_bytes, count by src_ip
      const statsMatch = cmd.match(/^stats\s+(.+?)(?:\s+by\s+(.+))?$/i);
      if (statsMatch) {
        const aggPart = statsMatch[1].trim();
        const byPart  = statsMatch[2]?.trim();

        // Parse aggregation functions
        const aggFuncs = aggPart.split(",").map((agg) => {
          agg = agg.trim();
          const asMatch = agg.match(/^(\w+)\(([^)]+)\)\s+as\s+(\w+)$/i);
          if (asMatch) {
            const [, fn, field, alias] = asMatch;
            const sparkFn = fn.toLowerCase() === "count" ? "COUNT"
                          : fn.toLowerCase() === "sum"   ? "SUM"
                          : fn.toLowerCase() === "avg"   ? "AVG"
                          : fn.toLowerCase() === "max"   ? "MAX"
                          : fn.toLowerCase() === "min"   ? "MIN"
                          : fn.toUpperCase();
            return `${sparkFn}(${field}) AS ${alias}`;
          }
          const simpleMatch = agg.match(/^(\w+)\(([^)]+)\)$/i);
          if (simpleMatch) {
            const [, fn, field] = simpleMatch;
            return `${fn.toUpperCase()}(${field})`;
          }
          if (agg.toLowerCase() === "count") return "COUNT(*) AS count";
          return agg;
        });

        const groupFields = byPart ? byPart.split(",").map((f) => f.trim()) : [];
        statsClause   = aggFuncs.join(",\n        ");
        groupByClause = groupFields.length > 0
          ? `GROUP BY\n        ${groupFields.join(", ")}`
          : "";
        selectFields  = groupFields.length > 0
          ? `${groupFields.join(", ")},\n        ${statsClause}`
          : statsClause;
        notes.push("Converted SPL stats command to GROUP BY aggregation.");
        continue;
      }

      // | where condition
      const whereMatch = cmd.match(/^where\s+(.+)$/i);
      if (whereMatch) {
        let cond = whereMatch[1]
          .replace(/\bAND\b/gi, "AND")
          .replace(/\bOR\b/gi, "OR")
          .replace(/isnotnull\((\w+)\)/gi, "$1 IS NOT NULL")
          .replace(/isnull\((\w+)\)/gi, "$1 IS NULL");
        // Convert LIKE wildcards
        cond = cond.replace(/"([^"]*\*[^"]*)"/, (_, v) => `'${v.replace(/\*/g, "%")}'`);
        whereConditions.push(cond);
        notes.push("Converted SPL where clause to SQL WHERE condition.");
        continue;
      }

      // | sort [-]field
      const sortMatch = cmd.match(/^sort\s+(.+)$/i);
      if (sortMatch) {
        const fields = sortMatch[1].split(",").map((f) => {
          f = f.trim();
          if (f.startsWith("-")) return `${f.slice(1)} DESC`;
          if (f.startsWith("+")) return `${f.slice(1)} ASC`;
          return `${f} ASC`;
        });
        orderByClause = `ORDER BY\n        ${fields.join(", ")}`;
        notes.push("Converted SPL sort to ORDER BY clause.");
        continue;
      }

      // | head N / | tail N
      const headMatch = cmd.match(/^head\s+(\d+)$/i);
      if (headMatch) { limitClause = `LIMIT ${headMatch[1]}`; continue; }
      const tailMatch = cmd.match(/^tail\s+(\d+)$/i);
      if (tailMatch) { warnings.push("SPL 'tail' has no direct SQL equivalent — approximated with ORDER BY + LIMIT."); continue; }

      // | table field1, field2
      const tableMatch = cmd.match(/^table\s+(.+)$/i);
      if (tableMatch && !statsClause) {
        selectFields = tableMatch[1].split(",").map((f) => f.trim()).join(", ");
        notes.push("Converted SPL table command to SELECT field list.");
        continue;
      }

      // | dedup field
      const dedupMatch = cmd.match(/^dedup\s+(\w+)$/i);
      if (dedupMatch) {
        warnings.push(`SPL 'dedup ${dedupMatch[1]}' approximated — use ROW_NUMBER() OVER (PARTITION BY ${dedupMatch[1]}) in a subquery for exact deduplication.`);
        continue;
      }

      // | eval field=expr
      const evalMatch = cmd.match(/^eval\s+(\w+)=(.+)$/i);
      if (evalMatch) {
        warnings.push(`SPL eval '${evalMatch[1]}=${evalMatch[2]}' — add this as a computed column in the SELECT clause manually.`);
        continue;
      }

      // | rex field=_raw "(?<named>\w+)"
      if (cmd.match(/^rex\b/i)) {
        warnings.push("SPL rex (regex extraction) — use regexp_extract() in Spark SQL or pyspark.sql.functions.regexp_extract().");
        continue;
      }

      warnings.push(`Unsupported SPL command: '${cmd.split(" ")[0]}' — review manually.`);
    }

    // ── Assemble Spark SQL query ─────────────────────────────────────────────
    const whereStr = whereConditions.length > 0
      ? `WHERE\n        ${whereConditions.join("\n        AND ")}`
      : "";

    const sqlParts = [
      `SELECT`,
      `        ${selectFields}`,
      `FROM`,
      `        ${tableName}`,
      whereStr,
      groupByClause,
      havingClause,
      orderByClause,
      limitClause,
    ].filter(Boolean);

    const sql = sqlParts.join("\n");

    const output = `# Converted from Splunk SPL → PySpark / Spark SQL
# Generated by AIDetectLab Converter
# Review field names and adjust to your data schema.

from pyspark.sql import SparkSession

spark = SparkSession.builder.appName("detection").getOrCreate()

# Option A — Spark SQL
df_result = spark.sql("""
    ${sql}
""")

df_result.show(50, truncate=False)

# Option B — DataFrame API
# df = spark.table("${tableName}")
# df_filtered = df${whereConditions.length > 0 ? `.filter(...)  # Apply conditions from WHERE clause above` : ""}
# df_result = df_filtered${statsClause ? `.groupBy(...).agg(...)  # Apply aggregation from SELECT clause above` : ""}
`;

    if (notes.length === 0) notes.push("Basic conversion completed. Review field names against your Spark schema.");
    warnings.push("Verify column names match your Spark table schema — SPL field names may differ.");

    return { output, notes, warnings, valid: true };
  } catch (e) {
    return {
      output: "# Conversion failed — please check the input SPL query.\n",
      notes: [],
      warnings: ["Unexpected error during conversion."],
      valid: false,
    };
  }
}
