import { ConversionResult } from "./sigmaToSplunk";

/**
 * Converts PySpark / Spark SQL detection logic to Splunk SPL.
 * Handles spark.sql(""" ... """) blocks and common DataFrame patterns.
 */
export function pysparkToSplunk(pyspark: string): ConversionResult {
  const notes: string[] = [];
  const warnings: string[] = [];

  try {
    // ── Extract SQL from spark.sql(""" ... """) block if present ─────────────
    const sqlBlockMatch = pyspark.match(/spark\.sql\s*\(\s*(?:"""|\"\"\"|'''|f"""|f''')([\s\S]+?)(?:"""|\"\"\"|''')\s*\)/i);
    const rawSql = sqlBlockMatch ? sqlBlockMatch[1].trim() : pyspark;

    // ── Parse SELECT clause ───────────────────────────────────────────────────
    const selectMatch = rawSql.match(/SELECT\s+([\s\S]+?)\s+FROM/i);
    const fromMatch   = rawSql.match(/FROM\s+(\w+)/i);
    const whereMatch  = rawSql.match(/WHERE\s+([\s\S]+?)(?:GROUP BY|ORDER BY|HAVING|LIMIT|$)/i);
    const groupMatch  = rawSql.match(/GROUP BY\s+([\s\S]+?)(?:HAVING|ORDER BY|LIMIT|$)/i);
    const havingMatch = rawSql.match(/HAVING\s+([\s\S]+?)(?:ORDER BY|LIMIT|$)/i);
    const orderMatch  = rawSql.match(/ORDER BY\s+([\s\S]+?)(?:LIMIT|$)/i);
    const limitMatch  = rawSql.match(/LIMIT\s+(\d+)/i);

    const tableName = fromMatch ? fromMatch[1].trim() : "security_events";

    // ── Map table name to Splunk index / sourcetype ───────────────────────────
    let indexClause = `index=security`;
    if (tableName.includes("windows_process") || tableName.includes("process_creation")) {
      indexClause = "index=endpoint sourcetype=WinEventLog:Security EventCode=4688";
      notes.push("Mapped windows_process_creation table → Splunk Windows Security Event 4688.");
    } else if (tableName.includes("windows")) {
      indexClause = "index=endpoint sourcetype=WinEventLog:Security";
      notes.push("Mapped windows_events table → Splunk WinEventLog:Security.");
    } else if (tableName.includes("cloudtrail") || tableName.includes("aws")) {
      indexClause = "index=aws sourcetype=aws:cloudtrail";
      notes.push("Mapped cloudtrail_events table → Splunk AWS CloudTrail.");
    } else if (tableName.includes("linux") || tableName.includes("audit")) {
      indexClause = "index=linux sourcetype=linux_audit";
      notes.push("Mapped linux_audit_events table → Splunk linux_audit.");
    } else if (tableName.includes("network") || tableName.includes("firewall")) {
      indexClause = "index=network sourcetype=firewall";
      notes.push("Mapped network_events table → Splunk firewall.");
    } else {
      indexClause = `index=${tableName.replace(/_/g, "-")}`;
      notes.push(`Using table name '${tableName}' as Splunk index.`);
    }

    // ── Convert WHERE clause to SPL search terms ──────────────────────────────
    const splSearchTerms: string[] = [];
    if (whereMatch) {
      let where = whereMatch[1].trim();

      // Remove SQL comments
      where = where.replace(/--[^\n]*/g, "").trim();

      // Split on AND (top-level only, simplified)
      const conditions = where.split(/\bAND\b/i).map((c) => c.trim()).filter(Boolean);
      for (const cond of conditions) {
        // field = 'value'  → field="value"
        const eqMatch = cond.match(/^(\w+)\s*=\s*'([^']+)'$/);
        if (eqMatch) { splSearchTerms.push(`${eqMatch[1]}="${eqMatch[2]}"`); continue; }

        // field != 'value' → NOT field="value"
        const neqMatch = cond.match(/^(\w+)\s*!=\s*'([^']+)'$/);
        if (neqMatch) { splSearchTerms.push(`NOT ${neqMatch[1]}="${neqMatch[2]}"`); continue; }

        // field LIKE '%value%' → field=*value*
        const likeMatch = cond.match(/^(\w+)\s+LIKE\s+'([^']+)'$/i);
        if (likeMatch) {
          const pattern = likeMatch[2].replace(/%/g, "*");
          splSearchTerms.push(`${likeMatch[1]}=${pattern}`);
          continue;
        }

        // field NOT LIKE '%value%' → NOT field=*value*
        const notLikeMatch = cond.match(/^(\w+)\s+NOT LIKE\s+'([^']+)'$/i);
        if (notLikeMatch) {
          const pattern = notLikeMatch[2].replace(/%/g, "*");
          splSearchTerms.push(`NOT ${notLikeMatch[1]}=${pattern}`);
          continue;
        }

        // field > N / field >= N
        const gtMatch = cond.match(/^(\w+)\s*(>=?)\s*(\d+)$/);
        if (gtMatch) { splSearchTerms.push(`${gtMatch[1]}>=${gtMatch[3]}`); continue; }

        // field IS NOT NULL → field=*
        if (cond.match(/(\w+)\s+IS\s+NOT\s+NULL/i)) {
          splSearchTerms.push(`${cond.match(/(\w+)/)?.[1]}=*`);
          continue;
        }

        // field IS NULL → NOT field=*
        if (cond.match(/(\w+)\s+IS\s+NULL/i)) {
          splSearchTerms.push(`NOT ${cond.match(/(\w+)/)?.[1]}=*`);
          continue;
        }

        // Fallback — append as-is with a warning
        splSearchTerms.push(`(* ${cond} *)`);
        warnings.push(`Could not convert condition '${cond.slice(0, 60)}', review manually.`);
      }
    }

    // ── Convert SELECT to SPL table/stats ────────────────────────────────────
    let statsCmd    = "";
    let tableCmd    = "";
    const sortCmd   = orderMatch ? buildSplSort(orderMatch[1]) : "";
    const headCmd   = limitMatch ? `| head ${limitMatch[1]}` : "";

    if (selectMatch) {
      const selectStr = selectMatch[1].trim();

      // Detect aggregations: COUNT(*), SUM(x) AS y, etc.
      const hasAgg = /\b(COUNT|SUM|AVG|MIN|MAX)\s*\(/i.test(selectStr);

      if (hasAgg && groupMatch) {
        const groupFields = groupMatch[1].trim().split(",").map((f) => f.trim());
        const aggParts    = parseAggregations(selectStr, notes);
        statsCmd = `| stats ${aggParts} by ${groupFields.join(", ")}`;
        notes.push("Converted GROUP BY + aggregation to SPL stats command.");
      } else if (hasAgg) {
        const aggParts = parseAggregations(selectStr, notes);
        statsCmd = `| stats ${aggParts}`;
        notes.push("Converted aggregation (no GROUP BY) to SPL stats command.");
      } else if (selectStr !== "*") {
        const fields = selectStr.split(",").map((f) => f.trim().split(/\s+AS\s+/i)[0].trim());
        tableCmd = `| table ${fields.join(", ")}`;
        notes.push("Converted SELECT field list to SPL table command.");
      }
    }

    // ── HAVING clause → SPL where ─────────────────────────────────────────────
    let havingCmd = "";
    if (havingMatch) {
      const having = havingMatch[1].trim()
        .replace(/SUM\((\w+)\)/gi, "sum($1)")
        .replace(/COUNT\(\*\)/gi, "count");
      havingCmd = `| where ${having}`;
      notes.push("Converted HAVING clause to SPL where command.");
      warnings.push("HAVING conditions reference aggregated fields; verify field names match SPL stats output.");
    }

    // ── Assemble SPL query ────────────────────────────────────────────────────
    const spl = [
      indexClause,
      splSearchTerms.join(" "),
      statsCmd,
      havingCmd,
      tableCmd || (statsCmd ? "" : ""),
      sortCmd,
      headCmd,
    ].filter(Boolean).join("\n| ").replace(/^\| /, "");

    const output = `| ${spl}

\`\`\`
Conversion Notes:
${notes.map((n) => "  • " + n).join("\n")}
${warnings.length > 0 ? "\nWarnings:\n" + warnings.map((w) => "  ⚠ " + w).join("\n") : ""}
\`\`\``;

    if (notes.length === 0) notes.push("Basic conversion completed. Review field names against your Splunk schema.");
    warnings.push("Splunk field names may differ from Spark column names; verify against your actual index schema.");

    return { output, notes, warnings, valid: true };
  } catch (e) {
    return {
      output: "* Conversion failed. Please check the input PySpark/Spark SQL code.",
      notes: [],
      warnings: ["Unexpected error during conversion."],
      valid: false,
    };
  }
}

function buildSplSort(orderStr: string): string {
  const fields = orderStr.trim().split(",").map((f) => {
    f = f.trim();
    if (/\bDESC\b/i.test(f)) return `-${f.replace(/\s+DESC\b/i, "").trim()}`;
    return f.replace(/\s+ASC\b/i, "").trim();
  });
  return `| sort ${fields.join(", ")}`;
}

function parseAggregations(selectStr: string, notes: string[]): string {
  const parts = selectStr.split(",").map((s) => s.trim());
  return parts.map((part) => {
    // COUNT(*) AS alias  or COUNT(*)
    const countStar = part.match(/COUNT\s*\(\s*\*\s*\)(?:\s+AS\s+(\w+))?/i);
    if (countStar) return countStar[1] ? `count AS ${countStar[1]}` : "count";

    // AGG(field) AS alias
    const aggAlias = part.match(/(\w+)\s*\(\s*(\w+)\s*\)\s+AS\s+(\w+)/i);
    if (aggAlias) {
      const fn = aggAlias[1].toLowerCase();
      return `${fn}(${aggAlias[2]}) AS ${aggAlias[3]}`;
    }

    // AGG(field)
    const aggPlain = part.match(/(\w+)\s*\(\s*(\w+)\s*\)/i);
    if (aggPlain) return `${aggPlain[1].toLowerCase()}(${aggPlain[2]})`;

    // Plain field (pass-through)
    return part.split(/\s+AS\s+/i)[0].trim();
  }).join(", ");
}
