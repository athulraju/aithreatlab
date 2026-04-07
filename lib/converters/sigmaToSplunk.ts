export interface ConversionResult {
  output: string;
  notes: string[];
  warnings: string[];
  valid: boolean;
}

// ─── Logsource → Splunk mapping ──────────────────────────────────────────────

interface SourceMapping {
  indexClause: string;
  tableFields: string[];
  notes: string[];
}

function getSourceMapping(product: string, category: string, service: string): SourceMapping {
  if (product === "windows") {
    switch (category) {
      case "process_creation":
        return {
          indexClause: "index=endpoint sourcetype=WinEventLog:Security EventCode=4688",
          tableFields: ["_time", "host", "User", "Image", "CommandLine", "ParentImage", "ParentCommandLine"],
          notes: [
            "Mapped process_creation to Windows Security Event 4688.",
            "Requires process command-line auditing via Group Policy.",
          ],
        };
      case "process_access":
        return {
          indexClause: "index=endpoint sourcetype=sysmon EventCode=10",
          tableFields: ["_time", "host", "SourceImage", "TargetImage", "GrantedAccess", "CallTrace"],
          notes: ["Mapped process_access to Sysmon Event ID 10."],
        };
      case "network_connection":
        return {
          indexClause: "index=endpoint sourcetype=sysmon EventCode=3",
          tableFields: ["_time", "host", "User", "Image", "DestinationIp", "DestinationPort"],
          notes: ["Mapped network_connection to Sysmon Event ID 3."],
        };
      case "file_event":
        return {
          indexClause: "index=endpoint sourcetype=sysmon EventCode=11",
          tableFields: ["_time", "host", "User", "Image", "TargetFilename"],
          notes: ["Mapped file_event to Sysmon Event ID 11."],
        };
      default:
        return {
          indexClause: "index=endpoint sourcetype=WinEventLog:Security",
          tableFields: ["_time", "host", "User", "EventCode", "Message"],
          notes: [],
        };
    }
  }

  if (product === "linux" || product === "oracle_linux") {
    return {
      indexClause: "index=linux_audit sourcetype=auditd",
      tableFields: ["_time", "host", "user", "exe", "cmdline", "ppid"],
      notes: ["Mapped to Linux auditd process events."],
    };
  }

  if (product === "oci") {
    return {
      indexClause: "index=oci sourcetype=oci:auditlog",
      tableFields: ["_time", "host", "user", "exe", "cmdline", "ppid"],
      notes: ["Mapped to OCI audit log sourcetype."],
    };
  }

  if (product === "aws") {
    if (service === "cloudtrail") {
      return {
        indexClause: "index=aws sourcetype=aws:cloudtrail",
        tableFields: ["_time", "userIdentity.arn", "eventName", "requestParameters", "sourceIPAddress"],
        notes: ["Mapped to AWS CloudTrail sourcetype."],
      };
    }
    return {
      indexClause: "index=aws sourcetype=aws:cloudwatch",
      tableFields: ["_time", "account_id", "region", "event_name", "source_ip"],
      notes: [],
    };
  }

  return {
    indexClause: "index=*",
    tableFields: ["_time", "host", "source", "sourcetype", "_raw"],
    notes: ["Could not determine logsource — using wildcard index. Narrow down for production use."],
  };
}

// ─── Detection block parser ───────────────────────────────────────────────────

type BlockMap = Record<string, string[]>;

function parseDetectionBlocks(sigma: string): { blocks: BlockMap; condition: string } {
  const blocks: BlockMap = {};
  let condition = "selection";

  // Collect lines inside the detection: section
  const lines = sigma.split("\n");
  let inDetection = false;
  const detLines: string[] = [];

  for (const line of lines) {
    if (/^detection:\s*$/.test(line)) {
      inDetection = true;
      continue;
    }
    if (inDetection) {
      // A new top-level YAML key ends the detection section
      if (/^\S/.test(line) && line.trim() !== "") break;
      detLines.push(line);
    }
  }

  if (detLines.length === 0) return { blocks, condition };

  // Extract condition
  for (const line of detLines) {
    const m = line.match(/^  condition:\s*(.+)$/);
    if (m) { condition = m[1].trim(); break; }
  }

  // Group lines into named blocks (keys at exactly 2-space indent)
  let currentName: string | null = null;
  let currentLines: string[] = [];

  const flush = () => {
    if (currentName && currentName !== "condition" && currentName !== "timeframe") {
      blocks[currentName] = parseBlockLines(currentLines);
    }
    currentLines = [];
  };

  for (const line of detLines) {
    const blockKey = line.match(/^  (\w[\w\d_]*):\s*$/);
    if (blockKey) {
      flush();
      currentName = blockKey[1];
    } else if (currentName) {
      currentLines.push(line);
    }
  }
  flush();

  return { blocks, condition };
}

function parseBlockLines(lines: string[]): string[] {
  const conditions: string[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];
    // Field at 4-space indent: "    FieldName|mod1|mod2: value"
    const fieldMatch = line.match(/^    ([\w.]+)((?:\|\w+)*):\s*(.*)?$/);
    if (!fieldMatch) { i++; continue; }

    const field = fieldMatch[1];
    const modStr = (fieldMatch[2] || "").replace(/^\|/, "");
    const modifiers = modStr ? modStr.split("|").filter(Boolean) : [];
    const inline = (fieldMatch[3] || "").trim().replace(/^['"]|['"]$/g, "");

    if (inline && !inline.startsWith("#")) {
      conditions.push(buildSPLCondition(field, modifiers, [inline]));
      i++;
    } else {
      // Collect list values at 6-space indent (      - value)
      const values: string[] = [];
      i++;
      while (i < lines.length && /^      -/.test(lines[i])) {
        const val = lines[i].trim().replace(/^-\s*/, "").replace(/^['"]|['"]$/g, "").trim();
        if (val && !val.startsWith("#")) values.push(val);
        i++;
      }
      if (values.length > 0) {
        conditions.push(buildSPLCondition(field, modifiers, values));
      }
    }
  }

  return conditions;
}

function buildSPLCondition(field: string, modifiers: string[], values: string[]): string {
  if (values.length === 0) return "";

  const primary = modifiers[0] || "exact";
  const allModifier = modifiers.includes("all");

  const esc = (v: string) => v.replace(/"/g, '\\"');

  if (primary === "cidr") {
    const terms = values.map((v) => `cidrmatch("${esc(v)}", ${field})`);
    return terms.length === 1 ? terms[0] : `(${terms.join(" OR ")})`;
  }

  if (primary === "contains") {
    const terms = values.map((v) => `${field}="*${esc(v)}*"`);
    if (allModifier) return `(${terms.join(" AND ")})`;
    return terms.length === 1 ? terms[0] : `(${terms.join(" OR ")})`;
  }

  if (primary === "startswith") {
    const terms = values.map((v) => `${field}="${esc(v)}*"`);
    return terms.length === 1 ? terms[0] : `(${terms.join(" OR ")})`;
  }

  if (primary === "endswith") {
    const terms = values.map((v) => `${field}="*${esc(v)}"`);
    return terms.length === 1 ? terms[0] : `(${terms.join(" OR ")})`;
  }

  if (primary === "re") {
    const terms = values.map((v) => `match(${field}, "${esc(v)}")`);
    return terms.length === 1 ? terms[0] : `(${terms.join(" OR ")})`;
  }

  // Default: exact match
  const terms = values.map((v) => `${field}="${esc(v)}"`);
  return terms.length === 1 ? terms[0] : `(${terms.join(" OR ")})`;
}

// ─── Condition expression → SPL WHERE ────────────────────────────────────────

function buildWhereClause(condition: string, blocks: BlockMap): string {
  let expr = condition;

  // Expand "N of block_*" wildcard patterns
  expr = expr.replace(/(\d+|all) of ([\w]+)\*/gi, (_m, count, prefix) => {
    const matching = Object.keys(blocks).filter((k) => k.startsWith(prefix));
    if (matching.length === 0) return "true";
    if (count.toLowerCase() === "all") {
      return matching.map((b) => `__${b}__`).join(" AND ");
    }
    return matching.length === 1
      ? `__${matching[0]}__`
      : `(${matching.map((b) => `__${b}__`).join(" OR ")})`;
  });

  // Replace block names with SPL conditions
  for (const [name, conds] of Object.entries(blocks)) {
    const splBlock =
      conds.length === 0
        ? "true"
        : conds.length === 1
        ? conds[0]
        : `(\n    ${conds.join("\n    AND ")}\n  )`;

    // Replace __name__ (from wildcard expansion) and bare block names
    expr = expr.replace(new RegExp(`__${name}__|\\b${name}\\b`, "g"), splBlock);
  }

  // Normalize operators to uppercase
  expr = expr
    .replace(/\band\b/gi, "AND")
    .replace(/\bor\b/gi, "OR")
    .replace(/\bnot\b/gi, "NOT");

  return expr;
}

// ─── Main converter ───────────────────────────────────────────────────────────

export function sigmaToSplunk(sigma: string): ConversionResult {
  const notes: string[] = [];
  const warnings: string[] = [];

  try {
    const titleMatch = sigma.match(/^title:\s*(.+)$/m);
    const title = titleMatch ? titleMatch[1].trim() : "Unknown Detection";

    const categoryMatch = sigma.match(/^  category:\s*(.+)$/m);
    const productMatch = sigma.match(/^  product:\s*(.+)$/m);
    const serviceMatch = sigma.match(/^  service:\s*(.+)$/m);

    const category = categoryMatch ? categoryMatch[1].trim() : "";
    const product = productMatch ? productMatch[1].trim() : "";
    const service = serviceMatch ? serviceMatch[1].trim() : "";

    const mapping = getSourceMapping(product, category, service);
    notes.push(...mapping.notes);

    const { blocks, condition } = parseDetectionBlocks(sigma);

    if (Object.keys(blocks).length === 0) {
      warnings.push("No detection blocks found. Ensure the rule has a detection: section.");
    }

    const whereExpr = buildWhereClause(condition, blocks);
    const tableFields = mapping.tableFields.join(", ");

    if (sigma.match(/^falsepositives:/m)) {
      warnings.push("Review false positives documented in the original Sigma rule.");
    }

    notes.push(`Converted from Sigma rule: "${title}"`);
    notes.push("Adjust index and sourcetype to match your environment.");

    const output = [
      `| comment("Detection: ${title}")`,
      mapping.indexClause,
      `  ${whereExpr}`,
      `| table ${tableFields}`,
      `| sort -_time`,
    ].join("\n");

    return { output, notes, warnings, valid: true };
  } catch {
    return {
      output: "-- Conversion failed. Check Sigma rule syntax.",
      notes: [],
      warnings: ["Failed to parse Sigma rule. Ensure YAML structure is valid."],
      valid: false,
    };
  }
}
