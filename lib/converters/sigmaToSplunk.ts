export interface ConversionResult {
  output: string;
  notes: string[];
  warnings: string[];
  valid: boolean;
}

export function sigmaToSplunk(sigma: string): ConversionResult {
  const notes: string[] = [];
  const warnings: string[] = [];

  try {
    // Parse basic Sigma structure
    const lines = sigma.split("\n");
    const titleMatch = sigma.match(/^title:\s*(.+)$/m);
    const title = titleMatch ? titleMatch[1].trim() : "Unknown Detection";

    // Extract logsource
    const categoryMatch = sigma.match(/^\s+category:\s*(.+)$/m);
    const productMatch = sigma.match(/^\s+product:\s*(.+)$/m);
    const serviceMatch = sigma.match(/^\s+service:\s*(.+)$/m);

    const category = categoryMatch ? categoryMatch[1].trim() : "";
    const product = productMatch ? productMatch[1].trim() : "";
    const service = serviceMatch ? serviceMatch[1].trim() : "";

    // Map logsource to Splunk index/sourcetype
    let indexClause = "index=*";
    if (product === "windows") {
      if (category === "process_creation") {
        indexClause = "index=endpoint sourcetype=WinEventLog:Security EventCode=4688";
        notes.push("Mapped process_creation to Windows Security Event 4688.");
        notes.push("Requires process command-line auditing via Group Policy.");
      } else if (category === "process_access") {
        indexClause = "index=endpoint sourcetype=sysmon EventCode=10";
        notes.push("Mapped process_access to Sysmon Event ID 10.");
      } else {
        indexClause = "index=endpoint sourcetype=WinEventLog:Security";
      }
    } else if (product === "aws" && service === "cloudtrail") {
      indexClause = "index=aws sourcetype=aws:cloudtrail";
      notes.push("Mapped to AWS CloudTrail sourcetype.");
    } else if (product === "linux") {
      indexClause = "index=endpoint sourcetype=syslog";
      notes.push("Mapped to Linux syslog sourcetype.");
    }

    // Extract detection fields
    const detectionSection = extractSection(sigma, "detection");
    const conditions = parseDetectionConditions(detectionSection);

    // Build WHERE clauses
    const whereClauses = buildWhereClauses(conditions);
    const whereString = whereClauses.length > 0 ? "\n" + whereClauses.join("\n") : "";

    // Extract falsePositives for note
    const fpMatch = sigma.match(/^falsepositives:\n((?:\s*-.*\n?)*)/m);
    if (fpMatch) {
      warnings.push("Review false positives documented in original Sigma rule.");
    }

    // Build output query
    const output = `| comment("Detection: ${title}")
${indexClause}${whereString}
| table _time, host, user, CommandLine, ParentImage, Image
| sort -_time`;

    notes.push(`Converted from Sigma rule: "${title}"`);
    notes.push("Field names mapped to Splunk CIM conventions.");
    notes.push("Adjust index and sourcetype to match your environment.");

    return { output, notes, warnings, valid: true };
  } catch (e) {
    return {
      output: "-- Conversion failed. Check Sigma rule syntax.",
      notes: [],
      warnings: ["Failed to parse Sigma rule. Ensure YAML structure is valid."],
      valid: false,
    };
  }
}

function extractSection(yaml: string, section: string): string {
  const regex = new RegExp(`^${section}:([\\s\\S]*?)^\\w`, "m");
  const match = yaml.match(regex);
  return match ? match[1] : "";
}

function parseDetectionConditions(detectionSection: string): Record<string, string[]> {
  const conditions: Record<string, string[]> = {};
  const selectionMatch = detectionSection.match(/selection:([\s\S]*?)(?=\n\s*\w+:|$)/);

  if (selectionMatch) {
    const selectionLines = selectionMatch[1].split("\n").filter((l) => l.trim());
    const current: string[] = [];
    for (const line of selectionLines) {
      const trimmed = line.trim();
      if (trimmed.startsWith("-")) {
        current.push(trimmed.slice(1).trim());
      } else if (trimmed.includes(":")) {
        const [key, value] = trimmed.split(":").map((s) => s.trim());
        if (value) current.push(`${key}="${value}"`);
      }
    }
    conditions["selection"] = current;
  }

  return conditions;
}

function buildWhereClauses(conditions: Record<string, string[]>): string[] {
  const clauses: string[] = [];
  for (const [, values] of Object.entries(conditions)) {
    for (const v of values) {
      if (v.includes("endswith")) {
        const clean = v.replace("|endswith", "");
        clauses.push(`  ${clean}=*${v.split('"')[1]}`);
      } else if (v.includes("contains")) {
        clauses.push(`  ${v}`);
      } else if (v) {
        clauses.push(`  ${v}`);
      }
    }
  }
  return clauses;
}
