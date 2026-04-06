import { ConversionResult } from "./sigmaToSplunk";

export function splunkToSigma(splunk: string): ConversionResult {
  const notes: string[] = [];
  const warnings: string[] = [];

  try {
    const lines = splunk.split("\n").map((l) => l.trim()).filter(Boolean);

    // Detect index and sourcetype
    const indexMatch = splunk.match(/index=(\S+)/);
    const sourcetypeMatch = splunk.match(/sourcetype=(\S+)/);
    const eventCodeMatch = splunk.match(/EventCode=(\d+)/i);

    const index = indexMatch ? indexMatch[1] : "endpoint";
    const sourcetype = sourcetypeMatch ? sourcetypeMatch[1] : "";
    const eventCode = eventCodeMatch ? eventCodeMatch[1] : "";

    // Map to Sigma logsource
    let logsource = "";
    let product = "windows";

    if (sourcetype.includes("WinEventLog") || sourcetype.includes("sysmon")) {
      if (eventCode === "4688" || sourcetype.includes("Security")) {
        logsource = `logsource:\n  category: process_creation\n  product: windows`;
        notes.push("Detected Windows process creation events from Event ID 4688.");
      } else if (eventCode === "10") {
        logsource = `logsource:\n  category: process_access\n  product: windows`;
        notes.push("Detected Sysmon process access events (Event ID 10).");
      } else {
        logsource = `logsource:\n  product: windows\n  service: security`;
      }
    } else if (sourcetype.includes("cloudtrail") || index.includes("aws")) {
      logsource = `logsource:\n  product: aws\n  service: cloudtrail`;
      product = "aws";
      notes.push("Detected AWS CloudTrail log source.");
    } else {
      logsource = `logsource:\n  category: application\n  product: generic`;
      warnings.push("Could not definitively determine log source — review logsource section.");
    }

    // Extract field conditions from WHERE-like clauses
    const conditions = extractSplunkConditions(splunk);

    // Generate Sigma detection block
    const selectionFields = conditions
      .map((c) => `    ${c}`)
      .join("\n");

    const sigma = `title: Converted from Splunk Query
id: ${generateId()}
status: experimental
description: >
  Automatically converted from Splunk SPL query.
  Review and validate before production deployment.
author: DetectLab Converter
date: ${new Date().toISOString().split("T")[0].replace(/-/g, "/")}
tags:
  - attack.detection
  # TODO: Add specific MITRE ATT&CK tags
${logsource}
detection:
  selection:
${selectionFields || "    # TODO: Map SPL conditions to Sigma field syntax"}
  condition: selection
falsepositives:
  - Review original Splunk query context
  - Document known-good use cases
level: medium
# Original Splunk query preserved below for reference:
# ${splunk.split("\n")[0].substring(0, 100)}`;

    notes.push("Converted from Splunk SPL to Sigma format.");
    notes.push("Review field mappings — Splunk fields may differ from Sigma field names.");
    notes.push("Add appropriate MITRE ATT&CK tags before production use.");
    warnings.push("Splunk macros, lookups, and complex functions cannot be automatically converted.");
    warnings.push("Validate converted rule against sample events before deployment.");

    return { output: sigma, notes, warnings, valid: true };
  } catch (e) {
    return {
      output: "# Conversion failed.",
      notes: [],
      warnings: ["Failed to parse SPL query."],
      valid: false,
    };
  }
}

function extractSplunkConditions(splunk: string): string[] {
  const conditions: string[] = [];
  const fieldPatterns = [
    /(\w+)="([^"]+)"/g,
    /(\w+)=\*([^*\s]+)\*/g,
    /(\w+) IN \(([^)]+)\)/gi,
  ];

  for (const pattern of fieldPatterns) {
    const matches = splunk.matchAll(pattern);
    for (const match of matches) {
      const field = match[1];
      const value = match[2];

      // Skip metadata fields
      if (["index", "sourcetype", "EventCode", "source"].includes(field)) continue;

      if (value.startsWith("*") && value.endsWith("*")) {
        conditions.push(`${field}|contains: '${value.slice(1, -1)}'`);
      } else if (value.endsWith("*")) {
        conditions.push(`${field}|startswith: '${value.slice(0, -1)}'`);
      } else if (value.startsWith("*")) {
        conditions.push(`${field}|endswith: '${value.slice(1)}'`);
      } else {
        conditions.push(`${field}: '${value}'`);
      }
    }
  }

  return [...new Set(conditions)];
}

function generateId(): string {
  return "conv-" + Math.random().toString(36).slice(2, 10);
}
