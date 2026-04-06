import { ConversionResult } from "./sigmaToSplunk";

export function pysparkToSigma(pyspark: string): ConversionResult {
  const notes: string[] = [];
  const warnings: string[] = [];

  try {
    // Extract data path hint
    const pathMatch = pyspark.match(/['"](s3:\/\/[^'"]+|\/data[^'"]+)['"]/);
    const dataPath = pathMatch ? pathMatch[1] : "";

    // Determine product/category from path
    let product = "generic";
    let category = "";

    if (dataPath.includes("windows") || dataPath.includes("endpoint")) {
      product = "windows";
      category = "process_creation";
      notes.push("Detected Windows endpoint data source from path hint.");
    } else if (dataPath.includes("cloudtrail") || dataPath.includes("aws")) {
      product = "aws";
      notes.push("Detected AWS CloudTrail data source from path hint.");
    } else if (dataPath.includes("linux") || dataPath.includes("auditd")) {
      product = "linux";
      notes.push("Detected Linux auditd data source from path hint.");
    }

    // Extract filter conditions
    const filterConditions = extractPySparkFilters(pyspark);

    const logsource = product === "aws"
      ? `logsource:\n  product: aws\n  service: cloudtrail`
      : category
      ? `logsource:\n  category: ${category}\n  product: ${product}`
      : `logsource:\n  product: ${product}`;

    const selectionFields = filterConditions
      .map((c) => `    ${c}`)
      .join("\n");

    const sigma = `title: Converted from PySpark Detection
id: ${generateId()}
status: experimental
description: >
  Automatically converted from PySpark detection logic.
  Review field mappings and logic before production deployment.
author: DetectLab Converter
date: ${new Date().toISOString().split("T")[0].replace(/-/g, "/")}
tags:
  - attack.detection
  # TODO: Add MITRE ATT&CK technique IDs
${logsource}
detection:
  selection:
${selectionFields || "    # TODO: Map PySpark filter conditions to Sigma syntax"}
  condition: selection
falsepositives:
  - Review original PySpark detection context
  - Verify with security team
level: medium`;

    notes.push("Converted PySpark filter logic to Sigma detection format.");
    notes.push("Complex PySpark operations (window functions, UDFs, ML models) cannot be represented in Sigma.");
    notes.push("Review and add MITRE ATT&CK technique tags.");
    warnings.push("PySpark → Sigma conversion loses aggregation and statistical logic.");
    warnings.push("Validate converted rule against real events before deployment.");

    return { output: sigma, notes, warnings, valid: true };
  } catch (e) {
    return {
      output: "# Conversion failed.",
      notes: [],
      warnings: ["Failed to parse PySpark code."],
      valid: false,
    };
  }
}

function extractPySparkFilters(code: string): string[] {
  const conditions: string[] = [];

  // col("field").endswith("value")
  const endswithMatches = code.matchAll(/col\(["'](\w+)["']\)\.endswith\(["']([^"']+)["']\)/g);
  for (const match of endswithMatches) {
    conditions.push(`${camelCase(match[1])}|endswith: '${match[2]}'`);
  }

  // col("field").startswith("value")
  const startswithMatches = code.matchAll(/col\(["'](\w+)["']\)\.startswith\(["']([^"']+)["']\)/g);
  for (const match of startswithMatches) {
    conditions.push(`${camelCase(match[1])}|startswith: '${match[2]}'`);
  }

  // lower(col("field")).contains("value")
  const containsMatches = code.matchAll(/col\(["'](\w+)["']\)\)?\s*\.contains\(["']([^"']+)["']\)/g);
  for (const match of containsMatches) {
    conditions.push(`${camelCase(match[1])}|contains: '${match[2]}'`);
  }

  // col("field") == "value" or col("field").isin([...])
  const eqMatches = code.matchAll(/col\(["'](\w+)["']\)\s*==\s*["']([^"']+)["']/g);
  for (const match of eqMatches) {
    conditions.push(`${camelCase(match[1])}: '${match[2]}'`);
  }

  return Array.from(new Set(conditions));
}

function camelCase(str: string): string {
  return str.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
}

function generateId(): string {
  return "conv-" + Math.random().toString(36).slice(2, 10);
}
