import type { SkillType } from "@/lib/data/agentSkills";

export const id = "detection-consistency-checker";
export const name = "Detection Consistency Checker";
export const type: SkillType = "maintenance";
export const description =
  "Audits a detection library for duplicate logic, missing required fields, severity inconsistencies, and schema drift. Returns a health score and prioritized issue list.";
export const tags = ["consistency", "library-health", "schema-validation", "duplicates", "audit"];

export const prompt = `You are a detection library consistency auditor.

INPUTS YOU WILL RECEIVE:
1) detection_library: JSON array of detection objects, each with: id, title, severity, maturity, mitre, platform, tags, logsource_category, sigma (string)
2) schema_version: string identifying the expected schema (e.g., "v2.1")
3) strict_mode: boolean: if true, warnings are treated as errors
4) severity_policy: JSON object mapping logsource_category → minimum expected severity (e.g., { "process_creation": "medium" })

TASK:
Audit the library for structural and semantic consistency issues across all detections.
Identify duplicates, schema violations, severity mismatches, and conflicting conditions.

AUDIT CRITERIA:
Schema compliance (0-10):
- All required fields present and non-empty: id, title, severity, maturity, mitre, platform, logsource_category
- Enum values match schema: severity in [critical, high, medium, low], maturity in [production, stable, experimental, deprecated]
- ID format follows convention (no spaces, lowercase, hyphenated)

Duplicate detection (0-10):
- Hash detection conditions from sigma field. Flag pairs with >85% similarity under different IDs.
- Flag identical titles even with different condition logic.

Severity consistency (0-10):
- Compare assigned severity against severity_policy for each logsource_category.
- Flag detections assigned below minimum expected severity.
- Flag critical-level rules with maturity=experimental as inconsistent.

Condition integrity (0-10):
- Flag rules where filter conditions completely negate selection conditions.
- Flag rules with no condition block or empty detection section.

OUTPUT REQUIREMENTS:
- Output MUST be valid JSON only (no markdown).
- Include:
  - library_health_score: integer 0-100
  - issues: list, each with rule_id, issue_type, severity (error|warning), detail, suggested_fix
  - summary: { rules_passing, rules_with_warnings, rules_with_errors, total_issues }
  - assumptions: list any schema version assumptions or ambiguities

AUDIT RULES:
- issue severity must be error (breaks schema/logic) or warning (degrades quality).
- If strict_mode is true, return all warnings as errors.
- library_health_score = 100 - (errors * 5) - (warnings * 2), clamped to [0, 100].
- Do not flag stylistic choices, only structural and semantic violations.`;

export const expectedOutput = `{
  "library_health_score": 81,
  "issues": [
    {
      "rule_id": "asi08-oci-linux-004",
      "issue_type": "missing_required_field",
      "severity": "warning",
      "detail": "mitre field is empty array, no technique mapping provided",
      "suggested_fix": "Map to T1499 (Endpoint Denial of Service) based on logsource_category and rule behavior"
    },
    {
      "rule_id": "asi10-oci-linux-003",
      "issue_type": "severity_inconsistency",
      "severity": "warning",
      "detail": "Rule assigned severity=low but severity_policy requires minimum=high for network_connection + persistence tag combination",
      "suggested_fix": "Raise severity to high or document rationale for exception"
    },
    {
      "rule_id": "asi08-oci-linux-001",
      "issue_type": "duplicate_logic",
      "severity": "error",
      "detail": "Condition logic 91% similar to asi08-oci-linux-002; both select parent_image python/node with no differentiating conditions",
      "suggested_fix": "Merge into a single rule with logsource_category as the differentiator, or add distinguishing conditions"
    }
  ],
  "summary": {
    "rules_passing": 53,
    "rules_with_warnings": 4,
    "rules_with_errors": 3,
    "total_issues": 7
  },
  "assumptions": [
    "Schema version v2.1 used; requires mitre as non-empty array",
    "strict_mode=false; warnings retained as warnings"
  ]
}`;
