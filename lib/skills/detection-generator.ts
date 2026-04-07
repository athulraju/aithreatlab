import type { SkillType } from "@/lib/data/agentSkills";

export const id = "detection-generator";
export const name = "Detection Generator";
export const type: SkillType = "detection";
export const description =
  "Takes a threat description and optional sample log, then generates production-ready Sigma, Splunk SPL, and PySpark detection rules with field mappings, false positive guidance, and severity classification.";
export const tags = ["auto-generation", "sigma", "splunk", "pyspark", "multi-format"];

export const prompt = `You are a multi-format security detection rule generator.

INPUTS YOU WILL RECEIVE:
1) threat_description: plain-text description of the threat behavior to detect
2) sample_log: optional JSON object — a single representative log event (may be null)
3) target_platform: one or more of [windows, linux, aws, oci, network]
4) mitre_technique_id: optional string (e.g., "T1059.004") — may be null
5) desired_formats: array containing one or more of [sigma, splunk, pyspark]

TASK:
Generate production-ready detection rules in each requested format based on the threat description.
If a sample log is provided, use its field names and values to ground the detection conditions.

GENERATION CRITERIA:
Coverage quality (0-10):
- Does the rule detect the core behavior described without being overly broad?
- Are multiple detection angles included where appropriate?

Field specificity (0-10):
- Are conditions specific to named fields rather than free-text searches?
- Are filter conditions included for known false positive sources?

Format correctness (0-10):
- Sigma: valid YAML, correct logsource, detection block structure
- Splunk: valid SPL with correct field references and pipe structure
- PySpark: valid Python, uses built-in Spark functions, filters applied early

OUTPUT REQUIREMENTS:
- Output MUST be valid JSON only (no markdown).
- Include:
  - rules: object with keys matching desired_formats, each containing the rule as a string
  - metadata: { severity, mitre, required_fields, logsource_category }
  - false_positives: list of 2-4 realistic FP scenarios
  - tuning_guidance: string — how to reduce FP rate in production
  - quality_scores: { coverage_quality, field_specificity, format_correctness } each 0-10
  - assumptions: list any missing information that influenced rule generation

GENERATION RULES:
- Never use wildcard-only conditions (e.g., CommandLine: '*') — require at least one specific term.
- Always include at least one filter condition for known-good sources.
- If mitre_technique_id is provided, include it in Sigma tags.
- If sample_log is null, derive field names from common schema for the target_platform.
- severity must be one of: critical | high | medium | low.`;

export const expectedOutput = `{
  "rules": {
    "sigma": "title: Python Agent Spawning Interactive Shell\\nid: gen-auto-20250110-001\\nstatus: experimental\\ndescription: Detects Python or Node agent runtimes spawning interactive shell interpreters\\nlogsource:\\n  product: linux\\n  category: process_creation\\ndetection:\\n  selection_parent:\\n    ParentImage|endswith:\\n      - '/python'\\n      - '/python3'\\n      - '/node'\\n  selection_child:\\n    Image|endswith:\\n      - '/bash'\\n      - '/sh'\\n      - '/zsh'\\n  filter_ci:\\n    User:\\n      - 'svc_build'\\n      - 'runner'\\n  condition: selection_parent and selection_child and not filter_ci\\nlevel: high\\ntags:\\n  - attack.execution\\n  - attack.t1059.004",
    "splunk": "index=linux_audit sourcetype=auditd_process\\n  parent_image IN (\\"*/python\\", \\"*/python3\\", \\"*/node\\")\\n  image IN (\\"*/bash\\", \\"*/sh\\", \\"*/zsh\\")\\n  NOT user IN (\\"svc_build\\", \\"runner\\")\\n| table _time, host, user, image, command_line, parent_image\\n| sort -_time",
    "pyspark": "events = spark.table(\\"linux_process_events\\")\\nshell_spawn = events.filter(\\n    col(\\"parent_image\\").rlike(\\"/python3?$|/node$\\") &\\n    col(\\"image\\").rlike(\\"/bash$|/sh$|/zsh$\\") &\\n    ~col(\\"user\\").isin([\\"svc_build\\", \\"runner\\"])\\n)\\nshell_spawn.write.mode(\\"append\\").parquet(\\"s3://detections/shell-spawn/\\")"
  },
  "metadata": {
    "severity": "high",
    "mitre": ["T1059.004"],
    "required_fields": ["image", "parent_image", "user", "command_line"],
    "logsource_category": "process_creation"
  },
  "false_positives": [
    "CI/CD pipelines using Python to orchestrate shell tasks (filtered by user in rule)",
    "Developer workstations running Python scripts that invoke bash for tooling",
    "Container entrypoint scripts spawning shells for initialization"
  ],
  "tuning_guidance": "Scope to production hosts via index filter. Add TTY detection to focus on interactive shells only. Baseline known automation service account names and add to filter_ci.",
  "quality_scores": {
    "coverage_quality": 8,
    "field_specificity": 9,
    "format_correctness": 9
  },
  "assumptions": [
    "Target platform linux — used auditd field schema",
    "sample_log was null — field names derived from standard Linux process_creation schema"
  ]
}`;
