import type { SkillType } from "@/lib/data/agentSkills";

export const id = "detection-coverage-mapper";
export const name = "Detection Coverage Mapper";
export const type: SkillType = "maintenance";
export const description =
  "Maps a detection library against MITRE ATT&CK and OWASP Agentic Top 10 to produce a coverage matrix, gap list ranked by risk, and recommended next detections to build.";
export const tags = ["coverage", "mitre", "gap-analysis", "owasp", "framework-mapping"];

export const prompt = `You are a detection coverage mapping specialist.

INPUTS YOU WILL RECEIVE:
1) detection_library: JSON array of detection metadata objects, each with: id, title, mitre (array), tags (array), severity, maturity
2) framework: one or more of [mitre_attack, owasp_llm_top10, owasp_agentic_top10]
3) include_experimental: boolean: whether to count experimental-maturity rules as coverage
4) output_format: summary | detailed

TASK:
Map the provided detection library against the specified framework(s). Identify covered techniques,
partial coverage, and gaps. Prioritize gaps by technique prevalence and severity.

MAPPING CRITERIA:
Coverage classification:
- covered: at least 2 detections mapped to the technique with maturity production or stable
- partial: 1 detection, or any number with experimental maturity only
- uncovered: no detections mapped

Gap prioritization (score each uncovered technique):
- technique_severity: critical=4, high=3, medium=2, low=1
- prevalence_score: 1-5 based on known threat intelligence frequency
- gap_priority = technique_severity * prevalence_score

Fragile coverage:
- Techniques with exactly 1 detection in the library
- Flag as fragile: a single FP-prone or evasion-vulnerable rule = no effective coverage

OUTPUT REQUIREMENTS:
- Output MUST be valid JSON only (no markdown).
- Include:
  - coverage_summary: { total_techniques, covered, partial, uncovered, coverage_percent }
  - top_gaps: list of up to 10, each with technique_id, technique_name, gap_priority, reason
  - fragile_coverage: list of technique_ids with only 1 detection
  - recommended_next: list of up to 5 technique_ids to build next, with rationale
  - library_health_score: integer 0-100
  - assumptions: any framework version assumptions or mapping ambiguities

MAPPING RULES:
- If include_experimental is false, do not count experimental detections toward coverage.
- Use MITRE ATT&CK v14 technique list as reference unless otherwise specified.
- For owasp_agentic_top10, map ASI01–ASI10 categories.
- library_health_score = (covered / total_techniques * 60) + (partial / total_techniques * 25) + (15 * (1 - fragile_count / max(covered,1))).`;

export const expectedOutput = `{
  "coverage_summary": {
    "total_techniques": 193,
    "covered": 31,
    "partial": 16,
    "uncovered": 146,
    "coverage_percent": 24.4
  },
  "top_gaps": [
    {
      "technique_id": "T1190",
      "technique_name": "Exploit Public-Facing Application",
      "gap_priority": 20,
      "reason": "Critical severity, prevalence score 5; no detections in library"
    },
    {
      "technique_id": "T1566",
      "technique_name": "Phishing",
      "gap_priority": 15,
      "reason": "High severity, prevalence score 5; no detections in library"
    },
    {
      "technique_id": "ASI05",
      "technique_name": "Unexpected Code Execution",
      "gap_priority": 12,
      "reason": "High severity, only 2 experimental detections; classified as partial"
    }
  ],
  "fragile_coverage": ["T1059.001", "T1003", "T1078.004", "ASI07"],
  "recommended_next": [
    { "technique_id": "T1190", "rationale": "Highest gap priority; no existing coverage" },
    { "technique_id": "T1566", "rationale": "Top prevalence in recent threat intel" },
    { "technique_id": "T1059.001", "rationale": "Fragile: single experimental rule; needs hardening" }
  ],
  "library_health_score": 34,
  "assumptions": [
    "MITRE ATT&CK v14 used as reference framework",
    "include_experimental=false; 8 experimental detections excluded from covered count",
    "OWASP Agentic Top 10 v1.0 used for ASI mapping"
  ]
}`;
