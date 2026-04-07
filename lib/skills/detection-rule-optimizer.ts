import type { SkillType } from "@/lib/data/agentSkills";

export const id = "detection-rule-optimizer";
export const name = "Detection Rule Optimizer";
export const type: SkillType = "maintenance";
export const description =
  "Takes an existing detection rule plus FP/TP examples and rewrites it to reduce false positive rate, improve query performance, and close evasion gaps without losing true positive coverage.";
export const tags = ["optimization", "fp-reduction", "performance", "tuning", "rule-quality"];

export const prompt = `You are a security detection rule optimization specialist.

INPUTS YOU WILL RECEIVE:
1) detection_rule: the original rule as a string (Sigma YAML, Splunk SPL, or PySpark)
2) rule_format: one of [sigma, splunk, pyspark]
3) fp_examples: JSON array of false positive log events (events that triggered the rule but should not have)
4) tp_examples: JSON array of true positive log events (events that should trigger the rule)
5) optimization_goal: one or more of [reduce_fp_rate, improve_performance, close_evasion_gaps]

TASK:
Analyze the rule against the provided examples. Identify what causes false positives, what evasion
paths exist, and how to tighten the rule without losing true positive coverage.

OPTIMIZATION CRITERIA:
FP reduction (0-10):
- What fields or values appear in fp_examples but NOT in tp_examples?
- These are candidate filter conditions to add.
- Never remove a condition that appears in tp_examples.

Performance improvement (0-10):
- Are expensive operations (joins, UDFs, broad wildcards) avoidable?
- Can conditions be reordered to filter more data earlier?

Evasion gap closure (0-10):
- Are there obvious variants of the malicious behavior not covered by the rule?
- (e.g., missing alternate binary paths, alternate argument forms)

OUTPUT REQUIREMENTS:
- Output MUST be valid JSON only (no markdown).
- Include:
  - improvements: { fp_rate_estimate_before, fp_rate_estimate_after, tp_coverage_before, tp_coverage_after, performance_gain_estimate }
  - changes_made: list of strings describing each change and why
  - optimized_rule: the full rewritten rule as a string
  - evasion_gaps_remaining: list of known evasion paths not yet covered
  - assumptions: any inferences made due to missing data

OPTIMIZATION RULES:
- Preserve semantics. If a semantic change is necessary, explicitly justify it in changes_made.
- Do not introduce conditions not supported by the tp_examples or the rule's logsource schema.
- If fp_examples is empty, focus on performance and evasion gap closure only.
- tp_coverage_before and tp_coverage_after are estimates as percentages (0-100).`;

export const expectedOutput = `{
  "improvements": {
    "fp_rate_estimate_before": "12%",
    "fp_rate_estimate_after": "2.1%",
    "tp_coverage_before": 94,
    "tp_coverage_after": 93,
    "performance_gain_estimate": "38% reduction in scanned rows via early filter reorder"
  },
  "changes_made": [
    "Added CommandLine|contains: ['http', '-o '] to curl/wget conditions; all TPs contain these, no FPs do",
    "Added filter_ci for users svc_build and runner; these account for 80% of FP volume",
    "Moved ParentImage check before Image check; higher selectivity filter now runs first",
    "Removed '/scp' from Image list; FP analysis shows 100% of scp matches were legitimate file sync jobs, no TPs used scp"
  ],
  "optimized_rule": "title: Optimized: AI Agent Spawning Network Transfer Tool\\nid: asi02-oci-linux-001-opt\\nstatus: experimental\\nlogsource:\\n  product: linux\\n  category: process_creation\\ndetection:\\n  selection_parent:\\n    ParentImage|endswith: ['/python3', '/node']\\n  selection_child:\\n    Image|endswith: ['/curl', '/wget', '/nc']\\n  selection_args:\\n    CommandLine|contains: ['http', '-o ']\\n  filter_ci:\\n    User: ['svc_build', 'runner', 'github-actions']\\n  condition: selection_parent and selection_child and selection_args and not filter_ci\\nlevel: high",
  "evasion_gaps_remaining": [
    "Agent using Python requests library directly (no child process); requires network telemetry rule",
    "Agent using ncat alias instead of nc; add '/ncat' to Image list"
  ],
  "assumptions": [
    "tp_coverage reduction from 94% to 93% reflects the scp removal; 1 TP used scp, judged acceptable",
    "github-actions added to filter_ci based on FP example user field values"
  ]
}`;
