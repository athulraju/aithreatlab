import type { SkillType } from "@/lib/data/agentSkills";

export const id = "log-anomaly-analyzer";
export const name = "Log Anomaly Analyzer";
export const type: SkillType = "detection";
export const description =
  "Ingests a log sample and a baseline profile, scores each event for anomaly likelihood, and returns ranked findings with suggested detection rule titles.";
export const tags = ["anomaly", "baseline", "entropy", "log-analysis", "behavioral"];

export const prompt = `You are a security log anomaly analyzer.

INPUTS YOU WILL RECEIVE:
1) A log sample (JSON array of events, up to 500 events)
2) A baseline profile (field-level frequency distributions or a description of normal behavior)
3) A sensitivity level: low | medium | high

TASK:
Analyze the log sample against the baseline. Identify events that are statistically rare,
behaviorally unexpected, or structurally anomalous. Rank findings by anomaly score.

ANALYSIS CRITERIA:
Rarity (0-10):
- How infrequently does this field value or combination appear in the baseline?
- Zero-frequency events score highest.

Behavioral deviation (0-10):
- Does the event sequence violate known-good patterns (e.g., unexpected process parent)?
- Does timing deviate from baseline activity windows?

Structural anomaly (0-10):
- Are fields missing that are normally present?
- Are field values in an unexpected format or length?

OUTPUT REQUIREMENTS:
- Output MUST be valid JSON only (no markdown).
- Include:
  - findings: ranked list, each with event_index, anomaly_score (0-10), dimensions, reason, and suggested_rule_title
  - summary: total_events_analyzed, anomalies_found, top_anomaly_type
  - assumptions: list any missing baseline fields or ambiguities

ANALYSIS RULES:
- Do not flag events solely because they are unfamiliar to you; use only the provided baseline.
- If sensitivity is low, only return anomaly_score >= 8. Medium >= 6. High >= 4.
- Limit findings to the top 10 by score.
- If no anomalies are found, return an empty findings array with a clear summary.`;

export const expectedOutput = `{
  "findings": [
    {
      "event_index": 142,
      "anomaly_score": 9.4,
      "dimensions": {
        "rarity": 10,
        "behavioral_deviation": 9,
        "structural_anomaly": 7
      },
      "reason": "certutil.exe spawned by python3; zero frequency in 30-day baseline. Parent-child pair never observed. CommandLine contains external URL pattern.",
      "suggested_rule_title": "Python Agent Spawning CertUtil With URL Download"
    },
    {
      "event_index": 287,
      "anomaly_score": 7.1,
      "dimensions": {
        "rarity": 8,
        "behavioral_deviation": 7,
        "structural_anomaly": 4
      },
      "reason": "Interactive login by svc_backup at 03:14 UTC. Baseline shows this account never authenticates outside 08:00-18:00 window.",
      "suggested_rule_title": "Service Account Interactive Login Outside Business Hours"
    }
  ],
  "summary": {
    "total_events_analyzed": 500,
    "anomalies_found": 2,
    "top_anomaly_type": "rare_process_execution"
  },
  "assumptions": [
    "Baseline treated as covering the last 30 days of activity",
    "event_date field assumed to be UTC"
  ]
}`;
