export type SkillType = "detection" | "maintenance";

export interface AgentSkill {
  id: string;
  name: string;
  type: SkillType;
  description: string;
  tags: string[];
  prompt: string;
  expectedOutput: string;
}

// ── Detection Skills ──────────────────────────────────────────────────────────
import * as logAnomalyAnalyzer    from "@/lib/skills/log-anomaly-analyzer";
import * as goalDriftDetector     from "@/lib/skills/goal-drift-detector";
import * as promptInjection       from "@/lib/skills/prompt-injection-detector";
import * as toolMisuse            from "@/lib/skills/tool-misuse-detector";
import * as dataExfiltration      from "@/lib/skills/data-exfiltration-detector";
import * as detectionGenerator    from "@/lib/skills/detection-generator";

// ── Maintenance Skills ────────────────────────────────────────────────────────
import * as pysparkReviewer       from "@/lib/skills/pyspark-query-reviewer";
import * as ruleOptimizer         from "@/lib/skills/detection-rule-optimizer";
import * as coverageMapper        from "@/lib/skills/detection-coverage-mapper";
import * as consistencyChecker    from "@/lib/skills/detection-consistency-checker";

function toSkill(mod: {
  id: string;
  name: string;
  type: SkillType;
  description: string;
  tags: string[];
  prompt: string;
  expectedOutput: string;
}): AgentSkill {
  return {
    id: mod.id,
    name: mod.name,
    type: mod.type,
    description: mod.description,
    tags: mod.tags,
    prompt: mod.prompt,
    expectedOutput: mod.expectedOutput,
  };
}

export const agentSkills: AgentSkill[] = [
  toSkill(logAnomalyAnalyzer),
  toSkill(goalDriftDetector),
  toSkill(promptInjection),
  toSkill(toolMisuse),
  toSkill(dataExfiltration),
  toSkill(detectionGenerator),
  toSkill(pysparkReviewer),
  toSkill(ruleOptimizer),
  toSkill(coverageMapper),
  toSkill(consistencyChecker),
];

export const skillCategories: { id: SkillType; label: string; description: string }[] = [
  { id: "detection",    label: "Detection Skills",    description: "Active threat detection and analysis" },
  { id: "maintenance",  label: "Maintenance Skills",  description: "Library health and optimization" },
];
