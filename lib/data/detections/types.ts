export interface Detection {
  id: string;
  title: string;
  description: string;
  platform: string[];
  mitre: string[];
  category: string;
  maturity: "production" | "stable" | "experimental" | "deprecated";
  severity: "critical" | "high" | "medium" | "low";
  tags: string[];
  author: string;
  updated: string;
  sigma: string;
  splunk: string;
  pyspark: string;
  sampleLogs: string[];
  requiredFields: string[];
  falsePositives: string[];
  tuningGuidance: string;
  deploymentNotes: string;
  evasionConsiderations: string;
  problemStatement: string;
}

