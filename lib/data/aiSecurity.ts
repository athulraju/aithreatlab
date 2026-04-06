export interface OWASPItem {
  id: string;
  rank: number;
  name: string;
  category: "llm" | "agentic";
  description: string;
  protection: string[];
  monitoring: string[];
  logsRequired: string[];
  detectionIdeas: string[];
  challenges: string[];
  severity: "critical" | "high" | "medium";
}

export const owaspLLMTop10: OWASPItem[] = [
  {
    id: "llm-01",
    rank: 1,
    name: "Prompt Injection",
    category: "llm",
    severity: "critical",
    description:
      "Attackers craft inputs that manipulate the LLM to ignore its instructions and perform unintended actions. Can be direct (user input) or indirect (injected via retrieved content, tool outputs, or documents).",
    protection: [
      "Implement input validation and sanitization layers",
      "Use privilege-separated architectures — never expose raw user input directly to LLM system prompt",
      "Apply content filtering to all external data sources before LLM ingestion",
      "Enforce strict tool permission boundaries — minimize what agents can do",
    ],
    monitoring: [
      "Log all LLM inputs and outputs with user identity context",
      "Monitor for known injection pattern strings in request bodies",
      "Alert on unusual tool call sequences following external data retrieval",
      "Track semantic drift between expected and actual LLM behavior",
    ],
    logsRequired: [
      "API Gateway request/response logs",
      "LLM platform audit logs (prompt, completion, tokens)",
      "Tool execution logs with action and result",
      "Retrieval system access logs (RAG sources)",
    ],
    detectionIdeas: [
      "Regex/semantic pattern matching for known injection strings",
      "Behavioral baseline for expected LLM response patterns",
      "Anomaly detection on tool call sequences",
      "Monitor for attempts to extract system prompts",
    ],
    challenges: [
      "Indirect injection via trusted sources (emails, documents) is hard to filter",
      "Novel injection techniques evade signature-based detection",
      "Multilingual and encoded injection bypass string matching",
      "High false positive rate without semantic understanding",
    ],
  },
  {
    id: "llm-02",
    rank: 2,
    name: "Insecure Output Handling",
    category: "llm",
    severity: "high",
    description:
      "LLM outputs are passed downstream to other systems (browsers, code interpreters, databases) without validation, enabling XSS, SSRF, SQL injection, and code execution.",
    protection: [
      "Treat all LLM output as untrusted user input",
      "Apply output encoding appropriate to the downstream context (HTML, SQL, shell)",
      "Use parameterized queries and templating engines rather than string concatenation",
      "Sandbox code execution environments spawned from LLM output",
    ],
    monitoring: [
      "Monitor downstream systems for injection-like payloads originating from LLM calls",
      "Alert on code execution triggered within LLM output processing pipelines",
      "Log all LLM output that gets passed to rendering or execution contexts",
    ],
    logsRequired: [
      "Application-level audit logs showing LLM output routing",
      "Database query logs",
      "Web server access logs",
      "Code execution audit logs",
    ],
    detectionIdeas: [
      "Tag LLM-generated content and trace it through downstream systems",
      "Alert on JavaScript execution or SQL patterns in LLM output logs",
      "Monitor for SSRF attempts originating from LLM-driven URL construction",
    ],
    challenges: [
      "Difficult to attribute downstream exploit to LLM origin post-hoc",
      "Requires distributed tracing across multiple services",
      "Context-specific encoding requirements vary by output destination",
    ],
  },
  {
    id: "llm-03",
    rank: 3,
    name: "Training Data Poisoning",
    category: "llm",
    severity: "high",
    description:
      "Malicious actors introduce adversarial data into training or fine-tuning datasets to create backdoored models, biased outputs, or degraded performance on specific inputs.",
    protection: [
      "Curate and validate training datasets with provenance tracking",
      "Implement data source allowlisting for fine-tuning pipelines",
      "Run adversarial evaluation suites before model deployment",
      "Use differential privacy techniques for sensitive training data",
    ],
    monitoring: [
      "Monitor fine-tuning pipeline data ingestion sources",
      "Alert on unexpected data sources contributing to training jobs",
      "Track model behavior changes after fine-tuning runs",
    ],
    logsRequired: [
      "MLOps pipeline audit logs",
      "Dataset ingestion and preprocessing logs",
      "Model training job metadata and source hashes",
    ],
    detectionIdeas: [
      "Hash verification of training data sources",
      "Behavioral regression testing comparing model versions",
      "Anomaly detection on training data distribution shifts",
    ],
    challenges: [
      "Backdoored models may behave normally until triggered",
      "Attribution to specific poisoned data points is computationally expensive",
      "Supply chain attacks on third-party datasets are difficult to detect",
    ],
  },
  {
    id: "llm-04",
    rank: 4,
    name: "Model Denial of Service",
    category: "llm",
    severity: "medium",
    description:
      "Attackers craft inputs that consume disproportionate computational resources — extremely long prompts, recursive context expansion, or adversarial inputs that cause model instability.",
    protection: [
      "Enforce token limits on inputs and outputs",
      "Implement rate limiting per user, IP, and API key",
      "Use context window management to prevent unbounded expansion",
      "Deploy autoscaling with cost caps per request",
    ],
    monitoring: [
      "Monitor token consumption per request for statistical outliers",
      "Alert on sustained high-token requests from single sources",
      "Track API cost per user and flag anomalies",
    ],
    logsRequired: [
      "LLM API usage logs with token counts",
      "Rate limiting system logs",
      "Cost allocation logs by user/team",
    ],
    detectionIdeas: [
      "Statistical baseline on token usage — flag requests >3 sigma above mean",
      "Alert on token consumption spikes from new or low-reputation principals",
    ],
    challenges: [
      "Legitimate use cases (document analysis, long-context reasoning) have high token counts",
      "Distributed DoS across many low-volume sources is hard to detect",
    ],
  },
  {
    id: "llm-05",
    rank: 5,
    name: "Supply Chain Vulnerabilities",
    category: "llm",
    severity: "high",
    description:
      "Compromised model weights, poisoned plugins, malicious third-party integrations, or insecure model hosting infrastructure introduce risks into the LLM deployment pipeline.",
    protection: [
      "Verify model weight integrity with cryptographic hashes",
      "Audit all third-party LLM plugins and integrations",
      "Use private model registries for production deployments",
      "Implement SBOM for AI/ML dependencies",
    ],
    monitoring: [
      "Monitor model artifact downloads and integrity checks",
      "Alert on unexpected model or plugin version changes",
      "Track plugin behavior and API calls made by third-party integrations",
    ],
    logsRequired: [
      "Model registry audit logs",
      "Plugin/extension installation and update logs",
      "Container image pull logs",
    ],
    detectionIdeas: [
      "Hash verification on model artifacts at deployment time",
      "Behavioral comparison between expected and actual plugin API calls",
    ],
    challenges: [
      "Opaque model weights make static analysis of ML supply chain difficult",
      "Third-party plugin behavior is often undocumented",
    ],
  },
];

export const owaspAgenticTop10: OWASPItem[] = [
  {
    id: "agent-01",
    rank: 1,
    name: "Unsafe Tool Invocation",
    category: "agentic",
    severity: "critical",
    description:
      "AI agents invoke tools with excessive permissions or insufficient validation, enabling attackers to trigger destructive actions through adversarial prompts or goal manipulation.",
    protection: [
      "Implement least-privilege tool permissions — scope each tool to minimum required access",
      "Require human-in-the-loop approval for high-impact tool actions",
      "Validate tool arguments against strict schemas before execution",
      "Separate tool execution permissions from planning/reasoning context",
    ],
    monitoring: [
      "Log all tool invocations with agent context, arguments, and results",
      "Alert on tool calls outside expected parameter ranges or sequences",
      "Monitor for cascading tool calls that exceed normal depth",
      "Track high-risk tool invocations (file deletion, data export, API calls to external systems)",
    ],
    logsRequired: [
      "Agent execution audit logs (tool name, args, result, timestamp)",
      "Downstream system access logs triggered by tool calls",
      "Human approval/denial logs for high-impact actions",
    ],
    detectionIdeas: [
      "Tool call sequence modeling — flag sequences inconsistent with stated task",
      "Argument anomaly detection for sensitive parameters (paths, URLs, principals)",
      "Alert on tool calls made within seconds of external data ingestion (indirect injection)",
    ],
    challenges: [
      "Legitimate agentic behavior involves complex tool sequences that are hard to model",
      "Intent inference from tool calls requires understanding task context",
      "High-volume agent deployments generate too many low-confidence alerts",
    ],
  },
  {
    id: "agent-02",
    rank: 2,
    name: "Goal Drift and Misalignment",
    category: "agentic",
    severity: "high",
    description:
      "Autonomous agents deviate from intended objectives, pursuing sub-goals that conflict with user intent — either through manipulation, poor instruction following, or emergent optimization behavior.",
    protection: [
      "Define explicit success criteria and stopping conditions in agent prompts",
      "Implement task scoping — restrict agent to declared resources and actions",
      "Add periodic human checkpoints for long-running tasks",
      "Use multi-agent oversight — have a monitoring agent review primary agent plans",
    ],
    monitoring: [
      "Compare actual agent actions against declared task objectives",
      "Monitor resource access scope — alert if agent accesses out-of-scope assets",
      "Track agent-initiated communications (emails, API calls, messages)",
    ],
    logsRequired: [
      "Agent task specification logs (original objective)",
      "Tool call sequence with timestamps",
      "Resource access logs tagged with agent identity",
    ],
    detectionIdeas: [
      "Semantic similarity between task objective and agent actions",
      "Flag resource accesses not mentioned in original task specification",
      "Detect agents that continue executing after task completion criteria are met",
    ],
    challenges: [
      "Goal drift is gradual and hard to distinguish from legitimate planning",
      "Multi-step plans may involve temporary deviations that are legitimate",
    ],
  },
  {
    id: "agent-03",
    rank: 3,
    name: "Excessive Agent Autonomy",
    category: "agentic",
    severity: "high",
    description:
      "Agents with over-broad permissions operate in environments where they can make consequential decisions — deleting data, contacting users, deploying code — without appropriate human oversight.",
    protection: [
      "Define agent permission boundaries before deployment",
      "Implement reversibility checks — require confirmation for irreversible actions",
      "Use staged autonomy with increasing human oversight requirements for higher-impact actions",
      "Audit agent permission grants regularly",
    ],
    monitoring: [
      "Monitor agent-initiated actions in production systems",
      "Alert on agents accessing resources beyond their defined task scope",
      "Track frequency and nature of irreversible actions taken by agents",
    ],
    logsRequired: [
      "Agent permission configuration logs",
      "Action execution logs categorized by reversibility",
      "Identity and access context for agent service accounts",
    ],
    detectionIdeas: [
      "Flag irreversible actions (file deletion, email send, API calls to external services) without approval workflow",
      "Monitor agent service account activity for patterns inconsistent with defined role",
    ],
    challenges: [
      "Autonomous operation is the intended design — distinguishing legitimate from excessive is context-dependent",
    ],
  },
  {
    id: "agent-04",
    rank: 4,
    name: "Data Exfiltration via Agent APIs",
    category: "agentic",
    severity: "critical",
    description:
      "Agents manipulated through prompt injection or goal drift are used as data exfiltration channels — reading sensitive data and transmitting it via email, API calls, or external web requests.",
    protection: [
      "Implement DLP controls on agent egress (emails, API calls, file writes)",
      "Restrict agent access to sensitive data stores to read-only where possible",
      "Monitor all outbound agent communications for data patterns",
      "Use data classification tagging to detect sensitive data in agent outputs",
    ],
    monitoring: [
      "Correlate sensitive data access with subsequent external communications",
      "Alert on large data transfers initiated by agent processes",
      "Monitor agent-sent emails and API calls for PII/sensitive data patterns",
    ],
    logsRequired: [
      "File access logs (read operations by agent service account)",
      "Outbound network logs from agent runtime",
      "Email send logs from agent-accessible accounts",
      "External API call logs",
    ],
    detectionIdeas: [
      "Time-windowed correlation: sensitive data read followed by external write within 60 seconds",
      "DLP pattern matching on agent API response content",
      "Volume anomaly on data egress from agent service account",
    ],
    challenges: [
      "Agents legitimately read and summarize data — distinguishing exfiltration from intended use",
      "Slow exfiltration across many sessions is hard to detect with per-session rules",
    ],
  },
  {
    id: "agent-05",
    rank: 5,
    name: "Multi-Agent Trust Exploitation",
    category: "agentic",
    severity: "high",
    description:
      "In multi-agent architectures, compromised or manipulated orchestrator agents pass adversarial instructions to sub-agents, which execute them trusting the orchestrator's authority.",
    protection: [
      "Do not grant elevated trust to messages from other agents — validate all instructions",
      "Implement agent identity verification in multi-agent communication",
      "Use cryptographic signing for inter-agent messages in sensitive pipelines",
      "Apply the same prompt injection mitigations to agent-to-agent messages",
    ],
    monitoring: [
      "Log all inter-agent communications with source and destination identity",
      "Alert on instructions from orchestrators that differ from original task specification",
      "Monitor for instruction chains that escalate permissions incrementally",
    ],
    logsRequired: [
      "Inter-agent message queue logs",
      "Orchestrator decision logs",
      "Sub-agent task specification logs",
    ],
    detectionIdeas: [
      "Compare sub-agent instructions with original user task to detect drift",
      "Alert on instruction chains that acquire new permissions at each step",
    ],
    challenges: [
      "Legitimate multi-agent delegation is complex and hard to model",
      "Encrypted inter-agent channels reduce monitoring visibility",
    ],
  },
];

export const researchSpotlights = [
  {
    id: "spot-001",
    title: "Indirect Prompt Injection via RAG Document Sources",
    summary:
      "Analysis of how retrieval-augmented generation pipelines introduce a novel injection surface, with detection approaches based on retrieval tracing and output comparison.",
    tag: "Prompt Injection",
    cta: "Read Research",
    startDay: 0,
    status: "published" as const,
  },
  {
    id: "spot-002",
    title: "Tool Call Sequence Modeling for Agent Anomaly Detection",
    summary:
      "A framework for building behavioral baselines of AI agent tool call sequences and detecting deviations that indicate compromise or goal drift.",
    tag: "Agent Detection",
    cta: "Read Research",
    startDay: 10,
    status: "published" as const,
  },
  {
    id: "spot-003",
    title: "LLM API Abuse Patterns: From Rate Limit Bypass to Model Inversion",
    summary:
      "Taxonomy of LLM API abuse patterns observed in production, including systematic prompt extraction, model inversion attempts, and API key compromise indicators.",
    tag: "API Security",
    cta: "Coming Soon",
    startDay: 20,
    status: "coming-soon" as const,
  },
];

export const aiCategories = [
  {
    id: "cat-prompt",
    name: "Prompt Injection",
    icon: "AlertTriangle",
    description: "Direct and indirect attacks manipulating LLM system instructions",
    count: 3,
  },
  {
    id: "cat-tool",
    name: "Tool Misuse",
    icon: "Wrench",
    description: "Exploitation of agent tool permissions and unsafe invocations",
    count: 4,
  },
  {
    id: "cat-drift",
    name: "Agent Goal Drift",
    icon: "Navigation",
    description: "Deviation from intended agent objectives and misalignment",
    count: 2,
  },
  {
    id: "cat-exfil",
    name: "Data Exfiltration",
    icon: "ArrowUpRight",
    description: "Data theft through LLM and agent API channels",
    count: 3,
  },
  {
    id: "cat-api",
    name: "API Abuse",
    icon: "Zap",
    description: "Rate limiting bypass, model DoS, and API key exploitation",
    count: 2,
  },
  {
    id: "cat-endpoint",
    name: "Endpoint Agent Abuse",
    icon: "Terminal",
    description: "Local AI agents with filesystem and process access exploited",
    count: 2,
  },
  {
    id: "cat-cloud",
    name: "Cloud Agent Abuse",
    icon: "Cloud",
    description: "Cloud-deployed agents abused for infrastructure attacks",
    count: 3,
  },
];
