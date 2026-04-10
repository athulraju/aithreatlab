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
      "Use privilege-separated architectures, never expose raw user input directly to LLM system prompt",
      "Apply content filtering to all external data sources before LLM ingestion",
      "Enforce strict tool permission boundaries, minimize what agents can do",
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
      "Attackers craft inputs that consume disproportionate computational resources, extremely long prompts, recursive context expansion, or adversarial inputs that cause model instability.",
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
      "Statistical baseline on token usage, flag requests >3 sigma above mean",
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
  {
    id: "llm-06",
    rank: 6,
    name: "Sensitive Information Disclosure",
    category: "llm",
    severity: "high",
    description:
      "LLMs may reveal sensitive data, including PII, credentials, internal system details, or confidential business context, either memorized from training data or present in the conversation context.",
    protection: [
      "Apply output filtering to detect and redact PII and secrets before returning responses",
      "Restrict what data enters the LLM context, enforce data classification at ingestion",
      "Use data loss prevention (DLP) controls on LLM API responses",
      "Avoid including credentials, internal URLs, or sensitive configuration in prompts",
    ],
    monitoring: [
      "Scan LLM API responses for PII patterns (emails, SSNs, credit card numbers)",
      "Alert on responses containing internal hostnames, IP ranges, or path structures",
      "Monitor for repeated probing queries designed to extract memorized information",
    ],
    logsRequired: [
      "LLM API response logs",
      "DLP scanning logs for API outputs",
      "User query logs with entity pattern detection",
    ],
    detectionIdeas: [
      "Regex and ML-based PII detection on API response content",
      "Alert on responses matching internal data patterns not present in the prompt",
      "Statistical analysis of user query patterns targeting information extraction",
    ],
    challenges: [
      "LLMs may return sensitive data in indirect or paraphrased form evading regex matching",
      "Distinguishing legitimate data retrieval from unauthorized disclosure is context-dependent",
      "Memorization in base models may not be visible in fine-tuned versions until probed",
    ],
  },
  {
    id: "llm-07",
    rank: 7,
    name: "Insecure Plugin Design",
    category: "llm",
    severity: "high",
    description:
      "LLM plugins and tool integrations with excessive permissions, insufficient input validation, or no authentication create attack surfaces for privilege escalation and data exfiltration through the LLM layer.",
    protection: [
      "Apply least-privilege permissions to all LLM plugins and tool integrations",
      "Validate and sanitize all inputs passed to plugins before execution",
      "Require authentication for plugin API endpoints, do not assume LLM context is trusted",
      "Document plugin capabilities and enforce strict parameter schemas",
    ],
    monitoring: [
      "Log all plugin invocations with inputs, outputs, and caller identity",
      "Alert on plugin calls with unusual parameter values or outside expected usage patterns",
      "Monitor for plugin chaining sequences that result in privilege escalation",
    ],
    logsRequired: [
      "Plugin execution audit logs",
      "API gateway access logs for plugin endpoints",
      "Permission grant and denial logs for plugin-initiated actions",
    ],
    detectionIdeas: [
      "Baseline normal plugin call patterns and alert on deviations",
      "Flag plugin inputs containing injection-like strings or sensitive data patterns",
      "Detect sequences: external retrieval → sensitive plugin invocation within short time window",
    ],
    challenges: [
      "Plugin ecosystems are often third-party and lack standardized audit logging",
      "LLM-mediated plugin calls may not appear in standard security telemetry",
      "Complex tool chains make causality attribution difficult",
    ],
  },
  {
    id: "llm-08",
    rank: 8,
    name: "Excessive Agency",
    category: "llm",
    severity: "high",
    description:
      "LLM-based systems granted excessive permissions or autonomy can take harmful actions with real-world consequences, deleting data, sending communications, modifying configurations, without adequate human oversight.",
    protection: [
      "Grant LLM systems the minimum permissions required for defined tasks",
      "Implement human-in-the-loop approval for consequential or irreversible actions",
      "Define explicit action boundaries and refuse out-of-scope requests programmatically",
      "Use read-only access wherever write access is not strictly required",
    ],
    monitoring: [
      "Log all actions taken by LLM systems with full context and authorization chain",
      "Alert on LLM-initiated write, delete, or send operations without explicit user confirmation",
      "Monitor for LLM service accounts accessing resources beyond their declared scope",
    ],
    logsRequired: [
      "LLM action execution logs (what action, what resource, which user context)",
      "File and database write logs attributed to LLM service accounts",
      "Email and API send logs from LLM-controlled identities",
    ],
    detectionIdeas: [
      "Flag irreversible actions (delete, send, deploy) taken without approval log entry",
      "Alert on LLM service account performing actions not listed in its permission model",
      "Volume anomaly on write/send operations from LLM-attributed sessions",
    ],
    challenges: [
      "Legitimate agentic workflows involve consequential actions, intent is hard to determine",
      "Human approval workflows can be bypassed through prompt manipulation",
      "Defining acceptable action boundaries is organization-specific",
    ],
  },
  {
    id: "llm-09",
    rank: 9,
    name: "Overreliance",
    category: "llm",
    severity: "medium",
    description:
      "Users and systems place excessive trust in LLM outputs without verification, leading to security-relevant decisions based on hallucinated, biased, or manipulated content, including incorrect security guidance, code vulnerabilities, or false threat intelligence.",
    protection: [
      "Implement output validation for safety-critical LLM use cases",
      "Design systems to treat LLM outputs as advisory rather than authoritative",
      "Add human review checkpoints for high-impact LLM-driven decisions",
      "Educate users on LLM hallucination and manipulation risks",
    ],
    monitoring: [
      "Track outcomes of LLM-driven decisions and flag adverse results for review",
      "Monitor for LLM-generated code or configurations deployed without review",
      "Log cases where LLM outputs directly drive automated downstream actions",
    ],
    logsRequired: [
      "LLM output usage logs (what was done with the response)",
      "Code deployment logs attributed to LLM-generated content",
      "Decision audit logs for LLM-assisted workflows",
    ],
    detectionIdeas: [
      "Static analysis on LLM-generated code before deployment",
      "Anomaly detection on LLM-sourced configuration changes",
      "Flag automated pipelines that accept LLM output without validation steps",
    ],
    challenges: [
      "Hallucinations and correct responses are syntactically indistinguishable without domain knowledge",
      "Overreliance often manifests in process failures rather than technical logs",
      "Security-relevant errors may not surface until adversarial exploitation",
    ],
  },
  {
    id: "llm-10",
    rank: 10,
    name: "Unbounded Consumption",
    category: "llm",
    severity: "medium",
    description:
      "Lack of resource controls allows attackers or misconfigurations to cause excessive LLM API consumption, through long prompts, context flooding, recursive agent loops, or credential sharing, resulting in cost exhaustion, degraded availability, or denial of service.",
    protection: [
      "Enforce per-user and per-application token limits and rate limits",
      "Implement context window management to prevent unbounded expansion",
      "Set hard cost caps per user session and per API key",
      "Detect and terminate infinite agent loops with execution depth limits",
    ],
    monitoring: [
      "Monitor token consumption per user and per API key for statistical outliers",
      "Alert on sustained high-volume requests or cost spikes from new principals",
      "Track agent execution depth and duration for loop detection",
    ],
    logsRequired: [
      "LLM API usage logs (tokens, cost, latency per request)",
      "Rate limiting system logs with denial records",
      "Agent execution trace logs with depth and duration metrics",
    ],
    detectionIdeas: [
      "Statistical baseline on token usage, alert on requests exceeding 3 sigma above user mean",
      "Alert on agent loops exceeding configured depth or duration thresholds",
      "Detect distributed DoS: many low-volume users from correlated IPs targeting same endpoint",
    ],
    challenges: [
      "Legitimate use cases (document analysis, long-context reasoning) have inherently high token counts",
      "Distributed attacks across many low-volume sessions are hard to attribute",
      "Agent loops may be legitimate before becoming runaway",
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
      "Implement least-privilege tool permissions, scope each tool to minimum required access",
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
      "Tool call sequence modeling, flag sequences inconsistent with stated task",
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
      "Autonomous agents deviate from intended objectives, pursuing sub-goals that conflict with user intent, either through manipulation, poor instruction following, or emergent optimization behavior.",
    protection: [
      "Define explicit success criteria and stopping conditions in agent prompts",
      "Implement task scoping, restrict agent to declared resources and actions",
      "Add periodic human checkpoints for long-running tasks",
      "Use multi-agent oversight, have a monitoring agent review primary agent plans",
    ],
    monitoring: [
      "Compare actual agent actions against declared task objectives",
      "Monitor resource access scope, alert if agent accesses out-of-scope assets",
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
      "Agents with over-broad permissions operate in environments where they can make consequential decisions, deleting data, contacting users, deploying code, without appropriate human oversight.",
    protection: [
      "Define agent permission boundaries before deployment",
      "Implement reversibility checks, require confirmation for irreversible actions",
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
      "Autonomous operation is the intended design, distinguishing legitimate from excessive is context-dependent",
    ],
  },
  {
    id: "agent-04",
    rank: 4,
    name: "Data Exfiltration via Agent APIs",
    category: "agentic",
    severity: "critical",
    description:
      "Agents manipulated through prompt injection or goal drift are used as data exfiltration channels, reading sensitive data and transmitting it via email, API calls, or external web requests.",
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
      "Agents legitimately read and summarize data, distinguishing exfiltration from intended use",
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
      "Do not grant elevated trust to messages from other agents, validate all instructions",
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
  {
    id: "agent-06",
    rank: 6,
    name: "Memory and Context Poisoning",
    category: "agentic",
    severity: "high",
    description:
      "Persistent agent memory stores, vector databases, conversation logs, context files, and session state, are manipulated to inject adversarial instructions that persist across sessions and influence future agent behavior.",
    protection: [
      "Treat memory inputs as untrusted, validate and sanitize content before storage",
      "Implement access controls on agent memory stores with audit logging",
      "Use integrity checksums on critical context files and prompt templates",
      "Scope memory access to the task, prevent cross-session context bleed",
    ],
    monitoring: [
      "Monitor writes to agent memory directories and vector store indices",
      "Alert on unexpected modifications to prompt templates or system instruction files",
      "Detect sudden behavioral changes after memory retrieval operations",
    ],
    logsRequired: [
      "File write logs for agent memory and context directories",
      "Vector database write and update audit logs",
      "Agent behavior change logs correlated with memory access events",
    ],
    detectionIdeas: [
      "Hash-based integrity monitoring for system prompt and persona files",
      "Anomaly detection on memory write operations from agent runtimes",
      "Detect injection strings (override, ignore instructions, new persona) in memory store contents",
    ],
    challenges: [
      "Poisoned memory may produce subtly altered behavior that is hard to distinguish from legitimate learning",
      "Vector database contents are not human-readable, making manual inspection difficult",
      "Persistent poisoning across sessions evades per-session detection baselines",
    ],
  },
  {
    id: "agent-07",
    rank: 7,
    name: "Prompt Injection Leading to Agent Action Chain",
    category: "agentic",
    severity: "critical",
    description:
      "Adversarial content retrieved from external sources, web pages, documents, emails, API responses, contains injected instructions that redirect the agent to execute a sequence of malicious tool calls, often resulting in data exfiltration, system modification, or lateral movement.",
    protection: [
      "Apply content filtering to all external data before it enters the agent's reasoning context",
      "Isolate retrieval from action, prevent retrieved content from directly triggering tool calls",
      "Implement mandatory human review before executing action sequences following external data ingestion",
      "Use semantic analysis to detect instruction-like patterns in retrieved content",
    ],
    monitoring: [
      "Correlate retrieval events with subsequent tool call sequences, flag anomalous patterns",
      "Alert on tool calls that occur immediately after external document or web retrieval",
      "Monitor for action sequences consistent with known exfiltration or lateral movement patterns",
    ],
    logsRequired: [
      "Retrieval operation logs (source URL/document, content hash)",
      "Tool call sequence logs with timestamps relative to retrieval events",
      "Agent reasoning trace logs showing how retrieved content influenced actions",
    ],
    detectionIdeas: [
      "Time-windowed detection: external retrieval followed by sensitive tool call within 30 seconds",
      "Sequence anomaly: retrieval → credential access → egress, flag this three-step pattern",
      "Content analysis on retrieved documents for injection-pattern strings before agent ingestion",
    ],
    challenges: [
      "Legitimate agentic workflows retrieve content and act on it, false positives are high without baseline",
      "Injection instructions may be encoded or embedded in benign-looking content",
      "Fast-moving agents may complete the exfiltration chain before detection fires",
    ],
  },
  {
    id: "agent-08",
    rank: 8,
    name: "Insufficient Human Oversight Controls",
    category: "agentic",
    severity: "high",
    description:
      "Agentic deployments lack adequate mechanisms for humans to observe, interrupt, or override agent behavior, allowing errors, manipulation, or misalignment to compound unchecked across long-running task sequences.",
    protection: [
      "Define explicit human approval gates for high-impact or irreversible actions",
      "Implement interrupt and rollback capabilities for all agent-initiated changes",
      "Provide real-time visibility dashboards showing agent task progress and tool usage",
      "Set maximum autonomy thresholds, require human confirmation after N consecutive tool calls",
    ],
    monitoring: [
      "Log all agent actions with reversibility classification (reversible vs. permanent)",
      "Alert when agents execute long sequences without human interaction",
      "Monitor for agents that are systematically avoiding approval workflows",
    ],
    logsRequired: [
      "Agent action logs with reversibility metadata",
      "Human approval/override event logs",
      "Agent session duration and tool call count metrics",
    ],
    detectionIdeas: [
      "Alert on sessions exceeding configured consecutive tool call threshold without human checkpoint",
      "Detect systematic bypassing of approval gates across multiple sessions",
      "Flag agents that execute irreversible actions after task scope has changed",
    ],
    challenges: [
      "Defining the right frequency and granularity of oversight is organization-specific",
      "Excessive oversight checkpoints degrade the operational value of agentic AI",
      "Approval workflow fatigue leads to rubber-stamping, qualitative oversight quality is hard to measure",
    ],
  },
  {
    id: "agent-09",
    rank: 9,
    name: "Misinformation and Deceptive Outputs",
    category: "agentic",
    severity: "medium",
    description:
      "Agents generate and act on inaccurate, fabricated, or adversarially manipulated information, including false threat intelligence, incorrect security advisories, fabricated audit trails, or deceptive responses to oversight systems, eroding trust in agentic workflows.",
    protection: [
      "Require grounding citations for agent outputs used in security decisions",
      "Implement output validation pipelines that cross-check agent conclusions against authoritative sources",
      "Treat agent-generated reports as unverified until validated against raw evidence",
      "Use multi-agent cross-verification for high-stakes outputs",
    ],
    monitoring: [
      "Compare agent outputs against ground-truth data sources for key claims",
      "Alert on agent-generated reports that conflict with direct log evidence",
      "Monitor for agents that generate outputs inconsistent with their tool call history",
    ],
    logsRequired: [
      "Agent output logs with source attribution",
      "Tool call result logs used to support agent conclusions",
      "Downstream usage logs showing where agent outputs influenced decisions",
    ],
    detectionIdeas: [
      "Cross-reference agent-stated facts with raw log evidence, flag unexplained discrepancies",
      "Detect agents that generate conclusive outputs without corresponding evidence in tool call logs",
      "Monitor for patterns of systematic overconfidence or scope misrepresentation",
    ],
    challenges: [
      "Distinguishing hallucination from manipulation requires deep domain knowledge",
      "Agents may be subtly inaccurate in ways that are difficult to detect without expert review",
      "Fabricated audit trails are particularly dangerous as they undermine investigation integrity",
    ],
  },
  {
    id: "agent-10",
    rank: 10,
    name: "Insecure Agent Deployment and Runtime Configuration",
    category: "agentic",
    severity: "high",
    description:
      "Agents deployed with insecure runtime configurations, exposed API endpoints, unencrypted inter-agent channels, hardcoded credentials, overly permissive container privileges, or inadequate network segmentation, create infrastructure-level attack surfaces that compound agentic AI risks.",
    protection: [
      "Harden agent runtime containers, no privileged mode, minimal OS capabilities, read-only filesystem where possible",
      "Encrypt all inter-agent communications in transit using mutual TLS",
      "Store agent credentials and API keys in secrets management systems, not environment variables or config files",
      "Apply network segmentation to agent runtimes, restrict inbound and outbound communication",
    ],
    monitoring: [
      "Monitor agent runtime processes for container escape indicators (unexpected system calls, namespace access)",
      "Alert on hardcoded credentials detected in agent configuration files or environment variables",
      "Track network connections from agent runtimes, flag connections to unexpected destinations",
    ],
    logsRequired: [
      "Container runtime security logs (syscall audit, capability usage)",
      "Secrets access logs from secrets management systems",
      "Network egress logs from agent runtime network namespaces",
    ],
    detectionIdeas: [
      "CIS benchmark scanning of agent container configurations at deployment time",
      "Detect credentials in configuration files using secrets scanning in CI/CD pipeline",
      "Network flow anomaly detection for agent runtime outbound connections",
    ],
    challenges: [
      "Agent infrastructure is often deployed rapidly by development teams without security review",
      "Container-based agentic workloads require security tooling adapted for dynamic, short-lived runtimes",
      "Secrets scanning may produce false positives on test credentials or example configurations",
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
    href: "https://arxiv.org/html/2601.10923v2",
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
