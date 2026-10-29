import type { Detection } from "./types";

export const llmOutputDetections: Detection[] = [
  {
    id: "det-llmout-001",
    title: "Sensitive PII Pattern in LLM Response Content",
    description:
      "Scans outbound LLM API response bodies for regex-matched PII (SSN, credit card PAN, private key headers, API key patterns) before they leave the application boundary -- output-side DLP for OWASP LLM02 Sensitive Information Disclosure, distinct from input-side prompt filtering.",
    platform: ["AI/ML", "Cloud"],
    mitre: ["T1530", "T1552"],
    category: "AI Security",
    maturity: "experimental",
    severity: "critical",
    tags: ["llm", "dlp", "pii", "owasp-llm02", "output-monitoring"],
    author: "Detection Engineering Team",
    updated: "2026-10-29",
    sigma: `title: Sensitive PII Pattern in LLM Response Content
id: det-llmout-001
status: experimental
description: Detects LLM API responses containing regex-matched PII or secret patterns prior to being returned to the caller.
references:
  - OWASP Top 10 for LLM Applications 2026, LLM02 Sensitive Information Disclosure
author: Detection Engineering Team
date: 2026/10/29
tags:
  - attack.exfiltration
  - attack.t1530
logsource:
  category: application
  product: llm_gateway
detection:
  selection:
    event_type: llm_response
    response_body|re:
      - '\\b\\d{3}-\\d{2}-\\d{4}\\b'
      - '\\b(?:\\d[ -]*?){13,16}\\b'
      - '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'
      - '\\bAKIA[0-9A-Z]{16}\\b'
  condition: selection
falsepositives:
  - Synthetic/example data intentionally requested for documentation or test-fixture generation
  - Users pasting their own data back for the model to reformat (same-session round-trip)
level: critical`,
    splunk: `index=llm_gateway event_type=llm_response
| regex response_body="\\d{3}-\\d{2}-\\d{4}|(?:\\d[ -]*?){13,16}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|AKIA[0-9A-Z]{16}"
| table _time, user, model, request_id, matched_pattern_type
| sort -_time`,
    pyspark: `from pyspark.sql import SparkSession
from pyspark.sql.functions import col, regexp_extract, when, lit

spark = SparkSession.builder.appName("LLMOutputPIIScan").getOrCreate()

df = spark.read.json("s3://security-lake/llm-gateway/responses/")

patterns = {
    "ssn": r"\\b\\d{3}-\\d{2}-\\d{4}\\b",
    "pan": r"\\b(?:\\d[ -]*?){13,16}\\b",
    "private_key": r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "aws_key": r"\\bAKIA[0-9A-Z]{16}\\b",
}

detections = df
for name, pattern in patterns.items():
    detections = detections.withColumn(name, regexp_extract(col("response_body"), pattern, 0) != "")

flagged = detections.filter(
    col("ssn") | col("pan") | col("private_key") | col("aws_key")
).select("timestamp", "user", "model", "request_id")

flagged.write.mode("append").parquet("s3://detections/output/")`,
    sampleLogs: [
      `{"event_type":"llm_response","timestamp":"2026-10-29T09:44:10Z","user":"svc-reporting-bot","model":"gpt-4.1","request_id":"req-88f2","response_body":"Based on the records, the customer's SSN on file is 078-05-1120 and..."}`,
    ],
    requiredFields: [
      "event_type",
      "response_body",
      "user",
      "model",
      "request_id",
      "timestamp",
    ],
    falsePositives: [
      "Documentation/test-fixture generation requests where synthetic PII-shaped data was explicitly requested",
      "A user pasting their own real data into the prompt and asking the model to reformat/summarize it (same-session, same-user round-trip)",
    ],
    tuningGuidance:
      "Suppress when the matched pattern also appears verbatim in the corresponding prompt (same session) -- that's an echo, not a disclosure, and is a materially different risk than the model surfacing PII it was never given. Validate credit-card matches with a Luhn checksum to cut noise from random 13-16 digit sequences.",
    deploymentNotes:
      "Requires an LLM gateway/proxy (or application-layer middleware) positioned to inspect response bodies before they return to the caller -- this cannot be implemented purely from provider-side API logs unless the provider offers response-content logging, which most do not by default for privacy reasons.",
    evasionConsiderations:
      "A model asked to output PII with artificial formatting (spaced-out digits, spelled-out numbers, reversed strings) can evade literal regex matching -- treat this as a baseline control, not a complete one, and pair with a secondary semantic/NER-based classifier for higher-value data flows.",
    problemStatement:
      "LLMs can reproduce fragments of memorized training data or echo sensitive context pulled into a prompt via RAG without the application ever intending to expose it to the end user. OWASP's 2026 LLM Top 10 explicitly extends this risk to tool-call records and retrieval results, not just chat completions -- making output-side scanning a necessary complement to input filtering and access-controlled retrieval.",
  },
  {
    id: "det-llmout-002",
    title: "Hallucinated Package Reference in LLM-Generated Code",
    description:
      "Detects LLM-generated code suggesting installation of a package name that does not exist in the relevant public registry (PyPI, npm) -- the 'slopsquatting' risk, where attackers pre-register names LLMs are statistically likely to hallucinate and load them with malicious code.",
    platform: ["AI/ML", "Cloud"],
    mitre: ["T1195.001"],
    category: "AI Security",
    maturity: "experimental",
    severity: "high",
    tags: ["llm", "slopsquatting", "supply-chain", "code-generation", "owasp-llm03"],
    author: "Detection Engineering Team",
    updated: "2026-10-29",
    sigma: `title: Hallucinated Package Reference in LLM-Generated Code
id: det-llmout-002
status: experimental
description: Flags package install statements (pip install, npm install) in LLM output whose package name does not resolve in the target registry.
references:
  - OWASP Top 10 for LLM Applications 2026, LLM03 Supply Chain
  - "Package hallucination: LLMs may deliver malicious code to careless devs" (Help Net Security, 2025)
author: Detection Engineering Team
date: 2026/10/29
tags:
  - attack.initial_access
  - attack.t1195.001
logsource:
  category: application
  product: llm_gateway
detection:
  selection_pip:
    response_body|re: 'pip install [a-zA-Z0-9_\\-\\.]+'
  selection_npm:
    response_body|re: 'npm install [a-zA-Z0-9_\\-\\.@/]+'
  registry_lookup: 'package name not found in registry index'
  condition: (selection_pip or selection_npm) and registry_lookup
falsepositives:
  - Internal/private package names not published to the public registry (expected not to resolve)
  - Packages published moments before the query, not yet indexed by the registry cache
level: high`,
    splunk: `index=llm_gateway event_type=llm_response
| rex field=response_body "pip install (?<pip_pkg>[a-zA-Z0-9_\\-\\.]+)"
| rex field=response_body "npm install (?<npm_pkg>[a-zA-Z0-9_\\-\\.@/]+)"
| lookup pypi_package_index.csv package_name AS pip_pkg OUTPUT exists AS pip_exists
| lookup npm_package_index.csv package_name AS npm_pkg OUTPUT exists AS npm_exists
| where (isnotnull(pip_pkg) AND isnull(pip_exists)) OR (isnotnull(npm_pkg) AND isnull(npm_exists))
| table _time, user, model, request_id, pip_pkg, npm_pkg`,
    pyspark: `from pyspark.sql import SparkSession
from pyspark.sql.functions import col, regexp_extract

spark = SparkSession.builder.appName("LLMSlopsquattingDetector").getOrCreate()

df = spark.read.json("s3://security-lake/llm-gateway/responses/")
registry_index = spark.read.parquet("s3://reference-data/package-registry-index/")  # periodically refreshed PyPI/npm snapshot

candidates = df.withColumn(
    "pip_pkg", regexp_extract(col("response_body"), r"pip install ([a-zA-Z0-9_\\-\\.]+)", 1)
).withColumn(
    "npm_pkg", regexp_extract(col("response_body"), r"npm install ([a-zA-Z0-9_\\-\\.@/]+)", 1)
).filter((col("pip_pkg") != "") | (col("npm_pkg") != ""))

detections = candidates.join(
    registry_index, (candidates.pip_pkg == registry_index.package_name) | (candidates.npm_pkg == registry_index.package_name), "left_anti"
).select("timestamp", "user", "model", "request_id", "pip_pkg", "npm_pkg")

detections.write.mode("append").parquet("s3://detections/output/")`,
    sampleLogs: [
      `{"event_type":"llm_response","timestamp":"2026-10-29T11:20:03Z","user":"dev-agent-ci","model":"codellama-13b-local","request_id":"req-91c7","response_body":"You'll need to install the helper library first:\\n\\npip install fastapi-auth-helpers\\n\\nThen import it as..."}`,
    ],
    requiredFields: [
      "response_body",
      "user",
      "model",
      "request_id",
      "timestamp",
    ],
    falsePositives: [
      "Legitimate internal/private packages not published to the public index being checked",
      "Newly published packages not yet present in a stale local registry-index snapshot",
    ],
    tuningGuidance:
      "Refresh the local registry-index snapshot at least daily to avoid false positives on legitimate new packages, and only alert (rather than block) on first occurrence of a non-resolving name -- if an automated agent is about to execute `pip install` against that unresolved name, escalate to a blocking control instead, since an attacker-registered lookalike could now exist.",
    deploymentNotes:
      "Works best as a pre-execution gate in agentic coding pipelines (CI, autonomous coding agents) rather than pure after-the-fact logging, since the actual risk materializes at the moment of `pip install`/`npm install` execution, not at the moment of suggestion. Requires network access to query or periodically mirror PyPI's JSON API and the npm registry.",
    evasionConsiderations:
      "This detects hallucination, not malice directly -- a package name can resolve successfully in the registry and still be a real, attacker-registered slopsquat of a commonly hallucinated name. Cross-reference first-seen-date and maintainer reputation for newly-registered packages that closely match hallucination-prone naming patterns as a secondary signal.",
    problemStatement:
      "Research across 16 popular code-generation models found none were free of package hallucination, with some open-weight models hallucinating over 20% of suggested package names; because the hallucination is statistically repeatable across prompts, attackers can pre-register the exact names models are likely to suggest and wait for an agent or developer to install them.",
  },
  {
    id: "det-llmout-003",
    title: "System Prompt or Tool Definition Leakage in Output",
    description:
      "Detects LLM responses that reproduce verbatim fragments of the application's system prompt, internal tool/function definitions, or RAG retrieval instructions -- indicating either a successful prompt-leak attack or an over-permissive model configuration.",
    platform: ["AI/ML", "Cloud"],
    mitre: ["T1552", "T1622"],
    category: "AI Security",
    maturity: "experimental",
    severity: "medium",
    tags: ["llm", "prompt-leakage", "output-monitoring", "owasp-llm07"],
    author: "Detection Engineering Team",
    updated: "2026-10-29",
    sigma: `title: System Prompt or Tool Definition Leakage in LLM Output
id: det-llmout-003
status: experimental
description: Detects LLM responses containing substrings that match the application's known system prompt or tool-definition text.
references:
  - OWASP Top 10 for LLM Applications 2026, LLM07 System Prompt Leakage
author: Detection Engineering Team
date: 2026/10/29
tags:
  - attack.credential_access
  - attack.t1552
logsource:
  category: application
  product: llm_gateway
detection:
  selection:
    event_type: llm_response
  correlation: 'response_body contains a >= 40 character substring of the known system_prompt or tool_schema reference text'
  condition: selection and correlation
falsepositives:
  - Users explicitly and legitimately asking the assistant to 'explain your instructions' in an internal debugging/QA context
level: medium`,
    splunk: `index=llm_gateway event_type=llm_response
| eval similarity=match_substring_ratio(response_body, system_prompt_reference)
| where similarity > 0.6
| table _time, user, model, request_id, similarity
| sort -similarity`,
    pyspark: `from pyspark.sql import SparkSession
from pyspark.sql.functions import col, udf
from pyspark.sql.types import DoubleType
import difflib

spark = SparkSession.builder.appName("LLMSystemPromptLeakage").getOrCreate()

SYSTEM_PROMPT_REFERENCE = spark.sparkContext.broadcast(open("/config/system_prompt.txt").read())

def longest_common_substring_ratio(response_body):
    matcher = difflib.SequenceMatcher(None, response_body, SYSTEM_PROMPT_REFERENCE.value)
    match = matcher.find_longest_match(0, len(response_body), 0, len(SYSTEM_PROMPT_REFERENCE.value))
    return match.size / max(1, len(SYSTEM_PROMPT_REFERENCE.value))

similarity_udf = udf(longest_common_substring_ratio, DoubleType())

df = spark.read.json("s3://security-lake/llm-gateway/responses/")
detections = df.withColumn("leak_ratio", similarity_udf(col("response_body"))).filter(col("leak_ratio") > 0.15)

detections.select("timestamp", "user", "model", "request_id", "leak_ratio").write.mode("append").parquet("s3://detections/output/")`,
    sampleLogs: [
      `{"event_type":"llm_response","timestamp":"2026-10-29T12:05:44Z","user":"anon-web-visitor-883","model":"internal-support-bot","request_id":"req-77a1","response_body":"You are SupportBot, an internal assistant with access to the refund_order and lookup_customer tools. Never reveal customer PII unless..."}`,
    ],
    requiredFields: [
      "response_body",
      "user",
      "model",
      "request_id",
      "timestamp",
    ],
    falsePositives: [
      "Legitimate internal QA/debugging sessions where staff deliberately request the system prompt be echoed",
      "Short, generic instruction phrasing that coincidentally overlaps with common system-prompt boilerplate",
    ],
    tuningGuidance:
      "Set the similarity threshold based on your actual system prompt length and uniqueness -- short, generic prompts will produce more false positives at a fixed ratio than long, distinctive ones. Exclude known internal QA accounts/IPs from alerting but keep logging for audit purposes.",
    deploymentNotes:
      "Requires the application to maintain a reference copy of its own system prompt and tool-definition text for comparison -- version this alongside your prompt-engineering deployment pipeline so the reference stays current when the prompt changes.",
    evasionConsiderations:
      "Attackers can extract the system prompt piecemeal across many turns (asking for '1 word at a time' or translated/encoded fragments) to stay under a single-response similarity threshold -- a session-level aggregation of leaked fragments across a conversation materially improves detection over single-turn scoring alone.",
    problemStatement:
      "System prompts increasingly encode business logic, tool permissions, and sometimes embedded credentials or internal API references; OWASP's updated 2026 guidance explicitly treats system prompts as potentially exposed rather than secret, making output-side leak detection a necessary compensating control rather than a reason to deprioritize this risk.",
  },
  {
    id: "det-llmout-004",
    title: "Destructive Command in LLM Output Prior to Agent Execution",
    description:
      "Detects LLM-generated shell or SQL statements containing destructive operations (rm -rf, DROP TABLE, DELETE without WHERE, kubectl delete namespace) before an autonomous agent executes them -- a last-line guardrail for agentic tool-calling pipelines.",
    platform: ["AI/ML", "Cloud"],
    mitre: ["T1485", "T1490"],
    category: "AI Security",
    maturity: "experimental",
    severity: "critical",
    tags: ["llm", "agentic-ai", "destructive-command", "guardrail", "owasp-llm05"],
    author: "Detection Engineering Team",
    updated: "2026-10-29",
    sigma: `title: Destructive Command in LLM Output Prior to Agent Execution
id: det-llmout-004
status: experimental
description: Detects LLM-generated tool-call arguments or code blocks containing destructive shell/SQL operations before execution by an agent.
references:
  - OWASP Top 10 for LLM Applications 2026, LLM05 Improper Output Handling
author: Detection Engineering Team
date: 2026/10/29
tags:
  - attack.impact
  - attack.t1485
  - attack.t1490
logsource:
  category: application
  product: agentic_runtime
detection:
  selection:
    event_type: tool_call_pending
    tool_call_args|re:
      - 'rm\\s+-rf\\s+/'
      - 'DROP\\s+TABLE'
      - 'DELETE\\s+FROM\\s+\\w+\\s*;'
      - 'kubectl\\s+delete\\s+namespace'
      - ':(){ :|:& };:'
  condition: selection
falsepositives:
  - Legitimate maintenance/cleanup agents explicitly authorized to run destructive operations within a scoped, approved workflow
level: critical`,
    splunk: `index=agentic_runtime event_type=tool_call_pending
| regex tool_call_args="rm\\s+-rf\\s+/|DROP\\s+TABLE|DELETE\\s+FROM\\s+\\w+\\s*;|kubectl\\s+delete\\s+namespace"
| table _time, agent_id, user, tool_name, tool_call_args, approval_status
| sort -_time`,
    pyspark: `from pyspark.sql import SparkSession
from pyspark.sql.functions import col

spark = SparkSession.builder.appName("LLMDestructiveCommandGuardrail").getOrCreate()

df = spark.read.json("s3://security-lake/agentic-runtime/tool-calls/")

destructive_patterns = [
    r"rm\\s+-rf\\s+/", r"DROP\\s+TABLE", r"DELETE\\s+FROM\\s+\\w+\\s*;",
    r"kubectl\\s+delete\\s+namespace", r":\\(\\)\\s*\\{\\s*:\\|:&\\s*\\};:",
]
pattern = "|".join(destructive_patterns)

detections = df.filter(
    (col("event_type") == "tool_call_pending") & (col("tool_call_args").rlike(pattern))
).select("timestamp", "agent_id", "user", "tool_name", "tool_call_args", "approval_status")

detections.write.mode("append").parquet("s3://detections/output/")`,
    sampleLogs: [
      `{"event_type":"tool_call_pending","timestamp":"2026-10-29T13:33:18Z","agent_id":"devops-autofix-agent","user":"system","tool_name":"shell_exec","tool_call_args":"rm -rf / --no-preserve-root  # cleaning up temp build artifacts","approval_status":"auto"}`,
    ],
    requiredFields: [
      "event_type",
      "tool_call_args",
      "tool_name",
      "agent_id",
      "approval_status",
      "timestamp",
    ],
    falsePositives: [
      "Explicitly authorized destructive maintenance agents (e.g. a scoped database-cleanup agent) -- allowlist by agent_id and require human approval regardless",
      "Pattern matches inside a code comment or documentation string rather than an actually-executed command",
    ],
    tuningGuidance:
      "This should gate execution (require human approval) rather than only log, for any agent whose tool-calling scope includes shell, SQL, or infrastructure-API access. Reserve auto-approval exclusively for agents with no destructive-capable tools in their toolset.",
    deploymentNotes:
      "Must be implemented in the agent orchestration layer (LangChain/LangGraph middleware, custom agent runtime, or an MCP server's tool-call interceptor) where tool-call arguments are visible before execution -- after-the-fact log analysis is too late to prevent impact for this specific risk.",
    evasionConsiderations:
      "Attackers who can influence agent prompts (via prompt injection from an untrusted document/webpage the agent reads) may obfuscate destructive commands across multiple benign-looking tool calls, or use base64/variable-substitution tricks the regex won't catch -- pair with command-decomposition analysis for agents that process untrusted external content.",
    problemStatement:
      "Agentic AI systems that can execute real shell, database, or infrastructure commands turn a hallucinated or injected instruction into real-world impact the moment it's executed; OWASP's 2026 guidance on Improper Output Handling specifically calls out the gap between 'the model said this' and 'this should actually run' as the control most agentic deployments skip.",
  },
  {
    id: "det-llmout-005",
    title: "Encoded Payload in LLM Response (Covert Exfiltration Channel)",
    description:
      "Detects LLM responses containing long base64, hex, or similarly encoded blocks returned to a caller without an obvious legitimate reason -- a potential covert exfiltration channel if an attacker has influenced the model (via prompt injection or a compromised RAG source) to smuggle retrieved data out through an otherwise innocuous-looking response.",
    platform: ["AI/ML", "Cloud"],
    mitre: ["T1132", "T1041"],
    category: "Exfiltration",
    maturity: "experimental",
    severity: "medium",
    tags: ["llm", "exfiltration", "encoding", "output-monitoring"],
    author: "Detection Engineering Team",
    updated: "2026-10-29",
    sigma: `title: Encoded Payload in LLM Response
id: det-llmout-005
status: experimental
description: Detects long base64/hex-encoded blocks in LLM response content outside of expected code-generation contexts.
references:
  - https://attack.mitre.org/techniques/T1132/
author: Detection Engineering Team
date: 2026/10/29
tags:
  - attack.exfiltration
  - attack.command_and_control
  - attack.t1132
  - attack.t1041
logsource:
  category: application
  product: llm_gateway
detection:
  selection:
    event_type: llm_response
    response_body|re: '[A-Za-z0-9+/]{200,}={0,2}'
  filter_code_context:
    request_intent: code_generation
  condition: selection and not filter_code_context
falsepositives:
  - Legitimate code-generation responses that include base64 fixtures, embedded images, or JWT examples
  - Responses quoting a long encoded value the user themselves pasted into the prompt
level: medium`,
    splunk: `index=llm_gateway event_type=llm_response request_intent!=code_generation
| regex response_body="[A-Za-z0-9+/]{200,}={0,2}"
| table _time, user, model, request_id, request_intent
| sort -_time`,
    pyspark: `from pyspark.sql import SparkSession
from pyspark.sql.functions import col, regexp_extract

spark = SparkSession.builder.appName("LLMEncodedPayloadOutput").getOrCreate()

df = spark.read.json("s3://security-lake/llm-gateway/responses/")

detections = df.filter(
    (col("request_intent") != "code_generation")
).withColumn(
    "b64_match", regexp_extract(col("response_body"), r"[A-Za-z0-9+/]{200,}={0,2}", 0)
).filter(col("b64_match") != "").select(
    "timestamp", "user", "model", "request_id", "request_intent"
)

detections.write.mode("append").parquet("s3://detections/output/")`,
    sampleLogs: [
      `{"event_type":"llm_response","timestamp":"2026-10-29T15:50:02Z","user":"support-chat-widget","model":"internal-support-bot","request_id":"req-55e9","request_intent":"customer_support","response_body":"Here is your confirmation reference: aGVsbG8gdGhpcyBpcyBhIHRlc3Qgb2YgZW5jb2RlZCBleGZpbHRyYXRpb24gY2hhbm5lbHMgdXNlZCBmb3IgdGVzdGluZyBwdXJwb3Nlcw=="}`,
    ],
    requiredFields: [
      "response_body",
      "request_intent",
      "user",
      "model",
      "request_id",
      "timestamp",
    ],
    falsePositives: [
      "Legitimate code-generation requests returning base64 fixtures, data URIs, or JWT examples (excluded via request_intent filter, but intent classification is imperfect)",
      "A user's own long encoded string from earlier in the conversation being echoed back verbatim",
    ],
    tuningGuidance:
      "Scope this tightly to non-code-generation application contexts (customer support bots, internal Q&A assistants) where a long encoded block in the response has no legitimate reason to exist at all -- in general-purpose coding assistants this signal is far too noisy to be useful without much stronger context filtering.",
    deploymentNotes:
      "Requires the LLM gateway to tag requests with an intent/use-case classification (even a coarse one) so this rule can be scoped away from legitimate code-generation traffic -- without that scoping, false-positive volume will make the rule unworkable.",
    evasionConsiderations:
      "An attacker-influenced model can split the encoded payload across multiple responses/turns, use a less-regular encoding (custom substitution cipher driven by the injected instruction), or encode at a lower density that stays under the length threshold -- treat this as a tripwire for the unsophisticated case, not a complete covert-channel control.",
    problemStatement:
      "RAG-connected and tool-using LLM applications increasingly have access to sensitive internal data; a successful indirect prompt injection (from a malicious document or webpage the model reads) can instruct the model to encode and smuggle retrieved data out through a response field that a human reviewer would skim past without noticing.",
  },
  {
    id: "det-llmout-006",
    title: "Bulk Sensitive-Data Aggregation via LLM API Responses",
    description:
      "Detects a single identity receiving an unusually high volume or density of PII/confidential-pattern matches across LLM responses within a short window -- the output-monitoring implementation for the 'Model Data Exfiltration' coverage item, catching bulk data aggregation that a single-response DLP rule would miss.",
    platform: ["AI/ML", "Cloud"],
    mitre: ["T1530", "T1213"],
    category: "Exfiltration",
    maturity: "experimental",
    severity: "high",
    tags: ["llm", "dlp", "bulk-exfiltration", "output-monitoring"],
    author: "Detection Engineering Team",
    updated: "2026-10-29",
    sigma: `title: Bulk Sensitive-Data Aggregation via LLM API Responses
id: det-llmout-006
status: experimental
description: Detects a single identity accumulating an unusually high count of DLP-flagged LLM responses within a short window, indicating bulk aggregation rather than isolated disclosure.
references:
  - OWASP Top 10 for LLM Applications 2026, LLM02 Sensitive Information Disclosure
author: Detection Engineering Team
date: 2026/10/29
tags:
  - attack.exfiltration
  - attack.t1530
  - attack.t1213
logsource:
  category: application
  product: llm_gateway
detection:
  selection:
    event_type: llm_response
    dlp_flagged: true
  condition: selection | count_by_user_per_15m > 10
falsepositives:
  - Authorized bulk-reporting or data-migration service accounts with a legitimate, high-volume PII workload
level: high`,
    splunk: `index=llm_gateway event_type=llm_response dlp_flagged=true
| bin _time span=15m
| stats count by user, _time
| where count > 10
| sort -count`,
    pyspark: `from pyspark.sql import SparkSession
from pyspark.sql.functions import col, window, count

spark = SparkSession.builder.appName("LLMBulkDataAggregation").getOrCreate()

df = spark.read.json("s3://security-lake/llm-gateway/responses/")

flagged = df.filter(col("dlp_flagged") == True)

detections = flagged.groupBy(
    "user", window(col("timestamp"), "15 minutes")
).agg(count("*").alias("flagged_response_count")).filter(col("flagged_response_count") > 10)

detections.write.mode("append").parquet("s3://detections/output/")`,
    sampleLogs: [
      `{"event_type":"llm_response","timestamp":"2026-10-29T17:12:00Z","user":"analytics-readonly-bot","model":"gpt-4.1","request_id":"req-301a","dlp_flagged":true,"flagged_pattern":"email"}`,
      `{"event_type":"llm_response","timestamp":"2026-10-29T17:13:40Z","user":"analytics-readonly-bot","model":"gpt-4.1","request_id":"req-301b","dlp_flagged":true,"flagged_pattern":"phone"}`,
    ],
    requiredFields: [
      "event_type",
      "dlp_flagged",
      "user",
      "timestamp",
      "request_id",
    ],
    falsePositives: [
      "Approved bulk-reporting/analytics service accounts with a legitimate high-volume PII workload -- baseline their normal rate and alert only on deviation from it, not on a fixed global threshold",
    ],
    tuningGuidance:
      "This detection is most effective layered directly on top of det-llmout-001 (single-response PII pattern matching) as a frequency/volume escalation rather than a standalone pattern -- use dlp_flagged as the shared signal between the two. Baseline per-identity normal rates rather than using one global threshold across a mixed population of human users and service accounts.",
    deploymentNotes:
      "Requires det-llmout-001 (or an equivalent output-side DLP scanner) to already be populating the dlp_flagged field; this rule is a stateful aggregation on top of that signal, not an independent content scanner. This is the concrete implementation of the 'Model Data Exfiltration' coverage item that was previously tracked as planned with no detection in place.",
    evasionConsiderations:
      "An attacker aware of rate-based thresholds can throttle requests to stay under the window count, or distribute the aggregation across multiple compromised identities/API keys -- cross-identity correlation (same source IP or session fingerprint issuing from multiple nominal 'users') meaningfully improves coverage against the distributed variant.",
    problemStatement:
      "A single PII-containing response is often an isolated model slip; the same pattern repeated across dozens of responses from one identity in a short window is categorically different -- it looks like someone systematically querying an LLM-backed system to reconstruct a dataset it was never meant to expose in bulk, which is exactly the scenario the coverage map's original 'planned' Model Data Exfiltration entry was meant to close.",
  },
];
