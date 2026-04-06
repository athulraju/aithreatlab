export interface ResearchArticle {
  id: string;
  title: string;
  summary: string;
  category: string;
  tags: string[];
  readTime: number;
  date: string;
  featured: boolean;
  content: string;
}

export const articles: ResearchArticle[] = [
  {
    id: "art-001",
    title: "Sigma Rule Portability: Challenges and Solutions Across SIEM Platforms",
    summary:
      "A deep dive into the practical challenges of translating Sigma rules across Splunk, Elastic, and Microsoft Sentinel, with a framework for measuring translation fidelity.",
    category: "Sigma Portability",
    tags: ["sigma", "splunk", "elastic", "sentinel", "detection-engineering"],
    readTime: 12,
    date: "2024-12-01",
    featured: true,
    content: `## Overview

Sigma rules promise SIEM-agnostic detection logic, but the reality of cross-platform translation reveals significant gaps. This research documents translation failures across three major platforms and proposes a portability scoring framework.

## Key Findings

After analyzing 847 Sigma rules against Splunk, Elastic, and Microsoft Sentinel backends:

- **34%** of rules required manual adjustment after automated translation
- **12%** produced functionally equivalent but syntactically different queries
- **8%** failed silently — generating queries that returned no results due to field name mismatches

## Translation Failure Categories

### 1. Field Mapping Gaps
Different SIEM platforms use different field names for the same data. Sigma's field mapping layer partially addresses this, but custom log sources and vendor-specific normalization create persistent gaps.

### 2. Function Equivalence Problems
Sigma's condition syntax maps to platform-specific functions. Operations like \`contains|all\` behave differently under negation across platforms.

### 3. Aggregation Semantics
Detection rules using \`count() by\` aggregations exhibit subtle behavioral differences, especially around null handling and time window boundaries.

## Portability Scoring Framework

We propose scoring rules across five dimensions:
- **Field Coverage**: Are all referenced fields in the target schema?
- **Function Parity**: Do all condition modifiers have equivalents?
- **Aggregation Support**: Do grouped aggregations translate faithfully?
- **Performance**: Does the translated query perform acceptably at scale?
- **Test Coverage**: Are there sample logs to validate behavior?

## Recommendations

1. Maintain SIEM-specific test harnesses
2. Run translation regression tests in CI/CD pipelines
3. Document platform-specific exceptions in rule metadata
4. Build field mapping validation into your detection lifecycle`,
  },
  {
    id: "art-002",
    title: "PySpark for Detection Engineering: Scaling Behavioral Analytics",
    summary:
      "How to implement UEBA-grade behavioral detections using PySpark, handling class imbalance, and deploying models alongside rule-based detections in a unified pipeline.",
    category: "PySpark Detections",
    tags: ["pyspark", "ueba", "ml", "behavioral-analytics", "detection-engineering"],
    readTime: 18,
    date: "2024-11-15",
    featured: true,
    content: `## Why PySpark for Detections?

Traditional SIEM-based detections hit performance walls at scale. PySpark enables detection logic over petabyte-scale security lakes with the full expressiveness of distributed computing.

## Architecture Pattern

A production detection pipeline in PySpark follows this pattern:

1. **Ingest** — Stream from Kafka or batch from S3/ADLS
2. **Normalize** — Apply field mapping to common schema
3. **Enrich** — Join with asset inventory, threat intel
4. **Detect** — Apply rule-based and ML-based detections
5. **Alert** — Write findings to alerting pipeline

## Handling Class Imbalance

Security data is inherently imbalanced. Malicious events represent 0.001% or less of total volume. Standard ML metrics fail here.

### Techniques That Work:
- **SMOTE with caution**: Oversample positives but validate with real attack data
- **Cost-sensitive learning**: Assign high misclassification cost to false negatives
- **Isolation Forest**: Unsupervised anomaly detection avoids the labeling problem
- **Precision-Recall curves**: Never evaluate security models on accuracy alone

## Behavioral Baseline Example

\`\`\`python
from pyspark.sql.window import Window
import pyspark.sql.functions as F

# Build 30-day user baseline
window = Window.partitionBy("user_id").orderBy("date").rowsBetween(-30, 0)

df_enriched = df.withColumn(
    "baseline_bytes_out",
    F.avg("bytes_out").over(window)
).withColumn(
    "deviation_score",
    (F.col("bytes_out") - F.col("baseline_bytes_out")) /
    F.stddev("bytes_out").over(window)
)

# Flag statistical outliers
detections = df_enriched.filter(F.col("deviation_score") > 3.0)
\`\`\`

## Production Considerations

- Cache frequently joined DataFrames (asset inventory, user lists)
- Partition by date and entity ID for performance
- Write detection output to Delta Lake for ACID guarantees
- Monitor detection job latency as part of your SLO`,
  },
  {
    id: "art-003",
    title: "Detecting AI Agent Misuse: A New Detection Engineering Frontier",
    summary:
      "As autonomous AI agents gain access to tools and enterprise systems, the attack surface expands dramatically. This piece outlines a detection framework for agent-specific threats.",
    category: "Agent Detection",
    tags: ["ai-agents", "llm", "detection", "ai-security", "tool-misuse"],
    readTime: 14,
    date: "2024-12-10",
    featured: true,
    content: `## The Agent Threat Model

Modern AI agents operate with access to:
- File systems and databases
- External APIs and web browsing
- Code execution environments
- Email and calendar systems
- Enterprise SaaS platforms

This creates a novel threat landscape where the attack surface is defined not by network topology but by tool permissions.

## Detection Categories

### 1. Goal Drift Detection
Agents with autonomy may pursue sub-goals that conflict with original intent. Detect via:
- Tool call sequence analysis (unexpected ordering)
- Resource access outside declared scope
- Iterative privilege escalation patterns

### 2. Prompt Injection via Tool Outputs
Retrieved documents, API responses, and web content may contain injected instructions. Monitor:
- Tool output ingestion patterns
- Sudden behavior changes after external data retrieval
- Unexpected action sequences following retrieval steps

### 3. Data Exfiltration via Agent APIs
Agents may be manipulated into exfiltrating data through:
- Summarization requests sent to external endpoints
- Email drafting with attached context
- File upload actions to unauthorized destinations

## Key Log Sources

| Source | What to Monitor |
|--------|----------------|
| LLM API | Token usage spikes, unusual prompt patterns |
| Tool execution logs | Sequence anomalies, out-of-scope calls |
| File system | Access to sensitive paths by agent process |
| Network | Unexpected egress from agent runtime |
| Identity | Service account activity from agent contexts |

## Detection Rule Concept

Flag agents that access high-sensitivity resources followed by external egress within a short time window — a behavioral pattern consistent with exfiltration chains.`,
  },
  {
    id: "art-004",
    title: "Insider Threat Detection: Behavioral Baselines and Statistical Triggers",
    summary:
      "Building effective insider threat detections requires understanding normal behavior before defining abnormal. This framework covers baseline construction, drift detection, and alert quality.",
    category: "Insider Threat",
    tags: ["insider-threat", "ueba", "behavioral-analytics", "detection-engineering"],
    readTime: 16,
    date: "2024-10-20",
    featured: false,
    content: `## The Baseline Problem

Insider threat detection fails when it tries to detect absolute behaviors rather than behavioral deviations. The employee who downloads 10GB on their last day may always download large amounts.

## Baseline Construction

Effective baselines are:
- **Peer-relative**: Compare against job-function cohorts, not global averages
- **Temporal**: Account for day-of-week and seasonal patterns
- **Multi-dimensional**: Single-metric baselines generate too many FPs

## Statistical Approaches

### Z-Score Anomalies
Simple but effective for normally distributed metrics like login frequency. Beware of long-tail distributions common in security data.

### Mahalanobis Distance
Accounts for correlations between features — useful for multi-dimensional user profiles.

### Isolation Forest
Strong unsupervised option for detecting unusual combinations of behaviors without labeled training data.

## Alert Quality Framework

Before deploying insider threat rules:
1. **Specificity**: What specific behavior pattern does this detect?
2. **Baseline dependency**: Is there a robust enough baseline to determine anomaly?
3. **Context enrichment**: What HR/identity context can reduce FP rate?
4. **Escalation path**: Who investigates and what do they need?

## Common Failure Modes

- Alerting on role changes without updating baselines
- Ignoring legitimate use cases (contractors, travelers)
- Not accounting for authorized after-hours work
- Conflating security events with productivity monitoring`,
  },
  {
    id: "art-005",
    title: "Class Imbalance in Security ML: Why Your AUC Score Is Lying To You",
    summary:
      "Standard ML evaluation metrics fail catastrophically in security contexts. This analysis covers what metrics actually matter, and how to validate security ML models honestly.",
    category: "Class Imbalance",
    tags: ["ml", "class-imbalance", "evaluation", "security-ml", "detection-engineering"],
    readTime: 10,
    date: "2024-09-15",
    featured: false,
    content: `## The Problem With AUC in Security

A model trained on security data with 1:100,000 imbalance can achieve 99.999% accuracy by predicting "benign" for everything. AUC looks reasonable because the ROC curve is computed at varying thresholds that will rarely matter operationally.

## Metrics That Matter

### Precision@K
At your actual operational alert threshold, what fraction of alerts are real? In most SOC contexts, precision below 20% is unsustainable.

### False Positive Rate Per Day
Convert your metrics to operational impact. 0.1% FPR sounds good until you realize it means 1,000 false alerts per day on a busy network.

### Detection Latency
How quickly does the model fire after attack onset? A perfect-precision model that fires 6 hours later may miss containment windows.

## Evaluation Framework

1. Establish your operational precision floor (e.g., must be >30%)
2. Define maximum acceptable FP volume per day
3. Set minimum recall for priority attack categories
4. Validate on time-held-out data, not random splits
5. Simulate adversarial evasion in your test set

## Practical Fixes

- **Threshold optimization**: Move beyond default 0.5 thresholds
- **Cost matrix**: Weight FN cost 100x higher than FP cost in training
- **Calibration**: Ensure predicted probabilities reflect true rates
- **Continuous validation**: Drift detection on model performance metrics`,
  },
  {
    id: "art-006",
    title: "Cloud Detection Engineering: Bridging CloudTrail, GuardDuty, and Custom Rules",
    summary:
      "Native cloud security services provide a foundation, but effective cloud detection requires custom logic layered on top. This guide covers the full cloud detection stack.",
    category: "Detection Engineering",
    tags: ["aws", "cloudtrail", "guardduty", "cloud", "detection-engineering"],
    readTime: 13,
    date: "2024-11-01",
    featured: false,
    content: `## Cloud Detection Layers

Effective AWS security detection operates at four layers:

1. **Native services** — GuardDuty, Security Hub, Config Rules
2. **CloudTrail analytics** — Custom rules on management/data events
3. **Service-specific logs** — VPC Flow Logs, ALB access logs, S3 access logs
4. **Cross-service correlation** — Combining signals across services

## What GuardDuty Misses

GuardDuty is excellent but incomplete. It lacks:
- Custom business logic (e.g., detection based on your specific role naming)
- Cross-account correlation visibility
- Application-layer context
- Detection of slow, low-volume activity

## High-Value Custom Rules

### IAM Privilege Escalation Chains
Monitor sequences of IAM events that collectively achieve privilege escalation even if no single event is suspicious.

### Resource Creation Anomalies
Unusual resource types, regions, or configurations that fall outside your organization's baseline.

### Data Plane Exfiltration Indicators
S3 GetObject calls on sensitive buckets from unusual principals or geographic locations.

### Terraform/IaC Drift
CloudFormation/CDK stacks modified outside of CI/CD — a strong indicator of unauthorized change.

## Architecture Recommendation

Route all CloudTrail logs to S3 > Glue Catalog > Athena for ad-hoc investigation. Stream to Kinesis > Lambda/SIEM for real-time detection. Maintain separate detection pipelines for different latency SLOs.`,
  },
];

export const articleCategories = [
  "All",
  "Detection Engineering",
  "AI Security",
  "Insider Threat",
  "Sigma Portability",
  "PySpark Detections",
  "Class Imbalance",
  "Agent Detection",
];

export const getArticleById = (id: string) => articles.find((a) => a.id === id);
