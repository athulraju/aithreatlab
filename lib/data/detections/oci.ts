import type { Detection } from "./types";

export const ociDetections: Detection[] = [
  // OCI Detections
  {
    id: "det-oci-001",
    title: "OCI Object Storage Mass Download, Data Exfiltration",
    description:
      "Detects bulk GetObject requests against OCI Object Storage buckets, indicating potential data exfiltration via the OCI API or console.",
    platform: ["OCI", "Cloud"],
    mitre: ["T1530"],
    category: "Exfiltration",
    maturity: "stable",
    severity: "high",
    tags: ["oci", "object-storage", "exfiltration", "cloud", "audit-log"],
    author: "Detection Engineering Team",
    updated: "2024-12-10",
    sigma: `title: OCI Object Storage Mass Download
id: det-oci-001
status: stable
description: Detects high-volume GetObject requests against OCI Object Storage
author: Detection Engineering Team
date: 2024/12/10
tags:
  - attack.exfiltration
  - attack.t1530
logsource:
  product: oracle_cloud
  service: audit
detection:
  selection:
    eventName: 'GetObject'
    requestAction: 'GET'
    responseStatus: '200'
  aggregate:
    count() > 500
    groupby:
      - principalId
      - compartmentId
    timeframe: 10m
  condition: selection | count > 500
falsepositives:
  - Authorized bulk backup or migration jobs
  - Data engineering pipelines reading large datasets
level: high`,
    splunk: `index=oci sourcetype=oci:audit
  eventName="GetObject"
  requestAction="GET"
  responseStatus="200"
| bin _time span=10m
| stats count as download_count, dc(resourceId) as unique_objects,
    values(sourceIPAddress) as src_ips
    by principalId, compartmentId, _time
| where download_count > 500
| eval risk = if(download_count > 2000, "critical", "high")
| table _time, principalId, compartmentId, download_count, unique_objects, src_ips, risk
| sort -download_count`,
    pyspark: `from pyspark.sql.functions import col, count, countDistinct, collect_set, window, when, lit

df_filtered = df.filter(
    (col("eventName") == "GetObject") &
    (col("requestAction") == "GET") &
    (col("responseStatus") == "200")
)

detections = df_filtered.groupBy(
    window(col("timestamp"), "10 minutes"),
    col("principalId"),
    col("compartmentId")
).agg(
    count("*").alias("download_count"),
    countDistinct("resourceId").alias("unique_objects"),
    collect_set("sourceIPAddress").alias("src_ips")
).filter(
    col("download_count") > 500
).withColumn(
    "risk", when(col("download_count") > 2000, "critical").otherwise("high")
).withColumn("detection_id", lit("det-oci-001"))`,
    sampleLogs: [
      `{"eventTime":"2024-12-10T02:15:00Z","eventName":"GetObject","requestAction":"GET","principalId":"ocid1.user.oc1..aaaaaaaa7xyz","principalName":"data-analyst@corp.com","compartmentId":"ocid1.compartment.oc1..aaaa1234","resourceId":"sensitive-bucket/hr/salaries_2024.csv","sourceIPAddress":"203.0.113.42","responseStatus":"200","bytesSent":524288}`,
      `{"eventTime":"2024-12-10T02:15:04Z","eventName":"GetObject","requestAction":"GET","principalId":"ocid1.user.oc1..aaaaaaaa7xyz","principalName":"data-analyst@corp.com","compartmentId":"ocid1.compartment.oc1..aaaa1234","resourceId":"sensitive-bucket/finance/q4_report.xlsx","sourceIPAddress":"203.0.113.42","responseStatus":"200","bytesSent":1048576}`,
      `{"eventTime":"2024-12-10T02:15:08Z","eventName":"GetObject","requestAction":"GET","principalId":"ocid1.user.oc1..aaaaaaaa7xyz","principalName":"data-analyst@corp.com","compartmentId":"ocid1.compartment.oc1..aaaa1234","resourceId":"sensitive-bucket/pii/customer_export_full.json","sourceIPAddress":"203.0.113.42","responseStatus":"200","bytesSent":10485760}`,
    ],
    requiredFields: [
      "eventName",
      "requestAction",
      "principalId",
      "principalName",
      "compartmentId",
      "resourceId",
      "sourceIPAddress",
      "responseStatus",
      "bytesSent",
      "eventTime",
    ],
    falsePositives: [
      "Authorized bulk backup jobs using service principals",
      "Data engineering pipelines performing large dataset reads",
      "Disaster recovery jobs during maintenance windows",
    ],
    tuningGuidance:
      "Whitelist known automation service accounts (OCIDs) and restrict the rule to human user principals. Add a bytesSent threshold to focus on large-volume transfers. Correlate with off-hours access for higher fidelity.",
    deploymentNotes:
      "Requires OCI Audit log ingestion. Enable audit logging for Object Storage service in OCI Console under Logging. Route logs via OCI Logging Service to SIEM or security lake.",
    evasionConsiderations:
      "Attackers may spread downloads across multiple sessions, use presigned URLs (which bypass IAM audit), or leverage a compromised service account with expected download patterns.",
    problemStatement:
      "OCI Object Storage is a common target for data exfiltration. Adversaries with compromised credentials can quietly download large datasets via the API with no alerting unless download volume is monitored.",
  },
  {
    id: "det-oci-002",
    title: "OCI IAM Policy Change by Non-Admin Principal",
    description:
      "Detects creation, modification, or deletion of OCI IAM policies by principals that are not designated IAM administrators.",
    platform: ["OCI", "Cloud"],
    mitre: ["T1098", "T1078.004"],
    category: "Privilege Escalation",
    maturity: "production",
    severity: "critical",
    tags: ["oci", "iam", "privilege-escalation", "policy-change", "cloud"],
    author: "Detection Engineering Team",
    updated: "2024-12-10",
    sigma: `title: OCI IAM Policy Modification
id: det-oci-002
status: stable
description: Detects IAM policy create/update/delete events in OCI Audit logs
author: Detection Engineering Team
date: 2024/12/10
tags:
  - attack.privilege_escalation
  - attack.t1098
logsource:
  product: oracle_cloud
  service: audit
detection:
  selection:
    eventName|contains:
      - 'CreatePolicy'
      - 'UpdatePolicy'
      - 'DeletePolicy'
    requestAction|contains:
      - 'POST'
      - 'PUT'
      - 'DELETE'
  filter_admin:
    principalName|contains:
      - 'iam-admin'
      - 'terraform-svc'
  condition: selection and not filter_admin
level: critical`,
    splunk: `index=oci sourcetype=oci:audit
  eventName IN ("CreatePolicy", "UpdatePolicy", "DeletePolicy")
| eval is_known_admin = if(
    match(principalName, "iam-admin|terraform-svc|oci-automation"),
    "true", "false"
  )
| where is_known_admin="false"
| spath requestParameters.statements{} output=policy_statements
| table _time, principalId, principalName, eventName,
    compartmentId, policy_statements, sourceIPAddress
| sort -_time`,
    pyspark: `detections = df.filter(
    col("eventName").isin(["CreatePolicy", "UpdatePolicy", "DeletePolicy"])
).filter(
    ~col("principalName").rlike("iam-admin|terraform-svc|oci-automation")
).select(
    "eventTime", "principalId", "principalName",
    "eventName", "compartmentId",
    "requestParameters", "sourceIPAddress"
).withColumn("detection_id", lit("det-oci-002")) \\
 .withColumn("severity", lit("critical"))`,
    sampleLogs: [
      `{"eventTime":"2024-12-10T11:45:22Z","eventName":"CreatePolicy","requestAction":"POST","principalId":"ocid1.user.oc1..aaaaadev9999","principalName":"dev-user@corp.com","compartmentId":"ocid1.compartment.oc1..root","requestParameters":{"name":"escalation-policy","statements":["Allow group Administrators to manage all-resources in tenancy"]},"sourceIPAddress":"10.0.5.88","responseStatus":"200"}`,
      `{"eventTime":"2024-12-10T11:47:05Z","eventName":"UpdatePolicy","requestAction":"PUT","principalId":"ocid1.user.oc1..aaaaadev9999","principalName":"dev-user@corp.com","compartmentId":"ocid1.compartment.oc1..aaaa5678","requestParameters":{"statements":["Allow any-user to manage buckets in tenancy"]},"sourceIPAddress":"10.0.5.88","responseStatus":"200"}`,
    ],
    requiredFields: [
      "eventName",
      "requestAction",
      "principalId",
      "principalName",
      "compartmentId",
      "requestParameters.statements",
      "sourceIPAddress",
      "responseStatus",
    ],
    falsePositives: [
      "Authorized IAM admins performing planned policy updates",
      "Terraform or Ansible automation using service principals",
      "OCI IAM administrator role assignments",
    ],
    tuningGuidance:
      "Maintain an allowlist of authorized IAM admin OCIDs and service account names. Alert specifically on human user principals. Cross-reference with change management records for scheduled updates.",
    deploymentNotes:
      "Requires OCI Audit log ingestion with Identity service events enabled. Ensure the tenancy-level audit log is captured, not just compartment-level.",
    evasionConsiderations:
      "Attackers may use dynamic group memberships to gain policy creation rights without directly modifying policies, or modify policies via Terraform from a compromised pipeline.",
    problemStatement:
      "OCI IAM policy changes represent a critical privilege escalation path. An attacker with write access to IAM can grant themselves or others administrator-level permissions across an entire tenancy.",
  },
  {
    id: "det-oci-003",
    title: "OCI API Key Created for Existing User, Credential Persistence",
    description:
      "Detects creation of new API keys for existing IAM users, a common persistence mechanism after initial compromise.",
    platform: ["OCI", "Cloud"],
    mitre: ["T1098.001", "T1556"],
    category: "Persistence",
    maturity: "stable",
    severity: "high",
    tags: ["oci", "api-key", "persistence", "credential-access", "cloud"],
    author: "Detection Engineering Team",
    updated: "2024-12-10",
    sigma: `title: OCI API Key Created for User
id: det-oci-003
status: stable
description: Detects new API key creation which may indicate credential persistence
author: Detection Engineering Team
date: 2024/12/10
tags:
  - attack.persistence
  - attack.t1098.001
logsource:
  product: oracle_cloud
  service: audit
detection:
  selection:
    eventName: 'CreateApiKey'
    requestAction: 'POST'
    responseStatus: '200'
  condition: selection
level: high`,
    splunk: `index=oci sourcetype=oci:audit
  eventName="CreateApiKey"
  responseStatus="200"
| eval self_created = if(principalId == requestParameters.userId, "self", "other")
| table _time, principalId, principalName, requestParameters.userId,
    requestParameters.fingerprint, self_created, sourceIPAddress, compartmentId
| sort -_time`,
    pyspark: `detections = df.filter(
    (col("eventName") == "CreateApiKey") &
    (col("responseStatus") == "200")
).withColumn(
    "self_created",
    when(
        col("principalId") == col("requestParameters.userId"), "self"
    ).otherwise("other_user")
).select(
    "eventTime", "principalId", "principalName",
    "requestParameters.userId", "requestParameters.fingerprint",
    "self_created", "sourceIPAddress"
)`,
    sampleLogs: [
      `{"eventTime":"2024-12-10T14:22:10Z","eventName":"CreateApiKey","requestAction":"POST","principalId":"ocid1.user.oc1..aaaattacker111","principalName":"attacker@external.com","requestParameters":{"userId":"ocid1.user.oc1..aaaavictim999","fingerprint":"aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:77:88:99:00"},"compartmentId":"ocid1.tenancy.oc1..roottenancy","sourceIPAddress":"185.220.101.55","responseStatus":"200"}`,
    ],
    requiredFields: [
      "eventName",
      "principalId",
      "principalName",
      "requestParameters.userId",
      "requestParameters.fingerprint",
      "sourceIPAddress",
      "responseStatus",
    ],
    falsePositives: [
      "Authorized administrators provisioning API keys for service accounts",
      "Onboarding automation creating keys for new users",
      "Developers creating their own API keys for local development",
    ],
    tuningGuidance:
      "Focus on cases where principalId differs from requestParameters.userId (one user creating a key for another). Alert on external source IPs. Correlate with recent login anomalies for the same principal.",
    deploymentNotes:
      "Requires OCI Audit log ingestion. The CreateApiKey event is always logged at the tenancy level. Ensure identity-related audit events are not filtered before ingestion.",
    evasionConsiderations:
      "Attackers may use existing compromised API keys to create new ones, avoiding interactive console login. They may also create Auth Tokens or SMTP credentials as alternative persistence mechanisms.",
    problemStatement:
      "After gaining initial access to an OCI account, attackers create new API keys to maintain persistence even if the compromised session or password is rotated.",
  },
  {
    id: "det-oci-004",
    title: "OCI Console Login from New Country or Tor Exit Node",
    description:
      "Detects OCI console sign-in events originating from a country not previously seen for the user, or from known Tor exit node IP ranges.",
    platform: ["OCI", "Cloud"],
    mitre: ["T1078.004"],
    category: "Initial Access",
    maturity: "production",
    severity: "high",
    tags: ["oci", "login-anomaly", "geo", "tor", "cloud", "initial-access"],
    author: "Detection Engineering Team",
    updated: "2024-12-10",
    sigma: `title: OCI Console Login Anomaly, New Country or Tor
id: det-oci-004
status: stable
description: Detects console logins from anomalous geographic locations or Tor
author: Detection Engineering Team
date: 2024/12/10
tags:
  - attack.initial_access
  - attack.t1078.004
logsource:
  product: oracle_cloud
  service: audit
detection:
  selection_tor:
    eventName: 'InteractiveLogin'
    sourceIPAddress|cidr:
      - '185.220.100.0/22'
      - '185.107.80.0/22'
      - '199.87.154.0/24'
  selection_failed:
    eventName: 'InteractiveLogin'
    responseStatus: '401'
  condition: selection_tor or selection_failed
level: high`,
    splunk: `index=oci sourcetype=oci:audit
  eventName="InteractiveLogin"
| iplocation sourceIPAddress
| eval is_tor = if(match(sourceIPAddress, "^185\\.220\\.|^199\\.87\\.154\\."), "true", "false")
| eval login_status = if(responseStatus="200", "success", "failed")
| stats
    values(Country) as countries,
    count(eval(login_status="failed")) as failed_logins,
    count(eval(login_status="success")) as success_logins,
    values(is_tor) as tor_detected
    by principalName, principalId
| where failed_logins > 5 OR tor_detected="true"
| table principalName, countries, failed_logins, success_logins, tor_detected`,
    pyspark: `from pyspark.sql.functions import col, count, when, lit, collect_set

# Tor exit node prefix list (simplified)
tor_prefixes = ["185.220.", "199.87.154.", "185.107.80."]

def is_tor_ip(ip):
    if ip is None:
        return False
    return any(ip.startswith(p) for p in tor_prefixes)

is_tor_udf = udf(is_tor_ip, BooleanType())

logins = df.filter(col("eventName") == "InteractiveLogin")

detections = logins.withColumn(
    "is_tor", is_tor_udf(col("sourceIPAddress"))
).withColumn(
    "login_failed", when(col("responseStatus") != "200", 1).otherwise(0)
).groupBy("principalId", "principalName").agg(
    collect_set("sourceIPAddress").alias("src_ips"),
    count(when(col("login_failed") == 1, 1)).alias("failed_count"),
    count(when(col("is_tor") == True, 1)).alias("tor_count")
).filter(
    (col("failed_count") > 5) | (col("tor_count") > 0)
)`,
    sampleLogs: [
      `{"eventTime":"2024-12-10T03:10:00Z","eventName":"InteractiveLogin","principalId":"ocid1.user.oc1..aaaauser001","principalName":"finance-lead@corp.com","sourceIPAddress":"185.220.101.47","userAgent":"Mozilla/5.0","responseStatus":"200","compartmentId":"ocid1.tenancy.oc1..roottenancy","additionalDetails":{"country":"Unknown","city":"Tor Exit Node"}}`,
      `{"eventTime":"2024-12-10T03:10:02Z","eventName":"InteractiveLogin","principalId":"ocid1.user.oc1..aaaauser001","principalName":"finance-lead@corp.com","sourceIPAddress":"185.220.101.47","responseStatus":"401","additionalDetails":{"country":"Unknown"}}`,
    ],
    requiredFields: [
      "eventName",
      "principalId",
      "principalName",
      "sourceIPAddress",
      "responseStatus",
      "additionalDetails.country",
      "eventTime",
    ],
    falsePositives: [
      "Employees using VPNs that exit in unexpected countries",
      "Travelers accessing OCI from foreign locations",
      "Privacy-conscious users routing through Tor for non-malicious reasons",
    ],
    tuningGuidance:
      "Build a per-user country baseline over 30 days. Alert only on first-time countries, not just foreign countries. Maintain a Tor exit node IP list and refresh weekly. Combine with failed login counts for higher fidelity.",
    deploymentNotes:
      "Requires OCI Audit ingestion with InteractiveLogin events. GeoIP enrichment can be applied at the SIEM ingestion layer or via lookup tables in Splunk.",
    evasionConsiderations:
      "Sophisticated attackers use residential proxies rather than Tor, making geographic anomaly detection less reliable. Combine with device fingerprinting or user-agent analysis.",
    problemStatement:
      "Console login anomalies are a primary indicator of account takeover in cloud environments. OCI console access from Tor or unexpected countries warrants immediate investigation.",
  },
  {
    id: "det-oci-005",
    title: "OCI Cross-Compartment Resource Access Anomaly",
    description:
      "Detects a principal accessing resources in compartments outside their normal operational scope, indicating potential lateral movement or policy misconfiguration exploitation.",
    platform: ["OCI", "Cloud"],
    mitre: ["T1078.004", "T1021"],
    category: "Lateral Movement",
    maturity: "experimental",
    severity: "medium",
    tags: ["oci", "compartment", "lateral-movement", "cloud", "anomaly"],
    author: "Detection Engineering Team",
    updated: "2024-12-10",
    sigma: `title: OCI Cross-Compartment Access Anomaly
id: det-oci-005
status: experimental
description: >
  Detects principals accessing compartments outside their established baseline.
  Requires historical baseline of normal compartment access per principal.
author: Detection Engineering Team
date: 2024/12/10
tags:
  - attack.lateral_movement
  - attack.t1078.004
logsource:
  product: oracle_cloud
  service: audit
detection:
  selection:
    responseStatus: '200'
  # Post-processing required: compare compartmentId against per-principal baseline
  condition: selection
  # Alert when compartmentId not in historical set for principalId
level: medium`,
    splunk: `index=oci sourcetype=oci:audit
  responseStatus="200"
| stats dc(compartmentId) as compartment_count,
    values(compartmentId) as compartments_accessed
    by principalId, principalName, date_mday
| eventstats avg(compartment_count) as avg_compartments,
    stdev(compartment_count) as stdev_compartments
    by principalId
| eval z_score = (compartment_count - avg_compartments) / max(stdev_compartments, 0.1)
| where z_score > 2.5
| table date_mday, principalName, compartment_count, avg_compartments,
    z_score, compartments_accessed
| sort -z_score`,
    pyspark: `from pyspark.sql.window import Window
from pyspark.sql.functions import (
    col, countDistinct, avg, stddev, collect_set, abs as spark_abs
)

window_30d = Window.partitionBy("principalId").rowsBetween(-30, 0)

daily_access = df.filter(
    col("responseStatus") == "200"
).groupBy(
    "principalId", "principalName",
    to_date(col("eventTime")).alias("event_date")
).agg(
    countDistinct("compartmentId").alias("compartment_count"),
    collect_set("compartmentId").alias("compartments_accessed")
)

with_baseline = daily_access.withColumn(
    "avg_compartments", avg("compartment_count").over(window_30d)
).withColumn(
    "stdev_compartments", stddev("compartment_count").over(window_30d)
).withColumn(
    "z_score",
    (col("compartment_count") - col("avg_compartments")) /
    (col("stdev_compartments") + lit(0.1))
)

detections = with_baseline.filter(col("z_score") > 2.5)`,
    sampleLogs: [
      `{"eventTime":"2024-12-10T09:30:00Z","eventName":"GetInstance","principalId":"ocid1.user.oc1..aaaadev111","principalName":"backend-dev@corp.com","compartmentId":"ocid1.compartment.oc1..prod-finance","resourceId":"ocid1.instance.oc1.ap-sydney-1.prod-payroll-server","sourceIPAddress":"10.10.2.50","responseStatus":"200"}`,
      `{"eventTime":"2024-12-10T09:31:15Z","eventName":"ListBuckets","principalId":"ocid1.user.oc1..aaaadev111","principalName":"backend-dev@corp.com","compartmentId":"ocid1.compartment.oc1..prod-hr","resourceId":null,"sourceIPAddress":"10.10.2.50","responseStatus":"200"}`,
    ],
    requiredFields: [
      "principalId",
      "principalName",
      "compartmentId",
      "eventName",
      "responseStatus",
      "eventTime",
      "sourceIPAddress",
    ],
    falsePositives: [
      "Cross-team projects requiring temporary access to multiple compartments",
      "Platform engineers with broad operational access",
      "New employees being onboarded across environments",
    ],
    tuningGuidance:
      "Requires minimum 14 days of baseline data per principal. Exclude service accounts with defined broad access. Use dynamic groups to maintain known-good access patterns. Tune Z-score threshold (2.5–3.0) based on environment noise.",
    deploymentNotes:
      "This is a behavioral/anomaly detection requiring historical baseline computation. Implement in PySpark or a UEBA platform rather than real-time SIEM rules. Run as a daily batch job.",
    evasionConsiderations:
      "Attackers with long dwell time may slowly expand compartment access to blend into the baseline. Combine with resource sensitivity classification to weight high-value compartment access more heavily.",
    problemStatement:
      "In OCI, compartments are the primary isolation boundary. A user unexpectedly accessing compartments outside their normal scope may indicate privilege escalation, credential compromise, or policy misconfiguration exploitation.",
  },
];
