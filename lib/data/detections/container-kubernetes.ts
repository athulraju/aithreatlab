import type { Detection } from "./types";

export const containerKubernetesDetections: Detection[] = [
  {
    id: "det-k8s-001",
    title: "Privileged Pod Creation",
    description:
      "Detects creation of a Kubernetes pod with a privileged security context via the Kubernetes API audit log -- the single highest-impact container misconfiguration, since a privileged container has effectively unrestricted access to the underlying node.",
    platform: ["Kubernetes", "Cloud"],
    mitre: ["T1610", "T1611"],
    category: "Privilege Escalation",
    maturity: "experimental",
    severity: "critical",
    tags: ["kubernetes", "containers", "privileged", "k8s-audit"],
    author: "Detection Engineering Team",
    updated: "2026-10-29",
    sigma: `title: Privileged Pod Creation via Kubernetes Audit Log
id: det-k8s-001
status: experimental
description: Detects pods created with securityContext.privileged=true via the Kubernetes API audit log.
references:
  - https://attack.mitre.org/techniques/T1610/
  - https://attack.mitre.org/matrices/enterprise/containers/
author: Detection Engineering Team
date: 2026/10/29
tags:
  - attack.privilege_escalation
  - attack.t1610
  - attack.t1611
logsource:
  category: k8s_audit
  product: kubernetes
detection:
  selection:
    verb: create
    objectRef.resource: pods
    requestObject.spec.containers[].securityContext.privileged: true
  condition: selection
falsepositives:
  - Node-level monitoring/logging DaemonSets (Falco, Datadog agent) that legitimately require privileged mode
  - CNI/CSI driver installer pods
level: critical`,
    splunk: `index=k8s_audit sourcetype=kube:audit verb=create objectRef.resource=pods
  "requestObject.spec.containers{}.securityContext.privileged"=true
| table _time, user.username, objectRef.namespace, objectRef.name, requestObject.spec.containers{}.image
| sort -_time`,
    pyspark: `from pyspark.sql import SparkSession
from pyspark.sql.functions import col, explode

spark = SparkSession.builder.appName("K8sPrivilegedPod").getOrCreate()

df = spark.read.json("s3://security-lake/k8s/audit-logs/")

pods = df.filter(
    (col("verb") == "create") & (col("objectRef.resource") == "pods")
)
containers = pods.select(
    "stageTimestamp", "user.username", "objectRef.namespace", "objectRef.name",
    explode("requestObject.spec.containers").alias("container")
)

detections = containers.filter(
    col("container.securityContext.privileged") == True
).select(
    "stageTimestamp", "user.username", "objectRef.namespace", "objectRef.name", "container.image"
)

detections.write.mode("append").parquet("s3://detections/output/")`,
    sampleLogs: [
      `{"kind":"Event","verb":"create","objectRef":{"resource":"pods","namespace":"default","name":"debug-pod"},"user":{"username":"system:serviceaccount:default:ci-runner"},"requestObject":{"spec":{"containers":[{"name":"debug","image":"alpine:latest","securityContext":{"privileged":true}}]}},"stageTimestamp":"2026-10-29T09:15:00Z"}`,
    ],
    requiredFields: [
      "verb",
      "objectRef.resource",
      "objectRef.namespace",
      "objectRef.name",
      "user.username",
      "requestObject.spec.containers[].securityContext.privileged",
    ],
    falsePositives: [
      "Known node-monitoring DaemonSets (allowlist by namespace + service account, e.g. falco, datadog-agent)",
      "CNI/CSI driver installers that legitimately require host access during a narrow install window",
    ],
    tuningGuidance:
      "Build an allowlist of (namespace, serviceAccount, image-prefix) tuples for your legitimate privileged workloads rather than excluding whole namespaces -- namespace-wide exclusion is a common way this control gets silently defeated over time. Pair with a Pod Security Admission policy set to 'restricted' or 'baseline' so this becomes a detection-of-policy-bypass rather than the only control.",
    deploymentNotes:
      "Requires Kubernetes API server audit logging enabled with at least Metadata-level auditing on pods (RequestResponse level needed to see the container spec). On managed clusters (EKS, GKE, AKS, OKE) this must be explicitly enabled via the control-plane audit log configuration.",
    evasionConsiderations:
      "Attackers with namespace-create rights may instead request specific capabilities (CAP_SYS_ADMIN, CAP_SYS_PTRACE) or hostPID/hostNetwork/hostPath mounts individually rather than full privileged:true, achieving similar escape primitives while evading a privileged-only rule -- see det-k8s-002 for the hostPath companion rule.",
    problemStatement:
      "A privileged container shares the host's device nodes, bypasses most seccomp/AppArmor/SELinux confinement, and can trivially escape to the node -- MITRE ATT&CK for Containers lists this as the primary path from Initial Access inside a cluster to full node and often cluster compromise.",
  },
  {
    id: "det-k8s-002",
    title: "Sensitive HostPath Volume Mount",
    description:
      "Detects pod creation requests that mount sensitive host paths -- the container runtime socket, /proc, /var/run, or the node root filesystem -- which is the most common non-privileged route to container escape.",
    platform: ["Kubernetes", "Cloud"],
    mitre: ["T1611", "T1610"],
    category: "Privilege Escalation",
    maturity: "experimental",
    severity: "critical",
    tags: ["kubernetes", "containers", "hostpath", "container-escape"],
    author: "Detection Engineering Team",
    updated: "2026-10-29",
    sigma: `title: Sensitive HostPath Volume Mount
id: det-k8s-002
status: experimental
description: Detects pods mounting sensitive host paths such as the container runtime socket or node filesystem root.
references:
  - https://attack.mitre.org/techniques/T1611/
author: Detection Engineering Team
date: 2026/10/29
tags:
  - attack.privilege_escalation
  - attack.t1611
logsource:
  category: k8s_audit
  product: kubernetes
detection:
  selection:
    verb: create
    objectRef.resource: pods
    requestObject.spec.volumes[].hostPath.path|contains:
      - '/var/run/docker.sock'
      - '/var/run/containerd/containerd.sock'
      - '/run/crio/crio.sock'
      - '/proc'
      - '/'
  condition: selection
falsepositives:
  - Approved node-level observability or CSI/CNI agents mounting the container runtime socket
level: critical`,
    splunk: `index=k8s_audit sourcetype=kube:audit verb=create objectRef.resource=pods
  "requestObject.spec.volumes{}.hostPath.path"="*docker.sock*" OR
  "requestObject.spec.volumes{}.hostPath.path"="*containerd.sock*" OR
  "requestObject.spec.volumes{}.hostPath.path"="/proc" OR
  "requestObject.spec.volumes{}.hostPath.path"="/"
| table _time, user.username, objectRef.namespace, objectRef.name, requestObject.spec.volumes{}.hostPath.path
| sort -_time`,
    pyspark: `from pyspark.sql import SparkSession
from pyspark.sql.functions import col, explode

spark = SparkSession.builder.appName("K8sSensitiveHostPath").getOrCreate()

df = spark.read.json("s3://security-lake/k8s/audit-logs/")

sensitive_paths = ["docker.sock", "containerd.sock", "crio.sock"]

pods = df.filter((col("verb") == "create") & (col("objectRef.resource") == "pods"))
volumes = pods.select(
    "stageTimestamp", "user.username", "objectRef.namespace", "objectRef.name",
    explode("requestObject.spec.volumes").alias("volume")
)

detections = volumes.filter(
    col("volume.hostPath.path").isin(["/", "/proc"]) |
    col("volume.hostPath.path").rlike("|".join(sensitive_paths))
).select("stageTimestamp", "user.username", "objectRef.namespace", "objectRef.name", "volume.hostPath.path")

detections.write.mode("append").parquet("s3://detections/output/")`,
    sampleLogs: [
      `{"kind":"Event","verb":"create","objectRef":{"resource":"pods","namespace":"ci","name":"build-helper"},"user":{"username":"system:serviceaccount:ci:pipeline"},"requestObject":{"spec":{"volumes":[{"name":"docker-sock","hostPath":{"path":"/var/run/docker.sock"}}]}},"stageTimestamp":"2026-10-29T10:02:14Z"}`,
    ],
    requiredFields: [
      "verb",
      "objectRef.resource",
      "objectRef.namespace",
      "user.username",
      "requestObject.spec.volumes[].hostPath.path",
    ],
    falsePositives: [
      "Legitimate CI runners using docker-in-docker via socket mount (should migrate to rootless/sysbox alternatives where possible)",
      "Approved observability agents (Falco, cAdvisor) mounting /proc read-only",
    ],
    tuningGuidance:
      "Differentiate read-only vs read-write mounts where your audit log captures volume mount mode -- a read-only /proc mount for an observability agent is materially lower-risk than a read-write docker.sock mount for an arbitrary workload. Treat docker.sock/containerd.sock mounts as critical regardless of mode, since socket access alone is sufficient for escape.",
    deploymentNotes:
      "Same audit-log prerequisite as det-k8s-001 (RequestResponse-level auditing on pods). Strongly recommended to pair this detection with an admission controller (OPA Gatekeeper, Kyverno) that blocks these mounts outright rather than relying on detection alone.",
    evasionConsiderations:
      "Attackers may mount a parent directory of the socket (e.g. /var/run/) rather than the socket path itself to avoid simple string matches -- match on path prefixes, not just exact paths, and consider flagging any hostPath mount of '/var/run' or '/run' broadly at a lower severity tier.",
    problemStatement:
      "Mounting the container runtime socket inside a container is functionally equivalent to root on the node: the socket accepts privileged API calls to create new, unrestricted containers. This remains one of the most common real-world container escape techniques because it requires no CVE, only a permissive pod spec.",
  },
  {
    id: "det-k8s-003",
    title: "Exec or Attach Into Running Pod",
    description:
      "Detects kubectl exec/attach requests into a running pod via the Kubernetes API audit log subresource, with emphasis on exec into pods that are privileged or owned by a different team than the requesting principal -- a common post-compromise lateral movement and discovery step.",
    platform: ["Kubernetes", "Cloud"],
    mitre: ["T1609", "T1021"],
    category: "Lateral Movement",
    maturity: "experimental",
    severity: "high",
    tags: ["kubernetes", "containers", "kubectl-exec", "lateral-movement"],
    author: "Detection Engineering Team",
    updated: "2026-10-29",
    sigma: `title: Kubectl Exec or Attach Into Pod
id: det-k8s-003
status: experimental
description: Detects pods/exec or pods/attach subresource requests via the Kubernetes API audit log.
references:
  - https://attack.mitre.org/techniques/T1609/
author: Detection Engineering Team
date: 2026/10/29
tags:
  - attack.execution
  - attack.lateral_movement
  - attack.t1609
logsource:
  category: k8s_audit
  product: kubernetes
detection:
  selection:
    verb: create
    objectRef.resource: pods
    objectRef.subresource:
      - exec
      - attach
  condition: selection
falsepositives:
  - On-call engineers debugging production pods via kubectl exec
  - CI/CD pipelines that exec into pods for health checks
level: high`,
    splunk: `index=k8s_audit sourcetype=kube:audit verb=create objectRef.resource=pods
  (objectRef.subresource=exec OR objectRef.subresource=attach)
| table _time, user.username, objectRef.namespace, objectRef.name, requestURI
| sort -_time`,
    pyspark: `from pyspark.sql import SparkSession
from pyspark.sql.functions import col

spark = SparkSession.builder.appName("K8sExecAttach").getOrCreate()

df = spark.read.json("s3://security-lake/k8s/audit-logs/")

detections = df.filter(
    (col("verb") == "create") &
    (col("objectRef.resource") == "pods") &
    (col("objectRef.subresource").isin(["exec", "attach"]))
).select("stageTimestamp", "user.username", "objectRef.namespace", "objectRef.name", "requestURI")

detections.write.mode("append").parquet("s3://detections/output/")`,
    sampleLogs: [
      `{"kind":"Event","verb":"create","objectRef":{"resource":"pods","subresource":"exec","namespace":"payments","name":"api-7d9f-x2k4"},"user":{"username":"jdoe@company.com"},"requestURI":"/api/v1/namespaces/payments/pods/api-7d9f-x2k4/exec?command=/bin/sh","stageTimestamp":"2026-10-29T14:22:07Z"}`,
    ],
    requiredFields: [
      "verb",
      "objectRef.resource",
      "objectRef.subresource",
      "objectRef.namespace",
      "objectRef.name",
      "user.username",
    ],
    falsePositives: [
      "Legitimate production debugging by on-call engineers (correlate with incident/change tickets to suppress)",
      "CI/CD health-check or migration-runner steps that exec into pods as part of normal deployment",
    ],
    tuningGuidance:
      "Score severity up when the exec target is a pod with a privileged security context, mounts a service account token with broad RBAC, or sits in a namespace the requesting user has no prior exec history in. Score down (but still log) for break-glass accounts during declared incidents.",
    deploymentNotes:
      "Standard pod-level audit logging at Metadata level is sufficient here since exec/attach is identified by the subresource field, not the request body -- lighter-weight than the Request/RequestResponse level needed for det-k8s-001/002.",
    evasionConsiderations:
      "An attacker with node access (rather than API-server access) can exec into a container directly via the container runtime CLI (crictl exec, docker exec) or ctr, bypassing the Kubernetes audit log entirely -- this rule only covers the API-server path. Pair with node-level EDR or Falco syscall rules for the node-local path.",
    problemStatement:
      "kubectl exec is a routine operational action, which is exactly why it's a high-value blind spot: an attacker who compromises a developer's kubeconfig or a CI service account with broad exec RBAC can use it to pivot into any pod they have permission to reach, often to steal mounted secrets or pivot further.",
  },
  {
    id: "det-k8s-004",
    title: "RBAC Escalation to cluster-admin ClusterRoleBinding",
    description:
      "Detects creation or modification of a ClusterRoleBinding that grants the cluster-admin ClusterRole to a user, group, or service account -- the Kubernetes equivalent of granting domain-admin, and a frequent objective of post-compromise privilege escalation.",
    platform: ["Kubernetes", "Cloud"],
    mitre: ["T1098", "T1484"],
    category: "Privilege Escalation",
    maturity: "experimental",
    severity: "critical",
    tags: ["kubernetes", "rbac", "cluster-admin", "privilege-escalation"],
    author: "Detection Engineering Team",
    updated: "2026-10-29",
    sigma: `title: RBAC Escalation to cluster-admin
id: det-k8s-004
status: experimental
description: Detects ClusterRoleBinding create/update events that bind the cluster-admin role to a new subject.
references:
  - https://attack.mitre.org/techniques/T1098/
author: Detection Engineering Team
date: 2026/10/29
tags:
  - attack.privilege_escalation
  - attack.persistence
  - attack.t1098
logsource:
  category: k8s_audit
  product: kubernetes
detection:
  selection:
    verb:
      - create
      - update
    objectRef.resource: clusterrolebindings
    requestObject.roleRef.name: cluster-admin
  condition: selection
falsepositives:
  - Platform/SRE team onboarding via approved Infrastructure-as-Code pipeline (correlate with CI/CD commit)
level: critical`,
    splunk: `index=k8s_audit sourcetype=kube:audit (verb=create OR verb=update) objectRef.resource=clusterrolebindings
  "requestObject.roleRef.name"="cluster-admin"
| table _time, user.username, objectRef.name, requestObject.subjects{}.kind, requestObject.subjects{}.name
| sort -_time`,
    pyspark: `from pyspark.sql import SparkSession
from pyspark.sql.functions import col

spark = SparkSession.builder.appName("K8sClusterAdminEscalation").getOrCreate()

df = spark.read.json("s3://security-lake/k8s/audit-logs/")

detections = df.filter(
    (col("verb").isin(["create", "update"])) &
    (col("objectRef.resource") == "clusterrolebindings") &
    (col("requestObject.roleRef.name") == "cluster-admin")
).select("stageTimestamp", "user.username", "objectRef.name", "requestObject.subjects")

detections.write.mode("append").parquet("s3://detections/output/")`,
    sampleLogs: [
      `{"kind":"Event","verb":"create","objectRef":{"resource":"clusterrolebindings","name":"ci-full-access"},"user":{"username":"system:serviceaccount:ci:deployer"},"requestObject":{"roleRef":{"kind":"ClusterRole","name":"cluster-admin"},"subjects":[{"kind":"ServiceAccount","name":"backdoor-sa","namespace":"kube-system"}]},"stageTimestamp":"2026-10-29T16:48:51Z"}`,
    ],
    requiredFields: [
      "verb",
      "objectRef.resource",
      "objectRef.name",
      "requestObject.roleRef.name",
      "requestObject.subjects[].kind",
      "requestObject.subjects[].name",
      "user.username",
    ],
    falsePositives: [
      "Approved GitOps/IaC pipelines (ArgoCD, Flux, Terraform) provisioning legitimate platform-team access -- allowlist the pipeline's own service account as the requesting user, not the subject being granted access",
    ],
    tuningGuidance:
      "This should fire on essentially every occurrence in most clusters, since cluster-admin bindings should be rare, deliberate, and change-managed. Treat any binding whose subject is a newly-created service account, or any binding created outside your IaC pipeline's identity, as an immediate critical incident rather than tuning for noise reduction.",
    deploymentNotes:
      "Requires RBAC resources (clusterrolebindings, rolebindings, clusterroles) to be included in the audit policy at Request level, which is often omitted from default audit policies that focus on workload resources -- verify this explicitly rather than assuming it's covered.",
    evasionConsiderations:
      "Attackers may instead create a new, differently-named ClusterRole with equivalent wildcard permissions ('*' on '*' in apiGroups '*') rather than reusing the cluster-admin name directly to dodge a name-based rule -- extend this detection to flag any ClusterRole/ClusterRoleBinding granting wildcard verbs/resources, not only ones literally named cluster-admin.",
    problemStatement:
      "RBAC privilege escalation is the Kubernetes-native equivalent of domain admin compromise in Active Directory: once an attacker controls a cluster-admin-bound identity, every other control in the cluster -- network policy, admission control, secrets -- is reachable or bypassable.",
  },
  {
    id: "det-k8s-005",
    title: "Container Runtime Socket Access From Inside a Container",
    description:
      "Detects a process running inside a container opening the Docker or containerd control socket (typically reached via a hostPath mount) -- the runtime-level signal that complements the admission-time det-k8s-002 mount detection by confirming the socket was actually used.",
    platform: ["Kubernetes", "Container", "Cloud"],
    mitre: ["T1611"],
    category: "Privilege Escalation",
    maturity: "experimental",
    severity: "critical",
    tags: ["kubernetes", "containers", "runtime-escape", "falco"],
    author: "Detection Engineering Team",
    updated: "2026-10-29",
    sigma: `title: Container Runtime Socket Access From Within Container
id: det-k8s-005
status: experimental
description: Detects open() syscalls targeting the container runtime control socket from within a running container, captured via Falco/eBPF.
references:
  - https://attack.mitre.org/techniques/T1611/
author: Detection Engineering Team
date: 2026/10/29
tags:
  - attack.privilege_escalation
  - attack.t1611
logsource:
  category: syscall
  product: falco
detection:
  selection:
    fd.name|contains:
      - '/var/run/docker.sock'
      - '/var/run/containerd/containerd.sock'
      - '/run/crio/crio.sock'
    container.id: exists
  condition: selection
falsepositives:
  - Approved privileged observability DaemonSets querying the runtime socket for container inventory
level: critical`,
    splunk: `index=falco rule="*runtime*socket*" OR fd_name="*docker.sock*" OR fd_name="*containerd.sock*"
  container_id!=""
| table _time, container_id, container_image, proc_name, fd_name, k8s_pod_name, k8s_ns_name
| sort -_time`,
    pyspark: `from pyspark.sql import SparkSession
from pyspark.sql.functions import col

spark = SparkSession.builder.appName("K8sRuntimeSocketAccess").getOrCreate()

df = spark.read.json("s3://security-lake/falco/events/")

socket_paths = ["docker.sock", "containerd.sock", "crio.sock"]

detections = df.filter(
    (col("fd.name").rlike("|".join(socket_paths))) &
    (col("container.id").isNotNull())
).select("time", "container.id", "container.image", "proc.name", "fd.name", "k8s.pod.name", "k8s.ns.name")

detections.write.mode("append").parquet("s3://detections/output/")`,
    sampleLogs: [
      `{"time":"2026-10-29T20:11:45Z","rule":"Container Runtime Socket Accessed","output":"File open of container runtime socket (user=root command=curl --unix-socket /var/run/docker.sock http://localhost/containers/json container_id=4f2a9c image=alpine:latest)","container":{"id":"4f2a9c","image":"alpine:latest"},"k8s":{"pod":{"name":"build-helper"},"ns":{"name":"ci"}}}`,
    ],
    requiredFields: [
      "fd.name",
      "container.id",
      "container.image",
      "proc.name",
      "k8s.pod.name",
      "k8s.ns.name",
    ],
    falsePositives: [
      "Approved node-inventory/observability agents that legitimately query the runtime socket read-only",
    ],
    tuningGuidance:
      "Distinguish read-only inventory calls (GET /containers/json) from mutating calls (POST /containers/create, /exec) where the socket's HTTP API can be parsed -- mutating calls from an unapproved container should page immediately, read-only calls can be a lower-severity audit trail.",
    deploymentNotes:
      "Requires a runtime security agent with syscall or eBPF visibility inside containers (Falco, Tetragon, or an equivalent EDR agent) -- the Kubernetes API audit log alone cannot see this, since socket access happens entirely within the node/container runtime layer.",
    evasionConsiderations:
      "If the attacker already has a shell in a container with the socket mounted, they will typically act quickly once admission-time detection (det-k8s-002) might have already alerted -- treat the two detections as a pair and prioritize investigating det-k8s-002 alerts before this one fires, since the mount is the earlier and more preventable control point.",
    problemStatement:
      "The admission-time hostPath mount detection shows intent/misconfiguration; this runtime-level detection confirms exploitation. Together they close the loop from 'a risky mount exists' to 'the risky mount was actually used to talk to the runtime', which matters for incident prioritization.",
  },
  {
    id: "det-k8s-006",
    title: "Anomalous Bulk Kubernetes Secret Access",
    description:
      "Detects a single identity listing or getting Kubernetes Secrets across many namespaces or at unusually high volume in a short window via the API audit log -- a strong indicator of credential harvesting following initial cluster access.",
    platform: ["Kubernetes", "Cloud"],
    mitre: ["T1552", "T1078.004"],
    category: "Credential Access",
    maturity: "experimental",
    severity: "high",
    tags: ["kubernetes", "secrets", "credential-access", "k8s-audit"],
    author: "Detection Engineering Team",
    updated: "2026-10-29",
    sigma: `title: Anomalous Bulk Kubernetes Secret Access
id: det-k8s-006
status: experimental
description: Detects a single identity performing get/list on Secrets across an unusually high number of distinct namespaces within a short window.
references:
  - https://attack.mitre.org/techniques/T1552/
author: Detection Engineering Team
date: 2026/10/29
tags:
  - attack.credential_access
  - attack.t1552
logsource:
  category: k8s_audit
  product: kubernetes
detection:
  selection:
    verb:
      - get
      - list
    objectRef.resource: secrets
  condition: selection | distinct_namespace_count > 5 within 10m by user.username
falsepositives:
  - Secret-management controllers (External Secrets Operator, Sealed Secrets, Vault Agent Injector) that legitimately read secrets cluster-wide
  - Backup/DR tooling performing full-cluster exports
level: high`,
    splunk: `index=k8s_audit sourcetype=kube:audit (verb=get OR verb=list) objectRef.resource=secrets
| bin _time span=10m
| stats dc(objectRef.namespace) as distinct_namespaces, count by user.username, _time
| where distinct_namespaces > 5
| sort -_time`,
    pyspark: `from pyspark.sql import SparkSession
from pyspark.sql.functions import col, window, countDistinct, count

spark = SparkSession.builder.appName("K8sBulkSecretAccess").getOrCreate()

df = spark.read.json("s3://security-lake/k8s/audit-logs/")

secret_reads = df.filter(
    (col("verb").isin(["get", "list"])) & (col("objectRef.resource") == "secrets")
)

detections = secret_reads.groupBy(
    "user.username", window(col("stageTimestamp"), "10 minutes")
).agg(
    countDistinct("objectRef.namespace").alias("distinct_namespaces"),
    count("*").alias("total_reads")
).filter(col("distinct_namespaces") > 5)

detections.write.mode("append").parquet("s3://detections/output/")`,
    sampleLogs: [
      `{"kind":"Event","verb":"list","objectRef":{"resource":"secrets","namespace":"payments"},"user":{"username":"system:serviceaccount:default:debug-sa"},"stageTimestamp":"2026-10-29T21:02:00Z"}`,
      `{"kind":"Event","verb":"list","objectRef":{"resource":"secrets","namespace":"auth"},"user":{"username":"system:serviceaccount:default:debug-sa"},"stageTimestamp":"2026-10-29T21:02:03Z"}`,
    ],
    requiredFields: [
      "verb",
      "objectRef.resource",
      "objectRef.namespace",
      "user.username",
      "stageTimestamp",
    ],
    falsePositives: [
      "Secret synchronization controllers (External Secrets Operator, Sealed Secrets controller) by design",
      "Cluster backup/disaster-recovery jobs performing scheduled full exports",
    ],
    tuningGuidance:
      "Allowlist known controller service accounts by (namespace, name) rather than excluding the 'secrets' resource broadly, and set the namespace-diversity threshold relative to your cluster's actual namespace count -- 5 namespaces is a reasonable default for a mid-sized multi-tenant cluster but should be tuned down for smaller clusters.",
    deploymentNotes:
      "Requires Metadata-level audit logging on the secrets resource at minimum; note that many default Kubernetes audit policies explicitly exclude get/list on secrets to control audit log volume -- this must be deliberately re-enabled, with request bodies still omitted to avoid logging secret values themselves.",
    evasionConsiderations:
      "An attacker aware of namespace-count thresholds may slow their access rate to stay under the 10-minute window, or access secrets by directly mounting a compromised service account token in a pod's environment rather than calling the API -- correlate with service account token usage patterns (new source IPs/pods using a long-lived token) as a complementary signal.",
    problemStatement:
      "Kubernetes Secrets routinely hold database credentials, API keys, and TLS private keys for every workload in a cluster. An attacker who gains any identity with broad secret-read RBAC -- common in clusters that haven't tightened default service account permissions -- can harvest the credentials for the entire platform in minutes.",
  },
];
