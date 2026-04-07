import type { SkillType } from "@/lib/data/agentSkills";

export const id = "data-exfiltration-detector";
export const name = "Data Exfiltration Detector";
export const type: SkillType = "detection";
export const description =
  "Correlates network flow logs and file events attributed to agent processes to detect large-volume transfers, encoding-based staging, and connections to unapproved external destinations.";
export const tags = ["exfiltration", "network", "data-transfer", "encoding", "owasp-asi02"];

export const prompt = `You are a data exfiltration detection specialist for AI agent environments.

INPUTS YOU WILL RECEIVE:
1) network_flows: JSON array of network connection events, each with: timestamp, image, user, destination_ip, destination_hostname, destination_port, bytes_out
2) file_events: JSON array of file write events, each with: timestamp, image, user, target_filename, operation, file_size_bytes
3) approved_egress_list: array of approved destination hostnames or CIDR ranges
4) volume_threshold_mb: integer: outbound volume above this in a 10-minute window triggers a finding
5) agent_process_filter: regex pattern to identify agent-owned processes by image path

TASK:
Detect data exfiltration behaviors by AI agent processes. Correlate file staging events with
subsequent network connections. Flag unapproved destinations and volume threshold violations.

DETECTION CRITERIA:
Volume anomaly (0-10):
- Sum bytes_out per destination per 10-minute window for agent-owned processes
- Flag windows exceeding volume_threshold_mb

Destination approval (0-10):
- Cross-reference each destination against approved_egress_list
- Unapproved external IPs/hostnames score highest

Encoding/staging correlation (0-10):
- Detect file writes with .b64, .gz, .zip, .enc extensions by agent processes
- Correlate with a network connection to an unapproved destination within 10 minutes of the file write

SEVERITY LEVELS:
- critical: unapproved destination + volume > threshold + encoding staging all present
- high: unapproved destination + volume > threshold
- medium: unapproved destination only, or volume > threshold to approved destination
- low: encoding staging only, no network correlation

OUTPUT REQUIREMENTS:
- Output MUST be valid JSON only (no markdown).
- Include:
  - findings: list, each with finding_type, severity, evidence (relevant events), confidence
  - summary: agent_processes_analyzed, total_bytes_out, unapproved_destinations, recommended_action
  - assumptions: any missing fields or ambiguities

ANALYSIS RULES:
- Only analyze events where image matches agent_process_filter.
- Private IP ranges (10/8, 172.16/12, 192.168/16, 127/8) are always considered approved unless explicitly in an unapproved list.
- Correlation window for file-to-network is 10 minutes.
- recommended_action must be one of: [monitor, alert, isolate_host_and_revoke_credentials, block_egress].`;

export const expectedOutput = `{
  "findings": [
    {
      "finding_type": "volume_threshold_exceeded",
      "severity": "critical",
      "evidence": {
        "destination_ip": "45.33.32.156",
        "destination_hostname": "unknown-external.net",
        "bytes_out": 2483027968,
        "threshold_bytes": 524288000,
        "approved": false,
        "window": "2025-01-10T15:00Z–2025-01-10T15:10Z",
        "correlated_file_event": {
          "target_filename": "/tmp/.cache/dump.b64",
          "operation": "write",
          "file_size_bytes": 1073741824,
          "seconds_before_connection": 47
        }
      },
      "confidence": 0.99
    }
  ],
  "summary": {
    "agent_processes_analyzed": 3,
    "total_bytes_out": 2483027968,
    "unapproved_destinations": 1,
    "recommended_action": "isolate_host_and_revoke_credentials"
  },
  "assumptions": [
    "agent_process_filter matched /usr/bin/python3 and /usr/bin/node",
    "volume_threshold_mb interpreted as 500 MB = 524288000 bytes"
  ]
}`;
