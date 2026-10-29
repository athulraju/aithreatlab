export type { Detection } from "./types";
export { coreDetections } from "./core";
export { ociDetections } from "./oci";
export { asiDetections } from "./oci-linux-asi";
export { llmDetections } from "./llm";
export { macosDetections } from "./macos";
export { containerKubernetesDetections } from "./container-kubernetes";
export { llmOutputDetections } from "./llm-output";

import { coreDetections } from "./core";
import { ociDetections } from "./oci";
import { asiDetections } from "./oci-linux-asi";
import { llmDetections } from "./llm";
import { macosDetections } from "./macos";
import { containerKubernetesDetections } from "./container-kubernetes";
import { llmOutputDetections } from "./llm-output";

export const detections = [
  ...coreDetections,
  ...ociDetections,
  ...asiDetections,
  ...llmDetections,
  ...macosDetections,
  ...containerKubernetesDetections,
  ...llmOutputDetections,
];

export const getDetectionById = (id: string) =>
  detections.find((d) => d.id === id);

export const categories = [
  "All",
  "Execution",
  "Credential Access",
  "Privilege Escalation",
  "Lateral Movement",
  "Defense Evasion",
  "Persistence",
  "Initial Access",
  "AI Security",
  "Exfiltration",
];

export const platforms = ["All", "Windows", "Linux", "macOS", "Cloud", "AWS", "OCI", "Kubernetes", "Container", "Endpoint", "Network", "AI/ML"];

export const maturityLevels = ["All", "production", "stable", "experimental", "deprecated"];
