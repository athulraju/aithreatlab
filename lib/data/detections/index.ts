export type { Detection } from "./types";
export { coreDetections } from "./core";
export { ociDetections } from "./oci";
export { asiDetections } from "./oci-linux-asi";

import { coreDetections } from "./core";
import { ociDetections } from "./oci";
import { asiDetections } from "./oci-linux-asi";

export const detections = [...coreDetections, ...ociDetections, ...asiDetections];

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

export const platforms = ["All", "Windows", "Linux", "Cloud", "AWS", "OCI", "Endpoint", "Network", "AI/ML"];

export const maturityLevels = ["All", "production", "stable", "experimental", "deprecated"];
