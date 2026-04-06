import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(dateStr: string): string {
  return new Date(dateStr).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

export function severityColor(severity: string): string {
  switch (severity) {
    case "critical":
      return "text-red-400 bg-red-400/10 border-red-400/20";
    case "high":
      return "text-orange-400 bg-orange-400/10 border-orange-400/20";
    case "medium":
      return "text-yellow-400 bg-yellow-400/10 border-yellow-400/20";
    case "low":
      return "text-blue-400 bg-blue-400/10 border-blue-400/20";
    default:
      return "text-gray-400 bg-gray-400/10 border-gray-400/20";
  }
}

export function maturityColor(maturity: string): string {
  switch (maturity) {
    case "production":
      return "text-emerald-400 bg-emerald-400/10 border-emerald-400/20";
    case "stable":
      return "text-cyan-400 bg-cyan-400/10 border-cyan-400/20";
    case "experimental":
      return "text-purple-400 bg-purple-400/10 border-purple-400/20";
    case "planned":
      return "text-gray-400 bg-gray-400/10 border-gray-400/20";
    case "deprecated":
      return "text-gray-500 bg-gray-500/10 border-gray-500/20";
    default:
      return "text-gray-400 bg-gray-400/10 border-gray-400/20";
  }
}

export function platformColor(platform: string): string {
  switch (platform.toLowerCase()) {
    case "windows":
      return "text-blue-400 bg-blue-400/10 border-blue-400/20";
    case "linux":
      return "text-orange-400 bg-orange-400/10 border-orange-400/20";
    case "aws":
    case "cloud":
      return "text-yellow-400 bg-yellow-400/10 border-yellow-400/20";
    case "ai/ml":
      return "text-purple-400 bg-purple-400/10 border-purple-400/20";
    default:
      return "text-gray-400 bg-gray-400/10 border-gray-400/20";
  }
}
