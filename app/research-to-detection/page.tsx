"use client";

import { motion } from "framer-motion";
import { staggerContainer, staggerItem, fadeUp } from "@/lib/motion";
import {
  FileSearch,
  Network,
  Code2,
  Activity,
  Clock,
} from "lucide-react";

const ease = [0.25, 0.1, 0.25, 1] as const;

const features = [
  {
    icon: FileSearch,
    title: "Research Paper Analysis",
    description:
      "Automatically parse and extract attacker techniques and behaviors from AI security research papers.",
  },
  {
    icon: Network,
    title: "Telemetry Mapping",
    description:
      "Map extracted behaviors to observable signals across host logs, cloud logs, identity data, and agent activity.",
  },
  {
    icon: Code2,
    title: "Query Detection Ideas",
    description:
      "Generate practical query-based detection suggestions grounded in the mapped telemetry sources.",
  },
  {
    icon: Activity,
    title: "Behavioral Detection Ideas",
    description:
      "Surface behavioral patterns and anomaly signals that can inform rule and model-based detections.",
  },
];

export default function ResearchToDetectionPage() {
  return (
    <main className="min-h-screen bg-[#080810]">
      <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 pt-28 pb-24">

        {/* Coming Soon badge */}
        <motion.div
          className="flex justify-center mb-8"
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.35, ease }}
        >
          <span className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-purple-500/30 bg-purple-500/10 text-purple-400 text-xs font-semibold uppercase tracking-widest">
            <Clock className="w-3 h-3" />
            Coming Soon
          </span>
        </motion.div>

        {/* Page header */}
        <motion.div
          className="text-center mb-6"
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.45, ease, delay: 0.06 }}
        >
          <h1 className="text-3xl sm:text-4xl font-bold text-white tracking-tight mb-3">
            Research to Detection
          </h1>
          <p className="text-purple-400 text-sm font-medium">
            Turn AI security research into actionable detection ideas.
          </p>
        </motion.div>

        {/* Description */}
        <motion.p
          className="text-gray-500 text-sm leading-relaxed text-center max-w-2xl mx-auto mb-14"
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.45, ease, delay: 0.18 }}
        >
          This upcoming tool will analyze AI security research papers, extract attacker
          behaviors, map observable signals to telemetry such as host logs, cloud logs,
          identity data, and agent activity, and suggest practical query and behavioral
          detection ideas.
        </motion.p>

        {/* Feature preview */}
        <motion.div
          className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-14"
          variants={staggerContainer(0.07, 0.25)}
          initial="hidden"
          animate="visible"
        >
          {features.map(({ icon: Icon, title, description }) => (
            <motion.div
              key={title}
              variants={staggerItem}
              className="card-surface p-5 flex gap-4 items-start"
            >
              <div className="flex-shrink-0 w-9 h-9 rounded-lg bg-purple-500/10 border border-purple-500/20 flex items-center justify-center">
                <Icon className="w-4 h-4 text-purple-400" />
              </div>
              <div>
                <p className="text-sm font-semibold text-white mb-1">{title}</p>
                <p className="text-xs text-gray-500 leading-relaxed">{description}</p>
              </div>
            </motion.div>
          ))}
        </motion.div>

        {/* CTA */}
        <motion.div
          className="flex flex-col items-center gap-5"
          variants={fadeUp}
          initial="hidden"
          animate="visible"
        >
          <button
            disabled
            className="inline-flex items-center gap-2 px-6 py-2.5 rounded-lg bg-purple-500/20 border border-purple-500/25 text-purple-400/60 text-sm font-medium cursor-not-allowed select-none"
          >
            <Clock className="w-4 h-4" />
            Available Soon
          </button>

          {/* Footer note */}
          <p className="text-xs text-gray-600 text-center">
            This feature is currently in development and will be available soon.
          </p>
        </motion.div>

      </div>
    </main>
  );
}
