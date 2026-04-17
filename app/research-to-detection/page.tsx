"use client";

import { motion } from "framer-motion";
import {
  staggerContainer,
  staggerItem,
  fadeUp,
  fadeIn,
} from "@/lib/motion";
import {
  BookOpen,
  Layers,
  Cpu,
  SlidersHorizontal,
  Download,
  BarChart2,
  Server,
  Activity,
  Files,
  Network,
  FileText,
  TrendingUp,
  ExternalLink,
  Terminal,
  ArrowRight,
  CheckCircle2,
  Sparkles,
  Lock,
} from "lucide-react";

// ── Animation ease ────────────────────────────────────────────────────────────
const ease = [0.25, 0.1, 0.25, 1] as const;

// ── Pipeline steps ─────────────────────────────────────────────────────────────
const steps = [
  {
    num: "01",
    icon: BookOpen,
    title: "Paper Selection",
    desc: "Upload PDFs, text files, or discover live arXiv papers ranked by detection relevance.",
  },
  {
    num: "02",
    icon: Layers,
    title: "Schema Mapping",
    desc: "Optionally provide your log schema (JSON/CSV) to align detections with your environment.",
  },
  {
    num: "03",
    icon: Cpu,
    title: "AI Processing",
    desc: "Local Ollama model analyzes the paper, extracts attacker behaviors, and synthesizes detections.",
  },
  {
    num: "04",
    icon: SlidersHorizontal,
    title: "Detection Review",
    desc: "Filter and examine generated rules by severity and detection type.",
  },
  {
    num: "05",
    icon: Download,
    title: "Skill Download",
    desc: "Export analyst-ready Markdown skill files with threat narratives and pseudo-code.",
  },
  {
    num: "06",
    icon: BarChart2,
    title: "Gap Analysis",
    desc: "Surface missing telemetry sources and coverage weaknesses in your detection stack.",
  },
];

// ── Feature cards ──────────────────────────────────────────────────────────────
const features = [
  {
    icon: Server,
    title: "Local-First Architecture",
    desc: "Runs entirely on localhost:9000 with Ollama. No cloud APIs, no data leaves your machine.",
    accent: "purple",
  },
  {
    icon: Activity,
    title: "Behavioral Detection",
    desc: "Sequence-based rules with temporal correlations — attacker intent, not keyword signatures.",
    accent: "cyan",
  },
  {
    icon: Files,
    title: "Multiple Input Formats",
    desc: "Supports PDF, Markdown, plain text, and live arXiv paper discovery with AI-powered ranking.",
    accent: "blue",
  },
  {
    icon: Network,
    title: "Environment Alignment",
    desc: "Provide your log field schema so generated detections map directly to your telemetry sources.",
    accent: "green",
  },
  {
    icon: FileText,
    title: "Analyst-Ready Output",
    desc: "Every detection includes false positive guidance, tuning advice, and implementation notes.",
    accent: "orange",
  },
  {
    icon: TrendingUp,
    title: "Coverage Gap Analysis",
    desc: "Identify blind spots and inferred telemetry assumptions that expose missing detection coverage.",
    accent: "purple",
  },
];

// ── Accent style map ──────────────────────────────────────────────────────────
const accentStyles: Record<string, { icon: string; badge: string; border: string }> = {
  purple: {
    icon: "text-purple-400",
    badge: "bg-purple-500/10 border-purple-500/20",
    border: "group-hover:border-purple-500/30",
  },
  cyan: {
    icon: "text-cyan-400",
    badge: "bg-cyan-500/10 border-cyan-500/20",
    border: "group-hover:border-cyan-500/30",
  },
  blue: {
    icon: "text-blue-400",
    badge: "bg-blue-500/10 border-blue-500/20",
    border: "group-hover:border-blue-500/30",
  },
  green: {
    icon: "text-green-400",
    badge: "bg-green-500/10 border-green-500/20",
    border: "group-hover:border-green-500/30",
  },
  orange: {
    icon: "text-orange-400",
    badge: "bg-orange-500/10 border-orange-500/20",
    border: "group-hover:border-orange-500/30",
  },
};

// ── Setup steps ───────────────────────────────────────────────────────────────
const setupSteps = [
  { step: "1", cmd: "ollama pull llama3.1:8b", label: "Pull the local model" },
  { step: "2", cmd: "./start.sh", label: "Launch the server" },
  { step: "3", cmd: "open http://localhost:9000", label: "Open in browser" },
];

// ── Detection JSON preview lines ──────────────────────────────────────────────
const detectionLines = [
  { type: "brace", text: "{" },
  { type: "key", key: "title", value: '"LLM Prompt Injection via Tool Override"', valueType: "string" },
  { type: "key", key: "severity", value: '"high"', valueType: "severity-high" },
  { type: "key", key: "confidence", value: "0.87", valueType: "number" },
  { type: "key", key: "detection_type", value: '"behavioral"', valueType: "special" },
  { type: "key", key: "attack_stage", value: '"execution"', valueType: "string" },
  { type: "array-open", key: "telemetry" },
  { type: "array-item", value: '"llm_api_logs"' },
  { type: "array-item", value: '"agent_tool_calls"' },
  { type: "array-item", value: '"system_prompt_events"' },
  { type: "array-close" },
  { type: "key", key: "pseudo_logic", value: '"SEQUENCE(override → escalation) WITHIN 5s"', valueType: "string" },
  { type: "key", key: "false_positives", value: '["Legitimate tool config updates"]', valueType: "string" },
  { type: "key", key: "tuning", value: '"Correlate with identity logs to reduce noise"', valueType: "string" },
  { type: "brace", text: "}" },
];

function DetectionPreview() {
  return (
    <div className="rounded-xl bg-[#0a0a14] border border-white/[0.07] overflow-hidden">
      {/* Window chrome */}
      <div className="flex items-center gap-1.5 px-4 py-3 border-b border-white/[0.06] bg-white/[0.02]">
        <span className="w-2.5 h-2.5 rounded-full bg-red-500/50" />
        <span className="w-2.5 h-2.5 rounded-full bg-yellow-500/50" />
        <span className="w-2.5 h-2.5 rounded-full bg-green-500/50" />
        <span className="ml-3 text-[11px] text-gray-600 font-mono">detection_output.json</span>
        <span className="ml-auto flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-semibold bg-green-500/10 border border-green-500/20 text-green-400">
          <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
          generated
        </span>
      </div>

      {/* Code content */}
      <div className="p-5 font-mono text-xs leading-6 overflow-x-auto">
        {detectionLines.map((line, i) => {
          if (line.type === "brace") {
            return (
              <div key={i} className="text-gray-500">{line.text}</div>
            );
          }
          if (line.type === "array-open") {
            return (
              <div key={i} className="pl-4">
                <span className="text-purple-300/80">&quot;{line.key}&quot;</span>
                <span className="text-gray-500">: [</span>
              </div>
            );
          }
          if (line.type === "array-item") {
            return (
              <div key={i} className="pl-8">
                <span className="text-cyan-300/70">{line.value}</span>
                <span className="text-gray-600">,</span>
              </div>
            );
          }
          if (line.type === "array-close") {
            return (
              <div key={i} className="pl-4 text-gray-500">],</div>
            );
          }
          // key-value
          const valueColors: Record<string, string> = {
            string: "text-cyan-300/70",
            number: "text-orange-300/80",
            special: "text-purple-300",
            "severity-high": "text-red-400",
          };
          const color = valueColors[line.valueType ?? "string"] ?? "text-cyan-300/70";
          return (
            <div key={i} className="pl-4">
              <span className="text-purple-300/80">&quot;{line.key}&quot;</span>
              <span className="text-gray-500">: </span>
              <span className={color}>{line.value}</span>
              <span className="text-gray-600">,</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function ResearchToDetectionPage() {
  return (
    <main className="min-h-screen bg-[#080810]">

      {/* ── HERO ──────────────────────────────────────────────────────────── */}
      <section className="relative overflow-hidden pt-28 pb-20">
        {/* Grid bg */}
        <div className="pointer-events-none absolute inset-0 bg-grid opacity-60" />
        {/* Purple glow */}
        <div
          className="pointer-events-none absolute inset-0"
          style={{
            background:
              "radial-gradient(ellipse 70% 55% at 50% 0%, rgba(139,92,246,0.12) 0%, transparent 65%)",
          }}
        />

        <div className="relative max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          {/* Badge row */}
          <motion.div
            className="flex flex-wrap justify-center gap-2 mb-8"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, ease }}
          >
            {[
              { icon: Lock, label: "Local AI" },
              { icon: Server, label: "No API Keys" },
              { icon: Sparkles, label: "Open Source" },
            ].map(({ icon: Icon, label }) => (
              <span
                key={label}
                className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full border border-purple-500/25 bg-purple-500/8 text-purple-300 text-[11px] font-semibold uppercase tracking-widest"
              >
                <Icon className="w-3 h-3" />
                {label}
              </span>
            ))}
          </motion.div>

          {/* Title */}
          <motion.h1
            className="text-4xl sm:text-5xl lg:text-6xl font-bold tracking-tight mb-5"
            initial={{ opacity: 0, y: 18 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, ease, delay: 0.08 }}
          >
            <span className="text-white">Research</span>
            <span className="text-gray-600 mx-3 font-light">→</span>
            <span className="gradient-text-purple">Detection</span>
          </motion.h1>

          {/* Tagline */}
          <motion.p
            className="text-lg text-gray-400 leading-relaxed max-w-2xl mx-auto mb-10"
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.45, ease, delay: 0.16 }}
          >
            Transform AI and LLM security research papers into structured, actionable
            detection rules — entirely on your machine, with no cloud APIs required.
          </motion.p>

          {/* CTAs */}
          <motion.div
            className="flex flex-wrap justify-center gap-3"
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, ease, delay: 0.24 }}
          >
            <a
              href="https://github.com/athulraju/Research2Defense"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-purple-500/15 border border-purple-500/30 text-purple-300 text-sm font-medium hover:bg-purple-500/22 hover:border-purple-500/45 transition-all"
            >
              <ExternalLink className="w-4 h-4" />
              View on GitHub
            </a>
            <a
              href="#setup"
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-white/5 border border-white/10 text-gray-300 text-sm font-medium hover:bg-white/8 hover:border-white/18 transition-all"
            >
              <Terminal className="w-4 h-4" />
              Local Setup
            </a>
          </motion.div>
        </div>
      </section>

      {/* ── PHILOSOPHY CALLOUT ────────────────────────────────────────────── */}
      <section className="py-8">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div
            className="relative rounded-2xl border border-purple-500/15 bg-purple-500/[0.05] p-6 sm:p-8 overflow-hidden"
            variants={fadeUp}
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true, margin: "-60px" }}
          >
            {/* Glow */}
            <div
              className="pointer-events-none absolute right-0 top-0 w-72 h-full opacity-30"
              style={{
                background:
                  "radial-gradient(ellipse 60% 80% at 100% 50%, rgba(139,92,246,0.25) 0%, transparent 70%)",
              }}
            />

            <div className="relative flex flex-col sm:flex-row sm:items-center gap-5">
              <div className="flex-shrink-0 w-11 h-11 rounded-xl bg-purple-500/15 border border-purple-500/25 flex items-center justify-center">
                <Activity className="w-5 h-5 text-purple-400" />
              </div>
              <div>
                <p className="text-sm font-semibold text-white mb-1">
                  Behavioral detection over keyword matching
                </p>
                <p className="text-sm text-gray-500 leading-relaxed">
                  R2D prioritizes sequence-based patterns, temporal correlations, and relationship
                  signals — generating rules that reflect attacker intent, not isolated signatures
                  that are trivial to evade.
                </p>
              </div>
            </div>
          </motion.div>
        </div>
      </section>

      {/* ── PIPELINE ──────────────────────────────────────────────────────── */}
      <section className="py-16">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">

          {/* Section header */}
          <motion.div
            className="mb-12 text-center"
            variants={fadeUp}
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true, margin: "-60px" }}
          >
            <p className="text-[11px] font-semibold uppercase tracking-widest text-purple-400 mb-3">
              How it works
            </p>
            <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
              Six-stage pipeline
            </h2>
          </motion.div>

          {/* Steps grid */}
          <motion.div
            className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4"
            variants={staggerContainer(0.08, 0.1)}
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true, margin: "-40px" }}
          >
            {steps.map(({ num, icon: Icon, title, desc }) => (
              <motion.div
                key={num}
                variants={staggerItem}
                className="group relative card-surface p-5 hover:border-purple-500/20 hover:bg-white/[0.06] transition-all duration-200"
              >
                {/* Step number */}
                <div className="flex items-start justify-between mb-4">
                  <div className="w-9 h-9 rounded-lg bg-purple-500/10 border border-purple-500/20 flex items-center justify-center group-hover:bg-purple-500/15 transition-colors">
                    <Icon className="w-4 h-4 text-purple-400" />
                  </div>
                  <span className="font-mono text-xs font-bold text-gray-700 group-hover:text-purple-500/60 transition-colors">
                    {num}
                  </span>
                </div>

                <p className="text-sm font-semibold text-white mb-1.5">{title}</p>
                <p className="text-xs text-gray-500 leading-relaxed">{desc}</p>

                {/* Arrow for non-last items on large screens */}
                {parseInt(num) < 6 && parseInt(num) % 3 !== 0 && (
                  <div className="hidden lg:block absolute -right-2 top-1/2 -translate-y-1/2 z-10">
                    <ArrowRight className="w-4 h-4 text-gray-700" />
                  </div>
                )}
              </motion.div>
            ))}
          </motion.div>

          {/* Flow summary */}
          <motion.div
            className="mt-8 flex items-center justify-center gap-2 flex-wrap"
            variants={fadeIn}
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true }}
          >
            {["Research Paper", "Ollama (Local)", "Detections + Skills"].map((label, i) => (
              <span key={label} className="flex items-center gap-2">
                <span className="px-3 py-1 rounded-md bg-white/[0.04] border border-white/[0.08] text-xs font-mono text-gray-400">
                  {label}
                </span>
                {i < 2 && <ArrowRight className="w-3.5 h-3.5 text-gray-700" />}
              </span>
            ))}
          </motion.div>
        </div>
      </section>

      {/* ── FEATURES ──────────────────────────────────────────────────────── */}
      <section className="py-16 relative">
        <div
          className="pointer-events-none absolute inset-0 opacity-40"
          style={{
            background:
              "radial-gradient(ellipse 80% 50% at 50% 50%, rgba(139,92,246,0.05) 0%, transparent 70%)",
          }}
        />
        <div className="relative max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">

          <motion.div
            className="mb-12 text-center"
            variants={fadeUp}
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true, margin: "-60px" }}
          >
            <p className="text-[11px] font-semibold uppercase tracking-widest text-purple-400 mb-3">
              Capabilities
            </p>
            <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
              Built for detection engineers
            </h2>
          </motion.div>

          <motion.div
            className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4"
            variants={staggerContainer(0.07, 0.1)}
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true, margin: "-40px" }}
          >
            {features.map(({ icon: Icon, title, desc, accent }) => {
              const s = accentStyles[accent];
              return (
                <motion.div
                  key={title}
                  variants={staggerItem}
                  className={`group card-surface p-5 transition-all duration-200 ${s.border}`}
                >
                  <div className={`w-9 h-9 rounded-lg border flex items-center justify-center mb-4 ${s.badge}`}>
                    <Icon className={`w-4 h-4 ${s.icon}`} />
                  </div>
                  <p className="text-sm font-semibold text-white mb-1.5">{title}</p>
                  <p className="text-xs text-gray-500 leading-relaxed">{desc}</p>
                </motion.div>
              );
            })}
          </motion.div>
        </div>
      </section>

      {/* ── DETECTION PREVIEW ─────────────────────────────────────────────── */}
      <section className="py-16">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-10 items-center">

            {/* Left: description */}
            <motion.div
              variants={fadeUp}
              initial="hidden"
              whileInView="visible"
              viewport={{ once: true, margin: "-60px" }}
            >
              <p className="text-[11px] font-semibold uppercase tracking-widest text-purple-400 mb-4">
                Output format
              </p>
              <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-tight mb-5">
                Structured, actionable detections
              </h2>
              <p className="text-sm text-gray-400 leading-relaxed mb-8">
                Every detection generated by R2D includes structured fields for
                immediate operationalization — severity scoring, required telemetry,
                pseudo-logic, false positive guidance, and tuning recommendations.
              </p>

              <ul className="space-y-3">
                {[
                  "Severity & confidence scoring",
                  "Telemetry source mapping",
                  "Behavioral pseudo-logic",
                  "False positive guidance",
                  "Implementation notes & tuning",
                ].map((item) => (
                  <li key={item} className="flex items-center gap-2.5 text-sm text-gray-400">
                    <CheckCircle2 className="w-4 h-4 text-purple-400 flex-shrink-0" />
                    {item}
                  </li>
                ))}
              </ul>
            </motion.div>

            {/* Right: code preview */}
            <motion.div
              variants={fadeUp}
              initial="hidden"
              whileInView="visible"
              viewport={{ once: true, margin: "-60px" }}
              transition={{ delay: 0.1 }}
            >
              <DetectionPreview />
            </motion.div>
          </div>
        </div>
      </section>

      {/* ── INPUTS & OUTPUTS ──────────────────────────────────────────────── */}
      <section className="py-12">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">

            {/* Inputs */}
            <motion.div
              className="card-surface p-6"
              variants={fadeUp}
              initial="hidden"
              whileInView="visible"
              viewport={{ once: true }}
            >
              <div className="flex items-center gap-2.5 mb-5">
                <div className="w-8 h-8 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center">
                  <Files className="w-3.5 h-3.5 text-blue-400" />
                </div>
                <p className="text-sm font-semibold text-white">Accepted Inputs</p>
              </div>
              <div className="space-y-2.5">
                {[
                  { label: "Documents", detail: ".pdf  .txt  .md" },
                  { label: "Log Schemas", detail: ".json  .csv  .txt" },
                  { label: "Live Discovery", detail: "arXiv API (AI-ranked)" },
                ].map(({ label, detail }) => (
                  <div key={label} className="flex items-center justify-between py-2 border-b border-white/[0.05] last:border-0">
                    <span className="text-xs text-gray-400">{label}</span>
                    <span className="font-mono text-[11px] text-blue-400/80 bg-blue-500/8 px-2 py-0.5 rounded">
                      {detail}
                    </span>
                  </div>
                ))}
              </div>
            </motion.div>

            {/* Outputs */}
            <motion.div
              className="card-surface p-6"
              variants={fadeUp}
              initial="hidden"
              whileInView="visible"
              viewport={{ once: true }}
              transition={{ delay: 0.08 }}
            >
              <div className="flex items-center gap-2.5 mb-5">
                <div className="w-8 h-8 rounded-lg bg-green-500/10 border border-green-500/20 flex items-center justify-center">
                  <Download className="w-3.5 h-3.5 text-green-400" />
                </div>
                <p className="text-sm font-semibold text-white">Generated Outputs</p>
              </div>
              <div className="space-y-2.5">
                {[
                  { label: "Detection Rules", detail: "JSON + Markdown" },
                  { label: "Skill Files", detail: "Analyst-ready .md" },
                  { label: "Gap Analysis", detail: "Telemetry recommendations" },
                ].map(({ label, detail }) => (
                  <div key={label} className="flex items-center justify-between py-2 border-b border-white/[0.05] last:border-0">
                    <span className="text-xs text-gray-400">{label}</span>
                    <span className="font-mono text-[11px] text-green-400/80 bg-green-500/8 px-2 py-0.5 rounded">
                      {detail}
                    </span>
                  </div>
                ))}
              </div>
            </motion.div>
          </div>
        </div>
      </section>

      {/* ── GET STARTED ───────────────────────────────────────────────────── */}
      <section id="setup" className="py-16 scroll-mt-20">
        <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8">

          <motion.div
            className="text-center mb-10"
            variants={fadeUp}
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true, margin: "-60px" }}
          >
            <p className="text-[11px] font-semibold uppercase tracking-widest text-purple-400 mb-3">
              Get started
            </p>
            <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-tight mb-3">
              Run it locally in minutes
            </h2>
            <p className="text-sm text-gray-500">
              Requires Python 3.10+ and{" "}
              <a
                href="https://ollama.com"
                target="_blank"
                rel="noopener noreferrer"
                className="text-purple-400 hover:text-purple-300 underline underline-offset-2 transition-colors"
              >
                Ollama
              </a>{" "}
              installed on your machine.
            </p>
          </motion.div>

          <motion.div
            className="space-y-3 mb-10"
            variants={staggerContainer(0.1, 0.1)}
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true }}
          >
            {setupSteps.map(({ step, cmd, label }) => (
              <motion.div
                key={step}
                variants={staggerItem}
                className="flex items-center gap-4 card-surface p-4"
              >
                <span className="flex-shrink-0 w-6 h-6 rounded-full bg-purple-500/15 border border-purple-500/25 text-purple-400 text-xs font-bold flex items-center justify-center">
                  {step}
                </span>
                <div className="flex-1 min-w-0">
                  <p className="text-[11px] text-gray-600 mb-0.5">{label}</p>
                  <code className="font-mono text-sm text-purple-300">{cmd}</code>
                </div>
              </motion.div>
            ))}
          </motion.div>

          {/* GitHub CTA */}
          <motion.div
            className="text-center"
            variants={fadeUp}
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true }}
          >
            <a
              href="https://github.com/athulraju/Research2Defense"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2.5 px-7 py-3 rounded-xl bg-purple-500/15 border border-purple-500/30 text-purple-300 text-sm font-semibold hover:bg-purple-500/22 hover:border-purple-500/45 active:scale-[0.98] transition-all"
            >
              <ExternalLink className="w-4 h-4" />
              View Research2Defense on GitHub
            </a>
            <p className="mt-4 text-xs text-gray-700">
              Open source · Self-hosted · No usage limits
            </p>
          </motion.div>
        </div>
      </section>

    </main>
  );
}
