"use client";

import { motion } from "framer-motion";
import { fadeUp, staggerContainer, staggerItem } from "@/lib/motion";
import {
  ExternalLink,
  Terminal,
  Sparkles,
  Lock,
  Server,
  Workflow,
  ShieldCheck,
  Clock,
  Database,
  FileJson,
  Download,
  Cpu,
  CheckCircle2,
} from "lucide-react";

const ease = [0.25, 0.1, 0.25, 1] as const;

const pipeline = [
  { num: "01", icon: Workflow, title: "Describe the activity", desc: "Plain language: \"User Alice modifies an IAM policy\" plus a provider, time window, and event count." },
  { num: "02", icon: Database, title: "Deterministic scenario match", desc: "Keyword-matched against a verified schema registry, so the model never decides which event type to impersonate." },
  { num: "03", icon: Cpu, title: "Local Ollama generation", desc: "Structured JSON generation against a local model, streamed with real incremental progress." },
  { num: "04", icon: Clock, title: "Deterministic normalization", desc: "Timestamp ordering/range and per-actor identity consistency enforced in code, not left to the model." },
  { num: "05", icon: ShieldCheck, title: "Schema validation", desc: "Every event's fields and operation name are checked against the matched scenario before it's returned." },
  { num: "06", icon: Download, title: "Export", desc: "Copy to clipboard, or download as JSON or JSONL for SIEM/parser testing." },
];

const features = [
  { icon: Database, title: "Verified Schema Registry", desc: "12 scenarios across OCI, AWS, and Azure, each backed by real provider documentation, with no invented event types.", accent: "mint" },
  { icon: Cpu, title: "Streaming, Honest Progress", desc: "Real character counts from the model as it generates, not a fabricated percentage bar.", accent: "amber" },
  { icon: Clock, title: "Deterministic Normalization", desc: "Timestamp ordering and multi-actor identity consistency are enforced in code, independent of the model.", accent: "mint" },
  { icon: ShieldCheck, title: "Refuses to Fabricate", desc: "If a request doesn't match a verified scenario, it says so instead of generating a plausible-looking but unverified event.", accent: "amber" },
  { icon: Server, title: "Fully Local", desc: "No database, no queue, no cloud dependency: just a Next.js API route and a local Ollama call.", accent: "mint" },
  { icon: FileJson, title: "JSON / JSONL Export", desc: "Copy or download results in either format, ready for SIEM ingestion or parser tests.", accent: "amber" },
];

const scenarios = [
  { provider: "OCI", items: ["IAM policy create/update/delete", "Group membership add/remove", "API signing key upload/delete", "MFA TOTP device lifecycle", "Object Storage bucket admin"] },
  { provider: "AWS", items: ["Console login", "IAM access key creation", "IAM policy attach (user/role)", "S3 bucket policy change"] },
  { provider: "Azure", items: ["RBAC role assignment", "App client secret/certificate change", "Sign-in activity"] },
];

export default function LogForgeAboutPage() {
  return (
    <main className="min-h-screen">
      {/* ── HERO ──────────────────────────────────────────────────────── */}
      <section className="pt-20 pb-16 sm:pt-28 sm:pb-20">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <motion.div
            className="flex flex-wrap justify-center gap-2 mb-8"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, ease }}
          >
            {[
              { icon: Lock, label: "Local AI" },
              { icon: Server, label: "No Cloud API" },
              { icon: Sparkles, label: "Open Source" },
            ].map(({ icon: Icon, label }) => (
              <span
                key={label}
                className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full border border-[#83d7b6]/25 bg-[#83d7b6]/8 text-[#83d7b6] text-[11px] font-semibold uppercase tracking-widest"
              >
                <Icon className="w-3 h-3" />
                {label}
              </span>
            ))}
          </motion.div>

          <motion.h1
            className="text-4xl sm:text-5xl lg:text-6xl font-bold tracking-tight mb-5"
            initial={{ opacity: 0, y: 18 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, ease, delay: 0.08 }}
          >
            <span className="text-white">Log</span>
            <span className="text-[#83d7b6]">Forge</span>
            <span className="text-gray-600 mx-3 font-light">·</span>
            <span className="text-white">AI</span>
          </motion.h1>

          <motion.p
            className="text-lg text-gray-400 leading-relaxed max-w-2xl mx-auto mb-10"
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.45, ease, delay: 0.16 }}
          >
            Describe a cloud security activity in plain language. Get back a realistic,
            chronological, schema-verified synthetic audit log timeline, entirely local,
            powered by Ollama, no cloud API required.
          </motion.p>

          <motion.div
            className="flex flex-wrap justify-center gap-3"
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, ease, delay: 0.24 }}
          >
            <a
              href="https://github.com/athulraju/logforge-ai"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-[#83d7b6]/15 border border-[#83d7b6]/30 text-[#83d7b6] text-sm font-medium hover:bg-[#83d7b6]/22 hover:border-[#83d7b6]/45 transition-all"
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

      {/* ── WHY A REGISTRY ───────────────────────────────────────────── */}
      <section className="py-8">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div
            className="relative rounded-2xl border border-[#83d7b6]/15 bg-[#83d7b6]/[0.05] p-6 sm:p-8"
            variants={fadeUp}
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true, margin: "-60px" }}
          >
            <p className="text-sm sm:text-base text-gray-300 leading-relaxed">
              LLMs will happily invent a plausible-looking but nonexistent cloud event name if
              you ask them to role-play one. LogForge doesn&apos;t let the model make that call:
              every scenario is backed by a JSON template whose operation names, required
              fields, and log source trace back to the provider&apos;s own documentation. If a
              request doesn&apos;t match a verified scenario, LogForge says so instead of
              fabricating one.
            </p>
          </motion.div>
        </div>
      </section>

      {/* ── PIPELINE ──────────────────────────────────────────────────── */}
      <section className="py-16">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div className="text-center mb-12" variants={fadeUp} initial="hidden" whileInView="visible" viewport={{ once: true }}>
            <h2 className="text-2xl sm:text-3xl font-bold tracking-tight mb-3">How it works</h2>
            <p className="text-gray-500 max-w-xl mx-auto">Request to validated output, in six deterministic steps.</p>
          </motion.div>
          <motion.div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4" variants={staggerContainer(0.06)} initial="hidden" whileInView="visible" viewport={{ once: true }}>
            {pipeline.map((step) => (
              <motion.div key={step.num} variants={staggerItem} className="card-surface p-5">
                <div className="flex items-center gap-2 mb-3">
                  <span className="text-xs font-mono text-[#83d7b6]">{step.num}</span>
                  <step.icon className="w-4 h-4 text-[#83d7b6]" />
                </div>
                <h3 className="text-sm font-semibold text-white mb-1.5">{step.title}</h3>
                <p className="text-xs text-gray-500 leading-relaxed">{step.desc}</p>
              </motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* ── FEATURES ──────────────────────────────────────────────────── */}
      <section className="py-16 border-t border-white/[0.06]">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div className="text-center mb-12" variants={fadeUp} initial="hidden" whileInView="visible" viewport={{ once: true }}>
            <h2 className="text-2xl sm:text-3xl font-bold tracking-tight mb-3">Built for detection engineering</h2>
          </motion.div>
          <motion.div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4" variants={staggerContainer(0.06)} initial="hidden" whileInView="visible" viewport={{ once: true }}>
            {features.map((f) => (
              <motion.div key={f.title} variants={staggerItem} className="card-surface p-5">
                <f.icon className={`w-4 h-4 mb-3 ${f.accent === "mint" ? "text-[#83d7b6]" : "text-[#d08a5d]"}`} />
                <h3 className="text-sm font-semibold text-white mb-1.5">{f.title}</h3>
                <p className="text-xs text-gray-500 leading-relaxed">{f.desc}</p>
              </motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* ── SUPPORTED SCENARIOS ───────────────────────────────────────── */}
      <section className="py-16 border-t border-white/[0.06]">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div className="text-center mb-12" variants={fadeUp} initial="hidden" whileInView="visible" viewport={{ once: true }}>
            <h2 className="text-2xl sm:text-3xl font-bold tracking-tight mb-3">12 verified scenarios</h2>
            <p className="text-gray-500 max-w-xl mx-auto">Each one traces to real provider documentation; see each template&apos;s <code className="text-[#83d7b6]">docReference</code> in the repo.</p>
          </motion.div>
          <motion.div className="grid grid-cols-1 sm:grid-cols-3 gap-4" variants={staggerContainer(0.08)} initial="hidden" whileInView="visible" viewport={{ once: true }}>
            {scenarios.map((group) => (
              <motion.div key={group.provider} variants={staggerItem} className="card-surface p-5">
                <h3 className="text-sm font-semibold text-[#83d7b6] mb-3">{group.provider}</h3>
                <ul className="space-y-2">
                  {group.items.map((item) => (
                    <li key={item} className="flex items-start gap-2 text-xs text-gray-400">
                      <CheckCircle2 className="w-3 h-3 text-gray-600 flex-shrink-0 mt-0.5" />
                      {item}
                    </li>
                  ))}
                </ul>
              </motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* ── SETUP ─────────────────────────────────────────────────────── */}
      <section id="setup" className="py-16 border-t border-white/[0.06] scroll-mt-20">
        <div className="max-w-2xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div className="text-center mb-10" variants={fadeUp} initial="hidden" whileInView="visible" viewport={{ once: true }}>
            <h2 className="text-2xl sm:text-3xl font-bold tracking-tight mb-3">Local setup</h2>
          </motion.div>
          <motion.div className="space-y-3 mb-10" variants={staggerContainer(0.06)} initial="hidden" whileInView="visible" viewport={{ once: true }}>
            {[
              { label: "Clone the repo", cmd: "git clone https://github.com/athulraju/logforge-ai.git" },
              { label: "Pull a local model", cmd: "ollama pull llama3.1:8b" },
              { label: "Install dependencies", cmd: "npm install" },
              { label: "Run it", cmd: "npm run dev" },
            ].map(({ label, cmd }) => (
              <motion.div key={cmd} variants={staggerItem} className="flex items-center gap-4 card-surface px-4 py-3">
                <div className="flex-1 min-w-0">
                  <p className="text-[11px] text-gray-600 mb-0.5">{label}</p>
                  <code className="font-mono text-sm text-[#83d7b6]">{cmd}</code>
                </div>
              </motion.div>
            ))}
          </motion.div>

          <motion.div className="text-center" variants={fadeUp} initial="hidden" whileInView="visible" viewport={{ once: true }}>
            <a
              href="https://github.com/athulraju/logforge-ai"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2.5 px-7 py-3 rounded-xl bg-[#83d7b6]/15 border border-[#83d7b6]/30 text-[#83d7b6] text-sm font-semibold hover:bg-[#83d7b6]/22 hover:border-[#83d7b6]/45 active:scale-[0.98] transition-all"
            >
              <ExternalLink className="w-4 h-4" />
              View LogForge AI on GitHub
            </a>
            <p className="mt-4 text-xs text-gray-700">Open source · Self-hosted · No usage limits</p>
          </motion.div>
        </div>
      </section>
    </main>
  );
}
