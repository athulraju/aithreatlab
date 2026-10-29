"use client";

import { motion } from "framer-motion";
import { fadeUp, staggerContainer, staggerItem } from "@/lib/motion";
import {
  Github,
  Terminal,
  Sparkles,
  Lock,
  Server,
  UploadCloud,
  SlidersHorizontal,
  PlayCircle,
  BarChart3,
  Brain,
  ShieldCheck,
  GitBranch,
  Scale,
  BookOpen,
  Clock,
  CheckCircle2,
} from "lucide-react";

const ease = [0.25, 0.1, 0.25, 1] as const;

const workflow = [
  { num: "01", icon: UploadCloud, title: "Upload Dataset", desc: "Drop in a preprocessed, numerically-encoded CSV or Parquet file and map your target, entity, timestamp, and context columns." },
  { num: "02", icon: SlidersHorizontal, title: "Configure Experiment", desc: "Minority Lens checks which pipelines are actually compatible with your column mapping and lets you pick a primary metric, seed, and run settings." },
  { num: "03", icon: PlayCircle, title: "Execute Pipelines", desc: "Each selected pipeline trains in the background with real, non-fabricated progress — cancel anytime." },
  { num: "04", icon: BarChart3, title: "Results Dashboard", desc: "See the validation-selected winner, a full leaderboard, confusion matrices, and an optional local-AI interpretation of the real results." },
];

const families = [
  { id: "A", name: "Supervised Bi-LSTM + SVM", family: "Supervised", accent: "mint" },
  { id: "B", name: "Hybrid Sequence + Tabular", family: "Hybrid", accent: "amber" },
  { id: "C", name: "Hybrid + Representation SMOTE", family: "Hybrid", accent: "amber" },
  { id: "D", name: "Semi-Supervised Pseudo-Labelling", family: "Semi-supervised", accent: "mint" },
  { id: "E", name: "Isolation Forest", family: "Anomaly", accent: "amber" },
  { id: "F", name: "Self-Supervised + Refinement", family: "Self-supervised", accent: "mint" },
  { id: "G", name: "Autoencoder", family: "Anomaly", accent: "amber" },
  { id: "H", name: "One-Class SVM", family: "Anomaly", accent: "amber" },
  { id: "E+Context", name: "Isolation Forest + Context Enrichment", family: "Anomaly", accent: "mint" },
];

const principles = [
  { icon: ShieldCheck, title: "Real training, every time", desc: "All nine pipelines are genuine PyTorch / scikit-learn / imbalanced-learn executions against your data — never an LLM-generated approximation of what a result would look like." },
  { icon: Scale, title: "Validation picks the winner", desc: "The winning pipeline and classification threshold are selected on validation performance only; test metrics are always reported separately." },
  { icon: GitBranch, title: "Honest about methodology", desc: "The thesis's temporal date-based split is reproduced exactly when timestamps are available; a stratified-random fallback is used otherwise and is explicitly labelled as a deviation." },
  { icon: Lock, title: "Fully local", desc: "No database, no queue, no cloud API in the training path. The only network call is an optional request to a local Ollama instance for result interpretation." },
];

export default function MinorityLensAboutPage() {
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
              { icon: Lock, label: "Local-First" },
              { icon: Server, label: "No Cloud API" },
              { icon: Sparkles, label: "Open Source" },
            ].map(({ icon: Icon, label }) => (
              <span
                key={label}
                className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full border border-[#d08a5d]/25 bg-[#d08a5d]/8 text-[#d08a5d] text-[11px] font-semibold uppercase tracking-widest"
              >
                <Icon className="w-3 h-3" />
                {label}
              </span>
            ))}
          </motion.div>

          <motion.h1
            className="text-4xl sm:text-5xl lg:text-6xl font-bold tracking-tight mb-5 text-white"
            initial={{ opacity: 0, y: 18 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, ease, delay: 0.08 }}
          >
            Minority Lens
          </motion.h1>

          <motion.p
            className="text-lg text-[#d08a5d] font-medium mb-5"
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.45, ease, delay: 0.14 }}
          >
            Finding signals in the rarest events.
          </motion.p>

          <motion.p
            className="text-base text-gray-400 leading-relaxed max-w-2xl mx-auto mb-10"
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.45, ease, delay: 0.2 }}
          >
            An AI-powered experimentation platform for evaluating supervised, hybrid, and
            anomaly-based machine learning pipelines on highly imbalanced datasets.
          </motion.p>

          <motion.div
            className="flex flex-wrap justify-center gap-3"
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, ease, delay: 0.28 }}
          >
            <span className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-white/[0.03] border border-white/10 text-gray-500 text-sm font-medium cursor-default">
              <Github className="w-4 h-4" />
              github.com/athulraju/Minority-Lens — publishing soon
            </span>
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

      {/* ── RESEARCH MOTIVATION ───────────────────────────────────────── */}
      <section className="py-8">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div
            className="relative rounded-2xl border border-[#d08a5d]/15 bg-[#d08a5d]/[0.05] p-6 sm:p-8"
            variants={fadeUp}
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true, margin: "-60px" }}
          >
            <div className="flex items-center gap-2 mb-3">
              <BookOpen className="w-4 h-4 text-[#d08a5d]" />
              <span className="text-xs font-semibold uppercase tracking-widest text-[#d08a5d]">Research motivation</span>
            </div>
            <p className="text-sm sm:text-base text-gray-300 leading-relaxed">
              Insider-threat and fraud datasets are extremely imbalanced — the behaviour you care
              about might be a fraction of a percent of all rows. Standard supervised classifiers
              tend to collapse toward the majority class, and whether oversampling, anomaly
              detection, semi-supervised pseudo-labelling, or context enrichment works best is
              genuinely dataset-dependent. Minority Lens is built around the MSc thesis{" "}
              <em>&quot;Anomaly Detection and Context Enrichment for Insider Threat Detection
              Under Extreme Class Imbalance&quot;</em> (Athul Raju, University of Limerick, 2026),
              which explored nine pipeline families on exactly this problem — and turns that
              exploration into a repeatable tool you can point at your own preprocessed dataset,
              rather than a one-off research notebook.
            </p>
          </motion.div>
        </div>
      </section>

      {/* ── WORKFLOW ──────────────────────────────────────────────────── */}
      <section className="py-16">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div className="text-center mb-12" variants={fadeUp} initial="hidden" whileInView="visible" viewport={{ once: true }}>
            <h2 className="text-2xl sm:text-3xl font-bold tracking-tight mb-3">How it works</h2>
            <p className="text-gray-500 max-w-xl mx-auto">A four-step workbench, from a raw file to a ranked leaderboard.</p>
          </motion.div>
          <motion.div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4" variants={staggerContainer(0.06)} initial="hidden" whileInView="visible" viewport={{ once: true }}>
            {workflow.map((step) => (
              <motion.div key={step.num} variants={staggerItem} className="card-surface p-5">
                <div className="flex items-center gap-2 mb-3">
                  <span className="text-xs font-mono text-[#d08a5d]">{step.num}</span>
                  <step.icon className="w-4 h-4 text-[#d08a5d]" />
                </div>
                <h3 className="text-sm font-semibold text-white mb-1.5">{step.title}</h3>
                <p className="text-xs text-gray-500 leading-relaxed">{step.desc}</p>
              </motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* ── PIPELINE FAMILIES ─────────────────────────────────────────── */}
      <section className="py-16 border-t border-white/[0.06]">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div className="text-center mb-12" variants={fadeUp} initial="hidden" whileInView="visible" viewport={{ once: true }}>
            <h2 className="text-2xl sm:text-3xl font-bold tracking-tight mb-3">Nine pipelines, five families</h2>
            <p className="text-gray-500 max-w-xl mx-auto">
              Supervised, hybrid, semi-supervised, self-supervised, and anomaly-based approaches —
              each a real, documented port of its thesis notebook, never a hardcoded result.
            </p>
          </motion.div>
          <motion.div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4" variants={staggerContainer(0.05)} initial="hidden" whileInView="visible" viewport={{ once: true }}>
            {families.map((p) => (
              <motion.div key={p.id} variants={staggerItem} className="card-surface p-5">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-mono text-gray-600">{p.id}</span>
                  <span className={`text-[10px] uppercase tracking-wider font-semibold ${p.accent === "mint" ? "text-[#83d7b6]" : "text-[#d08a5d]"}`}>{p.family}</span>
                </div>
                <h3 className="text-sm font-semibold text-white leading-snug">{p.name}</h3>
              </motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* ── PRINCIPLES ────────────────────────────────────────────────── */}
      <section className="py-16 border-t border-white/[0.06]">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div className="text-center mb-12" variants={fadeUp} initial="hidden" whileInView="visible" viewport={{ once: true }}>
            <h2 className="text-2xl sm:text-3xl font-bold tracking-tight mb-3">Built to be trusted, not just impressive</h2>
          </motion.div>
          <motion.div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4" variants={staggerContainer(0.06)} initial="hidden" whileInView="visible" viewport={{ once: true }}>
            {principles.map((f) => (
              <motion.div key={f.title} variants={staggerItem} className="card-surface p-5">
                <f.icon className="w-4 h-4 mb-3 text-[#d08a5d]" />
                <h3 className="text-sm font-semibold text-white mb-1.5">{f.title}</h3>
                <p className="text-xs text-gray-500 leading-relaxed">{f.desc}</p>
              </motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* ── LOCAL OLLAMA ──────────────────────────────────────────────── */}
      <section className="py-16 border-t border-white/[0.06]">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div className="card-surface p-6 sm:p-8" variants={fadeUp} initial="hidden" whileInView="visible" viewport={{ once: true }}>
            <div className="flex items-center gap-2 mb-3">
              <Brain className="w-4 h-4 text-[#d08a5d]" />
              <span className="text-xs font-semibold uppercase tracking-widest text-[#d08a5d]">Optional: local AI interpretation</span>
            </div>
            <p className="text-sm text-gray-400 leading-relaxed">
              Once pipelines finish training, Minority Lens can optionally ask a local Ollama
              model to interpret the <em>real</em> results — explaining the class imbalance,
              comparing the pipelines that actually ran, and explaining why the winner won — using
              an explicit system prompt that forbids inventing metrics or claiming an experiment
              ran when it didn&apos;t. Training, evaluation, and the full leaderboard work
              identically whether or not Ollama is running; this step only adds narrative, never
              new numbers.
            </p>
          </motion.div>
        </div>
      </section>

      {/* ── SETUP ─────────────────────────────────────────────────────── */}
      <section id="setup" className="py-16 border-t border-white/[0.06] scroll-mt-20">
        <div className="max-w-2xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div className="text-center mb-10" variants={fadeUp} initial="hidden" whileInView="visible" viewport={{ once: true }}>
            <h2 className="text-2xl sm:text-3xl font-bold tracking-tight mb-3">Local setup</h2>
            <p className="text-gray-500 max-w-xl mx-auto">
              Minority Lens runs as a FastAPI backend and a Next.js frontend, entirely on your own
              machine.
            </p>
          </motion.div>
          <motion.div className="space-y-3 mb-10" variants={staggerContainer(0.06)} initial="hidden" whileInView="visible" viewport={{ once: true }}>
            {[
              { label: "Backend — install", cmd: "cd backend && python3 -m venv .venv && source .venv/bin/activate && pip install -e \".[dev]\"" },
              { label: "Backend — run", cmd: "uvicorn app.main:app --host 127.0.0.1 --port 8800" },
              { label: "Frontend — install & run", cmd: "cd frontend && npm install && npm run dev" },
              { label: "Optional — local model", cmd: "ollama serve && ollama pull llama3.1:8b" },
            ].map(({ label, cmd }) => (
              <motion.div key={cmd} variants={staggerItem} className="flex items-center gap-4 card-surface px-4 py-3">
                <div className="flex-1 min-w-0">
                  <p className="text-[11px] text-gray-600 mb-0.5">{label}</p>
                  <code className="font-mono text-xs sm:text-sm text-[#d08a5d] break-all">{cmd}</code>
                </div>
              </motion.div>
            ))}
          </motion.div>

          <motion.div className="text-center" variants={fadeUp} initial="hidden" whileInView="visible" viewport={{ once: true }}>
            <p className="text-xs text-gray-600 mb-1">
              The workbench is then reachable at <code className="text-gray-500">http://localhost:3003</code> on
              the machine running it — this is a local development URL, not a hosted demo.
            </p>
            <div className="inline-flex items-center gap-2 mt-4 px-5 py-2.5 rounded-lg bg-white/[0.03] border border-white/10 text-gray-500 text-sm">
              <Clock className="w-4 h-4" />
              Repository publication is in progress — the GitHub link above will go live once published.
            </div>
          </motion.div>
        </div>
      </section>

      {/* ── ATTRIBUTION ───────────────────────────────────────────────── */}
      <section className="py-16 border-t border-white/[0.06]">
        <div className="max-w-2xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <motion.div variants={fadeUp} initial="hidden" whileInView="visible" viewport={{ once: true }}>
            <div className="flex items-center justify-center gap-2 mb-3">
              <CheckCircle2 className="w-4 h-4 text-[#d08a5d]" />
              <span className="text-xs font-semibold uppercase tracking-widest text-[#d08a5d]">Thesis attribution</span>
            </div>
            <p className="text-sm text-gray-500 leading-relaxed">
              Minority Lens&apos;s nine pipeline implementations are ported from the executed
              research notebooks accompanying the MSc thesis{" "}
              <em>&quot;Anomaly Detection and Context Enrichment for Insider Threat Detection
              Under Extreme Class Imbalance&quot;</em> by Athul Raju, University of Limerick, May
              2026. Every pipeline is run for real against whatever dataset you upload — the
              thesis&apos;s own published results are never reproduced or hardcoded here.
            </p>
          </motion.div>
        </div>
      </section>
    </main>
  );
}
