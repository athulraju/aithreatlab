"use client";

import Link from "next/link";
import { useRef, useEffect, useState } from "react";
import { detections } from "@/lib/data/detections/index";
import { coverageData, coverageLayers } from "@/lib/data/coverage";
import { motion, useInView, AnimatePresence } from "framer-motion";
import {
  ArrowRight,
  Zap,
  Shield,
  BarChart3,
  Brain,
  BookOpen,
  Terminal,
  GitBranch,
  Lock,
  CheckCircle2,
  ChevronRight,
  Search,
  AlertTriangle,
  Activity,
} from "lucide-react";
import { staggerContainer, staggerItem, fadeUp, revealItem } from "@/lib/motion";

// ── Count-up hook ─────────────────────────────────────────────────────────────
function useCountUp(target: number, duration = 1400) {
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true });
  const [count, setCount] = useState(0);

  useEffect(() => {
    if (!inView) return;
    let start = 0;
    const step = target / (duration / 16);
    const timer = setInterval(() => {
      start += step;
      if (start >= target) { setCount(target); clearInterval(timer); }
      else { setCount(Math.floor(start)); }
    }, 16);
    return () => clearInterval(timer);
  }, [inView, target, duration]);

  return { ref, count };
}

function StatCount({ value, label }: { value: number | string; label: string }) {
  const isNum = typeof value === "number";
  const { ref, count } = useCountUp(isNum ? (value as number) : 0);

  return (
    <div ref={ref} className="text-center">
      <div className="text-2xl font-bold text-white mb-1 tabular-nums">
        {isNum ? count : value}
      </div>
      <div className="text-xs text-gray-500">{label}</div>
    </div>
  );
}

// ── Data ──────────────────────────────────────────────────────────────────────
const layerColors: Record<string, string> = {
  "Host OS": "bg-cyan-500",
  "Host Application": "bg-blue-500",
  "Host Network": "bg-indigo-500",
  "Middle Network": "bg-purple-500",
  "Large Application": "bg-violet-500",
  "Identity": "bg-fuchsia-500",
  "Perimeter": "bg-pink-500",
  "AI Security Extension": "bg-rose-500",
};

const coverageLayerPreview = coverageLayers.map((layer) => ({
  layer,
  count: coverageData.filter((i) => i.layer === layer).length,
  color: layerColors[layer] ?? "bg-gray-500",
}));

const coverageLayerMax = Math.max(1, ...coverageLayerPreview.map((l) => l.count));

const features = [
  { icon: Zap,      title: "Multi-Format Converter",  description: "Translate detections between Sigma, Splunk SPL, and PySpark with validated output and translation notes.", href: "/converter",  accent: "cyan" },
  { icon: BookOpen, title: "Detection Library",        description: "Searchable, filterable library of production-grade detections with full logic, tuning guidance, and deployment notes.", href: "/detections", accent: "blue" },
  { icon: BarChart3,title: "Coverage Framework",       description: "Structured visibility across Host OS, Network, Identity, Cloud, and AI Security layers with MITRE mapping.", href: "/coverage",   accent: "purple" },
  { icon: Brain,    title: "AI Security",              description: "OWASP Top 10 for LLMs and Agentic AI — with practical detections, monitoring guidance, and threat models.", href: "/ai-security",accent: "purple" },
  { icon: Terminal, title: "Detection Playground",     description: "Interactive workbench to write, test, and validate detections against simulated event scenarios.", href: "/playground",  accent: "cyan" },
  { icon: BookOpen, title: "Research Hub",             description: "Technical articles on detection engineering, PySpark detections, Sigma portability, and AI threat modeling.", href: "/research",   accent: "blue" },
];

const stats = [
  { value: detections.length,    label: "Detection Rules" },
  { value: coverageLayers.length, label: "Coverage Layers" },
  { value: 3,                     label: "Output Formats" },
  { value: "OWASP",               label: "LLM & Agentic Top 10" },
];

const converterPreview = `title: Suspicious PowerShell Encoded Command
id: det-001
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains:
      - ' -EncodedCommand '
      - ' -enc '
  condition: selection
level: high`;

const splunkPreview = `index=endpoint sourcetype=WinEventLog:Security
  EventCode=4688
  Image="*\\powershell.exe"
  (CommandLine="* -EncodedCommand *" OR
   CommandLine="* -enc *")
| table _time, host, user, CommandLine
| sort -_time`;

const ease = [0.25, 0.1, 0.25, 1] as const;

export default function HomePage() {
  return (
    <div className="pt-14">

      {/* ── Hero ─────────────────────────────────────────────────────────── */}
      <section className="relative overflow-hidden">
        <div className="absolute inset-0 bg-grid opacity-50" />
        <div className="absolute inset-0 bg-gradient-to-b from-transparent via-transparent to-[#080810]" />

        {/* Animated ambient blobs */}
        <div className="pointer-events-none absolute inset-0 overflow-hidden">
          <div className="animate-glow-pulse absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[400px] bg-cyan-500/[0.05] rounded-full blur-3xl" />
          <div className="animate-glow-pulse absolute top-20 right-0 w-[400px] h-[400px] bg-blue-500/[0.03] rounded-full blur-3xl" style={{ animationDelay: "2s" }} />
          <div className="animate-glow-pulse absolute top-40 left-0 w-[300px] h-[300px] bg-violet-500/[0.03] rounded-full blur-3xl" style={{ animationDelay: "4s" }} />
        </div>

        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-20 pb-24 text-center">
          <motion.div initial="hidden" animate="visible" variants={fadeUp} custom={0}>
            <span className="inline-flex items-center gap-1.5 text-xs font-medium text-cyan-400 bg-cyan-400/10 border border-cyan-400/20 rounded-full px-3 py-1 mb-6">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
              Detection Engineering Platform
            </span>
          </motion.div>

          <motion.h1
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.55, ease, delay: 0.08 }}
            className="text-5xl sm:text-6xl lg:text-7xl font-bold text-white tracking-tight leading-[1.05] mb-6"
          >
            Build. Translate.
            <br />
            <span className="gradient-text">Operationalize.</span>
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, ease, delay: 0.16 }}
            className="text-xl text-gray-400 max-w-2xl mx-auto leading-relaxed mb-10"
          >
            A platform for building, translating, testing, and operationalizing detections across Sigma, Splunk, and PySpark — with a dedicated AI Security layer.
          </motion.p>

          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.45, ease, delay: 0.24 }}
            className="flex flex-col sm:flex-row items-center justify-center gap-3"
          >
            <Link
              href="/converter"
              className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-white font-medium transition-all shadow-lg shadow-cyan-500/25 text-sm hover:shadow-cyan-500/40 hover:-translate-y-0.5 duration-200"
            >
              Try the Converter
              <ArrowRight className="w-4 h-4" />
            </Link>
            <Link
              href="/detections"
              className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 hover:border-white/20 text-white font-medium transition-all text-sm hover:-translate-y-0.5 duration-200"
            >
              Browse Detections
            </Link>
          </motion.div>

          {/* Stats with count-up */}
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, ease, delay: 0.35 }}
            className="mt-16 grid grid-cols-2 sm:grid-cols-4 gap-6 max-w-2xl mx-auto"
          >
            {stats.map((stat) => (
              <StatCount key={stat.label} value={stat.value} label={stat.label} />
            ))}
          </motion.div>
        </div>
      </section>

      {/* ── Converter Preview ─────────────────────────────────────────────── */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20">
        <motion.div
          className="text-center mb-12"
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.45, ease }}
        >
          <p className="text-xs font-semibold text-cyan-400 uppercase tracking-widest mb-3">Converter</p>
          <h2 className="text-3xl font-bold text-white mb-4">Translate detections instantly</h2>
          <p className="text-gray-400 max-w-xl mx-auto">Write once in Sigma, deploy anywhere. Automatic translation to Splunk SPL and PySpark with validation and notes.</p>
        </motion.div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 max-w-5xl mx-auto">
          {[
            { dot: "bg-cyan-400", label: "Sigma Input", file: "rule.yml", content: converterPreview },
            { dot: "bg-orange-400", label: "Splunk Output", file: "detection.spl", content: splunkPreview },
          ].map((panel, i) => (
            <motion.div
              key={panel.label}
              className="card-surface overflow-hidden"
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.45, ease, delay: i * 0.08 }}
            >
              <div className="flex items-center justify-between px-4 py-3 border-b border-white/[0.06]">
                <div className="flex items-center gap-2">
                  <span className={`w-2 h-2 rounded-full ${panel.dot}`} />
                  <span className="text-xs font-medium text-gray-400">{panel.label}</span>
                </div>
                <span className="text-xs text-gray-600 font-mono">{panel.file}</span>
              </div>
              <pre className="p-4 text-xs font-mono text-gray-300 overflow-x-auto leading-relaxed">
                {panel.content}
              </pre>
            </motion.div>
          ))}
        </div>

        <motion.div
          className="text-center mt-8"
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.4, ease, delay: 0.2 }}
        >
          <Link href="/converter" className="inline-flex items-center gap-2 text-sm text-cyan-400 hover:text-cyan-300 font-medium transition-colors group">
            Open full converter
            <ChevronRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform duration-150" />
          </Link>
        </motion.div>
      </section>

      {/* ── Features Grid ─────────────────────────────────────────────────── */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20 border-t border-white/[0.04]">
        <motion.div
          className="text-center mb-12"
          initial={{ opacity: 0, y: 14 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.45, ease }}
        >
          <p className="text-xs font-semibold text-cyan-400 uppercase tracking-widest mb-3">Platform</p>
          <h2 className="text-3xl font-bold text-white mb-4">Everything for detection engineering</h2>
          <p className="text-gray-400 max-w-xl mx-auto">From writing rules to validating coverage to detecting AI threats — one platform for the full detection lifecycle.</p>
        </motion.div>

        <motion.div
          className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4"
          variants={staggerContainer(0.07)}
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true }}
        >
          {features.map((feature) => (
            <motion.div key={feature.title} variants={staggerItem}>
              <Link href={feature.href} className="card-surface-hover block p-6 group h-full cursor-pointer">
                <div className={`w-9 h-9 rounded-lg flex items-center justify-center mb-4 transition-colors duration-200 ${
                  feature.accent === "cyan"   ? "bg-cyan-400/10   group-hover:bg-cyan-400/20"   :
                  feature.accent === "blue"   ? "bg-blue-400/10   group-hover:bg-blue-400/20"   :
                  "bg-purple-400/10 group-hover:bg-purple-400/20"
                }`}>
                  <feature.icon className={`w-5 h-5 ${
                    feature.accent === "cyan"   ? "text-cyan-400"   :
                    feature.accent === "blue"   ? "text-blue-400"   :
                    "text-purple-400"
                  }`} />
                </div>
                <h3 className="text-sm font-semibold text-white mb-2 group-hover:text-cyan-300 transition-colors duration-200">
                  {feature.title}
                </h3>
                <p className="text-sm text-gray-500 leading-relaxed">{feature.description}</p>
                <div className="flex items-center gap-1 mt-4 text-xs text-gray-600 group-hover:text-cyan-400 transition-colors duration-200">
                  Explore <ChevronRight className="w-3 h-3 group-hover:translate-x-0.5 transition-transform duration-150" />
                </div>
              </Link>
            </motion.div>
          ))}
        </motion.div>
      </section>

      {/* ── Coverage Framework Preview ─────────────────────────────────────── */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20 border-t border-white/[0.04]">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, ease }}
          >
            <p className="text-xs font-semibold text-purple-400 uppercase tracking-widest mb-3">Coverage Framework</p>
            <h2 className="text-3xl font-bold text-white mb-4">Know your detection coverage</h2>
            <p className="text-gray-400 leading-relaxed mb-6">
              Structured visibility across 8 detection layers — from Host OS to AI Security. Map detections to MITRE techniques, identify gaps, and track maturity.
            </p>
            <motion.div
              className="space-y-3 mb-8"
              variants={staggerContainer(0.07)}
              initial="hidden"
              whileInView="visible"
              viewport={{ once: true }}
            >
              {["Host OS & Application", "Network & Perimeter", "Identity & Cloud", "AI Security Extension"].map((layer) => (
                <motion.div key={layer} variants={staggerItem} className="flex items-center gap-2.5">
                  <CheckCircle2 className="w-4 h-4 text-cyan-400 flex-shrink-0" />
                  <span className="text-sm text-gray-400">{layer}</span>
                </motion.div>
              ))}
            </motion.div>
            <Link href="/coverage" className="inline-flex items-center gap-2 text-sm text-purple-400 hover:text-purple-300 font-medium group transition-colors">
              View coverage framework <ChevronRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform duration-150" />
            </Link>
          </motion.div>

          <motion.div
            className="card-surface p-6"
            initial={{ opacity: 0, x: 20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, ease, delay: 0.1 }}
          >
            <div className="space-y-2">
              {coverageLayerPreview.map((item, i) => (
                <div key={item.layer} className="flex items-center gap-3">
                  <span className="text-xs text-gray-500 w-36 flex-shrink-0">{item.layer}</span>
                  <div className="flex-1 bg-white/5 rounded-full h-2 overflow-hidden">
                    <motion.div
                      className={`h-full rounded-full ${item.color} opacity-70`}
                      initial={{ scaleX: 0, originX: 0 }}
                      whileInView={{ scaleX: 1, originX: 0 }}
                      viewport={{ once: true }}
                      transition={{ duration: 0.6, ease, delay: 0.2 + i * 0.05 }}
                      style={{ width: `${(item.count / coverageLayerMax) * 100}%` }}
                    />
                  </div>
                  <span className="text-xs text-gray-600 w-4">{item.count}</span>
                </div>
              ))}
            </div>
          </motion.div>
        </div>
      </section>

      {/* ── AI Security Preview ─────────────────────────────────────────────── */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20 border-t border-white/[0.04]">
        <motion.div
          className="text-center mb-12"
          initial={{ opacity: 0, y: 14 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.45, ease }}
        >
          <p className="text-xs font-semibold text-purple-400 uppercase tracking-widest mb-3">AI Security</p>
          <h2 className="text-3xl font-bold text-white mb-4">Detect threats in AI systems</h2>
          <p className="text-gray-400 max-w-xl mx-auto">OWASP Top 10 for LLMs and Agentic AI — with practical monitoring guidance, detection rules, and threat models.</p>
        </motion.div>

        <motion.div
          className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 max-w-5xl mx-auto"
          variants={staggerContainer(0.06)}
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true }}
        >
          {[
            { title: "Prompt Injection",  desc: "Direct and indirect attacks manipulating LLM instructions",          icon: AlertTriangle, color: "text-red-400 bg-red-400/10",    hoverBorder: "hover:border-red-500/30" },
            { title: "Tool Misuse",        desc: "AI agents exploiting tool permissions for unauthorized actions",      icon: Zap,           color: "text-orange-400 bg-orange-400/10", hoverBorder: "hover:border-orange-500/30" },
            { title: "Agent Goal Drift",   desc: "Autonomous agents deviating from intended objectives",               icon: Activity,      color: "text-yellow-400 bg-yellow-400/10", hoverBorder: "hover:border-yellow-500/30" },
            { title: "Data Exfiltration",  desc: "Sensitive data extracted through LLM API channels",                 icon: Shield,        color: "text-blue-400 bg-blue-400/10",    hoverBorder: "hover:border-blue-500/30" },
            { title: "API Abuse",          desc: "Rate limit bypass, model DoS, and credential theft",                 icon: Lock,          color: "text-cyan-400 bg-cyan-400/10",    hoverBorder: "hover:border-cyan-500/30" },
            { title: "Supply Chain",       desc: "Poisoned model weights and compromised integrations",               icon: GitBranch,     color: "text-purple-400 bg-purple-400/10", hoverBorder: "hover:border-purple-500/30" },
          ].map((item) => (
            <motion.div
              key={item.title}
              variants={staggerItem}
              className={`card-surface p-5 border border-white/[0.08] transition-all duration-200 rounded-xl hover:-translate-y-1 hover:shadow-lg hover:shadow-black/30 ${item.hoverBorder}`}
            >
              <div className={`w-8 h-8 rounded-lg ${item.color} flex items-center justify-center mb-3`}>
                <item.icon className="w-4 h-4" />
              </div>
              <h3 className="text-sm font-semibold text-white mb-1.5">{item.title}</h3>
              <p className="text-xs text-gray-500 leading-relaxed">{item.desc}</p>
            </motion.div>
          ))}
        </motion.div>

        <motion.div
          className="text-center mt-8"
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.4, ease, delay: 0.3 }}
        >
          <Link
            href="/ai-security"
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-purple-500/10 hover:bg-purple-500/20 border border-purple-500/20 hover:border-purple-500/35 text-purple-400 font-medium transition-all text-sm hover:-translate-y-0.5 duration-200"
          >
            Explore AI Security
            <ArrowRight className="w-4 h-4" />
          </Link>
        </motion.div>
      </section>

      {/* ── CTA ─────────────────────────────────────────────────────────────── */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20 border-t border-white/[0.04]">
        <motion.div
          className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-cyan-500/10 via-blue-500/10 to-purple-500/10 border border-white/10 p-12 text-center"
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.5, ease }}
        >
          <div className="absolute inset-0 bg-grid opacity-30" />
          {/* Animated beam */}
          <div className="animate-beam absolute inset-y-0 w-32 bg-gradient-to-r from-transparent via-white/[0.04] to-transparent pointer-events-none" />
          <div className="relative">
            <h2 className="text-3xl font-bold text-white mb-4">Start building detections</h2>
            <p className="text-gray-400 max-w-md mx-auto mb-8">Convert your first rule, explore the library, or build in the playground.</p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
              <Link
                href="/converter"
                className="flex items-center gap-2 px-6 py-3 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-white font-medium transition-all shadow-lg shadow-cyan-500/25 hover:shadow-cyan-500/40 text-sm hover:-translate-y-0.5 duration-200"
              >
                Open Converter
                <ArrowRight className="w-4 h-4" />
              </Link>
              <Link
                href="/playground"
                className="flex items-center gap-2 px-6 py-3 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 hover:border-white/20 text-white font-medium transition-all text-sm hover:-translate-y-0.5 duration-200"
              >
                <Terminal className="w-4 h-4" />
                Try Playground
              </Link>
            </div>
          </div>
        </motion.div>
      </section>
    </div>
  );
}
