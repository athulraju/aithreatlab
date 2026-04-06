"use client";

import Link from "next/link";
import { motion } from "framer-motion";
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

const fadeUp = {
  hidden: { opacity: 0, y: 20 },
  visible: (i = 0) => ({
    opacity: 1,
    y: 0,
    transition: { delay: i * 0.08, duration: 0.5, ease: "easeOut" },
  }),
};

const features = [
  {
    icon: Zap,
    title: "Multi-Format Converter",
    description:
      "Translate detections between Sigma, Splunk SPL, and PySpark with validated output and translation notes.",
    href: "/converter",
    accent: "cyan",
  },
  {
    icon: BookOpen,
    title: "Detection Library",
    description:
      "Searchable, filterable library of production-grade detections with full logic, tuning guidance, and deployment notes.",
    href: "/detections",
    accent: "blue",
  },
  {
    icon: BarChart3,
    title: "Coverage Framework",
    description:
      "Structured visibility across Host OS, Network, Identity, Cloud, and AI Security layers with MITRE mapping.",
    href: "/coverage",
    accent: "purple",
  },
  {
    icon: Brain,
    title: "AI Security",
    description:
      "OWASP Top 10 for LLMs and Agentic AI — with practical detections, monitoring guidance, and threat models.",
    href: "/ai-security",
    accent: "purple",
  },
  {
    icon: Terminal,
    title: "Detection Playground",
    description:
      "Interactive workbench to write, test, and validate detections against simulated event scenarios.",
    href: "/playground",
    accent: "cyan",
  },
  {
    icon: BookOpen,
    title: "Research Hub",
    description:
      "Technical articles on detection engineering, PySpark detections, Sigma portability, and AI threat modeling.",
    href: "/research",
    accent: "blue",
  },
];

const stats = [
  { value: "20+", label: "Detection Rules" },
  { value: "8", label: "Coverage Layers" },
  { value: "4", label: "Output Formats" },
  { value: "OWASP", label: "LLM & Agentic Top 10" },
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

export default function HomePage() {
  return (
    <div className="pt-14">
      {/* Hero */}
      <section className="relative overflow-hidden">
        <div className="absolute inset-0 bg-grid opacity-50" />
        <div className="absolute inset-0 bg-gradient-to-b from-transparent via-transparent to-[#080810]" />
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[400px] bg-cyan-500/[0.04] rounded-full blur-3xl" />

        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-20 pb-24 text-center">
          <motion.div
            initial="hidden"
            animate="visible"
            variants={fadeUp}
            custom={0}
          >
            <span className="inline-flex items-center gap-1.5 text-xs font-medium text-cyan-400 bg-cyan-400/10 border border-cyan-400/20 rounded-full px-3 py-1 mb-6">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
              Detection Engineering Platform
            </span>
          </motion.div>

          <motion.h1
            initial="hidden"
            animate="visible"
            variants={fadeUp}
            custom={1}
            className="text-5xl sm:text-6xl lg:text-7xl font-bold text-white tracking-tight leading-[1.05] mb-6"
          >
            Build. Translate.
            <br />
            <span className="gradient-text">Operationalize.</span>
          </motion.h1>

          <motion.p
            initial="hidden"
            animate="visible"
            variants={fadeUp}
            custom={2}
            className="text-xl text-gray-400 max-w-2xl mx-auto leading-relaxed mb-10"
          >
            A platform for building, translating, testing, and operationalizing detections across Sigma, Splunk, and PySpark — with a dedicated AI Security layer.
          </motion.p>

          <motion.div
            initial="hidden"
            animate="visible"
            variants={fadeUp}
            custom={3}
            className="flex flex-col sm:flex-row items-center justify-center gap-3"
          >
            <Link
              href="/converter"
              className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-white font-medium transition-all shadow-lg shadow-cyan-500/25 text-sm"
            >
              Try the Converter
              <ArrowRight className="w-4 h-4" />
            </Link>
            <Link
              href="/detections"
              className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-white font-medium transition-all text-sm"
            >
              Browse Detections
            </Link>
          </motion.div>

          {/* Stats */}
          <motion.div
            initial="hidden"
            animate="visible"
            variants={fadeUp}
            custom={5}
            className="mt-16 grid grid-cols-2 sm:grid-cols-4 gap-6 max-w-2xl mx-auto"
          >
            {stats.map((stat) => (
              <div key={stat.label} className="text-center">
                <div className="text-2xl font-bold text-white mb-1">{stat.value}</div>
                <div className="text-xs text-gray-500">{stat.label}</div>
              </div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* Converter Preview */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20">
        <div className="text-center mb-12">
          <p className="text-xs font-semibold text-cyan-400 uppercase tracking-widest mb-3">Converter</p>
          <h2 className="text-3xl font-bold text-white mb-4">Translate detections instantly</h2>
          <p className="text-gray-400 max-w-xl mx-auto">Write once in Sigma, deploy anywhere. Automatic translation to Splunk SPL and PySpark with validation and notes.</p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 max-w-5xl mx-auto">
          <div className="card-surface overflow-hidden">
            <div className="flex items-center justify-between px-4 py-3 border-b border-white/[0.06]">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-cyan-400" />
                <span className="text-xs font-medium text-gray-400">Sigma Input</span>
              </div>
              <span className="text-xs text-gray-600 font-mono">rule.yml</span>
            </div>
            <pre className="p-4 text-xs font-mono text-gray-300 overflow-x-auto leading-relaxed">
              {converterPreview}
            </pre>
          </div>

          <div className="card-surface overflow-hidden">
            <div className="flex items-center justify-between px-4 py-3 border-b border-white/[0.06]">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-orange-400" />
                <span className="text-xs font-medium text-gray-400">Splunk Output</span>
              </div>
              <span className="text-xs text-gray-600 font-mono">detection.spl</span>
            </div>
            <pre className="p-4 text-xs font-mono text-gray-300 overflow-x-auto leading-relaxed">
              {splunkPreview}
            </pre>
          </div>
        </div>

        <div className="text-center mt-8">
          <Link
            href="/converter"
            className="inline-flex items-center gap-2 text-sm text-cyan-400 hover:text-cyan-300 font-medium transition-colors"
          >
            Open full converter
            <ChevronRight className="w-4 h-4" />
          </Link>
        </div>
      </section>

      {/* Features Grid */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20 border-t border-white/[0.04]">
        <div className="text-center mb-12">
          <p className="text-xs font-semibold text-cyan-400 uppercase tracking-widest mb-3">Platform</p>
          <h2 className="text-3xl font-bold text-white mb-4">Everything for detection engineering</h2>
          <p className="text-gray-400 max-w-xl mx-auto">From writing rules to validating coverage to detecting AI threats — one platform for the full detection lifecycle.</p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {features.map((feature, i) => (
            <motion.div
              key={feature.title}
              initial={{ opacity: 0, y: 16 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.06, duration: 0.4 }}
            >
              <Link href={feature.href} className="card-surface-hover block p-6 group h-full">
                <div className={`w-9 h-9 rounded-lg flex items-center justify-center mb-4 ${
                  feature.accent === "cyan" ? "bg-cyan-400/10" :
                  feature.accent === "blue" ? "bg-blue-400/10" :
                  "bg-purple-400/10"
                }`}>
                  <feature.icon className={`w-5 h-5 ${
                    feature.accent === "cyan" ? "text-cyan-400" :
                    feature.accent === "blue" ? "text-blue-400" :
                    "text-purple-400"
                  }`} />
                </div>
                <h3 className="text-sm font-semibold text-white mb-2 group-hover:text-cyan-300 transition-colors">
                  {feature.title}
                </h3>
                <p className="text-sm text-gray-500 leading-relaxed">{feature.description}</p>
                <div className="flex items-center gap-1 mt-4 text-xs text-gray-600 group-hover:text-cyan-400 transition-colors">
                  Explore <ChevronRight className="w-3 h-3" />
                </div>
              </Link>
            </motion.div>
          ))}
        </div>
      </section>

      {/* Coverage Framework Preview */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20 border-t border-white/[0.04]">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
          <div>
            <p className="text-xs font-semibold text-purple-400 uppercase tracking-widest mb-3">Coverage Framework</p>
            <h2 className="text-3xl font-bold text-white mb-4">Know your detection coverage</h2>
            <p className="text-gray-400 leading-relaxed mb-6">
              Structured visibility across 8 detection layers — from Host OS to AI Security. Map detections to MITRE techniques, identify gaps, and track maturity.
            </p>
            <div className="space-y-3 mb-8">
              {["Host OS & Application", "Network & Perimeter", "Identity & Cloud", "AI Security Extension"].map((layer) => (
                <div key={layer} className="flex items-center gap-2.5">
                  <CheckCircle2 className="w-4 h-4 text-cyan-400 flex-shrink-0" />
                  <span className="text-sm text-gray-400">{layer}</span>
                </div>
              ))}
            </div>
            <Link
              href="/coverage"
              className="inline-flex items-center gap-2 text-sm text-purple-400 hover:text-purple-300 font-medium"
            >
              View coverage framework <ChevronRight className="w-4 h-4" />
            </Link>
          </div>

          <div className="card-surface p-6">
            <div className="space-y-2">
              {[
                { layer: "Host OS", count: 4, color: "bg-cyan-500" },
                { layer: "Host Application", count: 2, color: "bg-blue-500" },
                { layer: "Host Network", count: 2, color: "bg-indigo-500" },
                { layer: "Middle Network", count: 2, color: "bg-purple-500" },
                { layer: "Large Application", count: 2, color: "bg-violet-500" },
                { layer: "Identity", count: 3, color: "bg-fuchsia-500" },
                { layer: "Perimeter", count: 2, color: "bg-pink-500" },
                { layer: "AI Security Extension", count: 3, color: "bg-rose-500" },
              ].map((item) => (
                <div key={item.layer} className="flex items-center gap-3">
                  <span className="text-xs text-gray-500 w-36 flex-shrink-0">{item.layer}</span>
                  <div className="flex-1 bg-white/5 rounded-full h-2 overflow-hidden">
                    <div
                      className={`h-full rounded-full ${item.color} opacity-70`}
                      style={{ width: `${(item.count / 5) * 100}%` }}
                    />
                  </div>
                  <span className="text-xs text-gray-600 w-4">{item.count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* AI Security Preview */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20 border-t border-white/[0.04]">
        <div className="text-center mb-12">
          <p className="text-xs font-semibold text-purple-400 uppercase tracking-widest mb-3">AI Security</p>
          <h2 className="text-3xl font-bold text-white mb-4">Detect threats in AI systems</h2>
          <p className="text-gray-400 max-w-xl mx-auto">OWASP Top 10 for LLMs and Agentic AI — with practical monitoring guidance, detection rules, and threat models.</p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 max-w-5xl mx-auto">
          {[
            { title: "Prompt Injection", desc: "Direct and indirect attacks manipulating LLM instructions", icon: AlertTriangle, color: "text-red-400 bg-red-400/10" },
            { title: "Tool Misuse", desc: "AI agents exploiting tool permissions for unauthorized actions", icon: Zap, color: "text-orange-400 bg-orange-400/10" },
            { title: "Agent Goal Drift", desc: "Autonomous agents deviating from intended objectives", icon: Activity, color: "text-yellow-400 bg-yellow-400/10" },
            { title: "Data Exfiltration", desc: "Sensitive data extracted through LLM API channels", icon: Shield, color: "text-blue-400 bg-blue-400/10" },
            { title: "API Abuse", desc: "Rate limit bypass, model DoS, and credential theft", icon: Lock, color: "text-cyan-400 bg-cyan-400/10" },
            { title: "Supply Chain", desc: "Poisoned model weights and compromised integrations", icon: GitBranch, color: "text-purple-400 bg-purple-400/10" },
          ].map((item) => (
            <div key={item.title} className="card-surface p-5">
              <div className={`w-8 h-8 rounded-lg ${item.color} flex items-center justify-center mb-3`}>
                <item.icon className="w-4 h-4" />
              </div>
              <h3 className="text-sm font-semibold text-white mb-1.5">{item.title}</h3>
              <p className="text-xs text-gray-500 leading-relaxed">{item.desc}</p>
            </div>
          ))}
        </div>

        <div className="text-center mt-8">
          <Link
            href="/ai-security"
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-purple-500/10 hover:bg-purple-500/20 border border-purple-500/20 text-purple-400 font-medium transition-all text-sm"
          >
            Explore AI Security
            <ArrowRight className="w-4 h-4" />
          </Link>
        </div>
      </section>

      {/* CTA */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20 border-t border-white/[0.04]">
        <div className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-cyan-500/10 via-blue-500/10 to-purple-500/10 border border-white/10 p-12 text-center">
          <div className="absolute inset-0 bg-grid opacity-30" />
          <div className="relative">
            <h2 className="text-3xl font-bold text-white mb-4">Start building detections</h2>
            <p className="text-gray-400 max-w-md mx-auto mb-8">Convert your first rule, explore the library, or build in the playground.</p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
              <Link
                href="/converter"
                className="flex items-center gap-2 px-6 py-3 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-white font-medium transition-all shadow-lg shadow-cyan-500/25 text-sm"
              >
                Open Converter
                <ArrowRight className="w-4 h-4" />
              </Link>
              <Link
                href="/playground"
                className="flex items-center gap-2 px-6 py-3 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-white font-medium transition-all text-sm"
              >
                <Terminal className="w-4 h-4" />
                Try Playground
              </Link>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
