"use client";

import Link from "next/link";
import { motion } from "framer-motion";
import { fadeUp, staggerContainer, staggerItem } from "@/lib/motion";
import { PageHeader } from "@/components/PageHeader";
import { Badge } from "@/components/Badge";
import { ArrowRight, ExternalLink, FlaskConical, Server, Lock, Sparkles } from "lucide-react";

const ease = [0.25, 0.1, 0.25, 1] as const;

const projects = [
  {
    id: "r2d",
    name: "Research2Defense",
    tagline: "AI Security Research → Detection Engineering",
    desc: "Converts AI/LLM/agent security research papers into structured detection rules, analyst skill files, and telemetry gap analysis.",
    href: "/research-to-detection",
    github: "https://github.com/athulraju/Research2Defense",
    accent: "#8b7fd6",
    accentBorder: "border-[#8b7fd6]/25",
    accentBg: "bg-[#8b7fd6]/8",
    stack: ["Python", "FastAPI", "React"],
  },
  {
    id: "logforge",
    name: "LogForge AI",
    tagline: "Natural language → synthetic cloud audit logs",
    desc: "Generates realistic, schema-verified OCI, AWS, and Azure audit log timelines for detection testing, SIEM parser validation, and training.",
    href: "/agents/logforge",
    github: "https://github.com/athulraju/logforge-ai",
    accent: "#83d7b6",
    accentBorder: "border-[#83d7b6]/25",
    accentBg: "bg-[#83d7b6]/8",
    stack: ["Next.js", "TypeScript"],
  },
  {
    id: "minority-lens",
    name: "Minority Lens",
    tagline: "Finding signals in the rarest events.",
    desc: "A private research project born out of a year of graduate AI research. Not open source — reach out if you'd like a look.",
    href: "/agents/minority-lens",
    github: null,
    accent: "#d08a5d",
    accentBorder: "border-[#d08a5d]/25",
    accentBg: "bg-[#d08a5d]/8",
    stack: [],
  },
] as const;

export default function LabsPage() {
  return (
    <main className="min-h-screen">
      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 pt-20 pb-24 sm:pt-28">
        <PageHeader
          eyebrow="Labs"
          title="Standalone tools from AIThreatLab."
          description="Local-first, Ollama-powered AI agents — each its own open-source repo, independent of this site, built with the same verify-before-generate philosophy."
          accent="green"
        />

        <motion.div
          className="flex flex-wrap gap-2 mb-12"
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

        <motion.div
          className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5"
          variants={staggerContainer(0.08)}
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true }}
        >
          {projects.map((p) => (
            <motion.div key={p.id} variants={staggerItem} className="card-surface p-7 flex flex-col">
              <div className="flex items-center gap-2 mb-4">
                <FlaskConical className="w-4 h-4" style={{ color: p.accent }} />
                <span className="text-xs font-mono text-gray-600">{p.id}</span>
              </div>

              <h2 className="text-xl font-semibold text-white mb-1.5">{p.name}</h2>
              <p className="text-sm mb-4" style={{ color: p.accent }}>{p.tagline}</p>
              <p className="text-sm text-gray-500 leading-relaxed mb-5 flex-1">{p.desc}</p>

              <div className="flex flex-wrap gap-1.5 mb-6">
                {p.stack.map((s) => (
                  <Badge key={s} variant="gray" size="sm">{s}</Badge>
                ))}
              </div>

              <div className="flex gap-2.5">
                <Link
                  href={p.href}
                  className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-white/5 border border-white/10 text-gray-300 text-xs font-medium hover:bg-white/8 hover:border-white/18 transition-all"
                >
                  Learn more <ArrowRight className="w-3.5 h-3.5" />
                </Link>
                {p.github ? (
                  <a
                    href={p.github}
                    target="_blank"
                    rel="noopener noreferrer"
                    className={`inline-flex items-center gap-1.5 px-4 py-2 rounded-lg ${p.accentBg} border ${p.accentBorder} text-xs font-medium hover:brightness-110 transition-all`}
                    style={{ color: p.accent }}
                  >
                    GitHub <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                ) : (
                  <span className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-white/[0.02] border border-white/[0.06] text-gray-600 text-xs font-medium cursor-default">
                    Private
                  </span>
                )}
              </div>
            </motion.div>
          ))}
        </motion.div>

        <motion.div
          className="mt-14 pt-8 border-t border-white/[0.06] text-center"
          variants={fadeUp}
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true }}
        >
          <p className="text-xs text-gray-600">
            Research2Defense and LogForge AI are open source, self-hosted, and run entirely on your own machine against a local Ollama model.
            Minority Lens is a private project — reach out if you&apos;d like to see it.
          </p>
        </motion.div>
      </div>
    </main>
  );
}
