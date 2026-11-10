"use client";

import { motion } from "framer-motion";
import { fadeUp, staggerContainer, staggerItem } from "@/lib/motion";
import { Linkedin, Lock, Network, Shuffle, MessageCircleQuestion } from "lucide-react";

const ease = [0.25, 0.1, 0.25, 1] as const;

const LINKEDIN_URL = "https://www.linkedin.com/in/athul-raju-38745552";

const curiosities = [
  {
    icon: Shuffle,
    title: "Not all AI systems are equal",
    desc: "A chatbot with no tool access and an autonomous agent with database write permissions aren't the same threat model, even though most scanners still treat them like they are.",
  },
  {
    icon: Network,
    title: "It's the wiring, not the parts",
    desc: "The interesting failures tend to live in how components connect, trust each other, and hand off control, not in any single piece examined alone.",
  },
  {
    icon: Lock,
    title: "Kept close for now",
    desc: "It's private while it's being built out. No public repo, no demo link here, just an invitation to talk about it.",
  },
];

export default function BlastRadiusAboutPage() {
  return (
    <main className="min-h-screen">
      {/* ── HERO ──────────────────────────────────────────────────────── */}
      <section className="pt-24 pb-20 sm:pt-32 sm:pb-24">
        <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <motion.div
            className="flex flex-wrap justify-center gap-2 mb-8"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, ease }}
          >
            {[
              { icon: Lock, label: "Private Project" },
              { icon: Network, label: "AI Security" },
            ].map(({ icon: Icon, label }) => (
              <span
                key={label}
                className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full border border-[#e0625f]/25 bg-[#e0625f]/8 text-[#e0625f] text-[11px] font-semibold uppercase tracking-widest"
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
            Blast Radius
          </motion.h1>

          <motion.p
            className="text-lg text-[#e0625f] font-medium mb-6"
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.45, ease, delay: 0.14 }}
          >
            The architecture is the attack surface.
          </motion.p>

          <motion.p
            className="text-base text-gray-400 leading-relaxed max-w-xl mx-auto mb-10"
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.45, ease, delay: 0.2 }}
          >
            A private research project exploring how an AI system&apos;s own design, not just its
            code, decides how much damage a single compromised piece can do. Not public, by
            design. If it sounds interesting, I&apos;d rather tell you about it directly.
          </motion.p>

          <motion.div
            className="flex flex-wrap justify-center gap-3"
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, ease, delay: 0.28 }}
          >
            <a
              href={LINKEDIN_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 px-6 py-3 rounded-xl bg-[#e0625f]/15 border border-[#e0625f]/30 text-[#e0625f] text-sm font-semibold hover:bg-[#e0625f]/22 hover:border-[#e0625f]/45 active:scale-[0.98] transition-all"
            >
              <Linkedin className="w-4 h-4" />
              Reach out to request a look
            </a>
          </motion.div>
        </div>
      </section>

      {/* ── CURIOSITY CARDS ───────────────────────────────────────────── */}
      <section className="py-12 border-t border-white/[0.06]">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div className="grid grid-cols-1 sm:grid-cols-3 gap-4" variants={staggerContainer(0.08)} initial="hidden" whileInView="visible" viewport={{ once: true }}>
            {curiosities.map((c) => (
              <motion.div key={c.title} variants={staggerItem} className="card-surface p-5">
                <c.icon className="w-4 h-4 mb-3 text-[#e0625f]" />
                <h3 className="text-sm font-semibold text-white mb-1.5">{c.title}</h3>
                <p className="text-xs text-gray-500 leading-relaxed">{c.desc}</p>
              </motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* ── CLOSING CTA ───────────────────────────────────────────────── */}
      <section className="py-16 border-t border-white/[0.06]">
        <div className="max-w-2xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <motion.div variants={fadeUp} initial="hidden" whileInView="visible" viewport={{ once: true }}>
            <div className="flex items-center justify-center gap-2 mb-3">
              <MessageCircleQuestion className="w-4 h-4 text-[#e0625f]" />
              <span className="text-xs font-semibold uppercase tracking-widest text-[#e0625f]">Want to see it?</span>
            </div>
            <p className="text-sm text-gray-500 leading-relaxed mb-6">
              Blast Radius isn&apos;t open source and there&apos;s no public demo link. If you
              work on AI security design reviews or threat modeling, or you&apos;re just curious,
              the fastest way to find out more is to message me directly.
            </p>
            <a
              href={LINKEDIN_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2.5 px-7 py-3 rounded-xl bg-[#e0625f]/15 border border-[#e0625f]/30 text-[#e0625f] text-sm font-semibold hover:bg-[#e0625f]/22 hover:border-[#e0625f]/45 active:scale-[0.98] transition-all"
            >
              <Linkedin className="w-4 h-4" />
              Connect on LinkedIn
            </a>
          </motion.div>
        </div>
      </section>
    </main>
  );
}
