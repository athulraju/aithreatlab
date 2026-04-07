"use client";

import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { PageHeader } from "@/components/PageHeader";
import { researchSections, sectionColors, sourceColors } from "@/lib/data/research";
import { ExternalLink } from "lucide-react";

const ease = [0.25, 0.1, 0.25, 1] as const;

export default function ResearchPage() {
  const [activeSection, setActiveSection] = useState<string>("all");
  useEffect(() => { document.title = "Research | AIDetectLab"; }, []);

  const visibleSections =
    activeSection === "all"
      ? researchSections
      : researchSections.filter((s) => s.id === activeSection);

  return (
    <div className="pt-14 min-h-screen">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
        <PageHeader
          eyebrow="Research"
          title="Research Reference"
          description="Curated papers, reports, and resources across AI security, agentic AI, detection engineering, and LLM security."
          accent="gray"
        />

        {/* Section filter tabs */}
        <motion.div
          className="flex flex-wrap gap-2 mb-10"
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.35, ease, delay: 0.15 }}
        >
          {["all", ...researchSections.map((s) => s.id)].map((id) => {
            const label = id === "all" ? "All" : researchSections.find((s) => s.id === id)?.title ?? id;
            const isActive = activeSection === id;
            return (
              <button
                key={id}
                onClick={() => setActiveSection(id)}
                className={`relative px-3 py-1.5 rounded-md text-xs font-medium border transition-colors duration-200 ${
                  isActive
                    ? "bg-white/10 border-white/20 text-white"
                    : "bg-transparent border-white/[0.08] text-gray-500 hover:text-gray-300 hover:border-white/15"
                }`}
              >
                {isActive && (
                  <motion.div
                    layoutId="research-filter"
                    className="absolute inset-0 bg-white/10 rounded-md"
                    transition={{ duration: 0.2, ease }}
                  />
                )}
                <span className="relative">{label}</span>
              </button>
            );
          })}
        </motion.div>

        {/* Sections — crossfade (no mode="wait") to avoid long full-page exit/enter cycle */}
        <AnimatePresence>
          <motion.div
            key={activeSection}
            className="space-y-10"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0, position: "absolute" } as any}
            transition={{ duration: 0.18 }}
          >
            {visibleSections.map((section, si) => (
              <motion.div
                key={section.id}
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.35, ease, delay: si * 0.06 }}
              >
                <div className="flex items-center gap-3 mb-4">
                  <span className={`inline-flex items-center text-xs font-semibold border rounded px-2.5 py-1 ${
                    sectionColors[section.id] ?? "text-gray-400 bg-white/5 border-white/10"
                  }`}>
                    {section.title}
                  </span>
                  <span className="text-xs text-gray-600">{section.links.length} references</span>
                </div>

                <div className="space-y-2">
                  {section.links.map((link, i) => (
                    <motion.a
                      key={i}
                      href={link.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="block card-surface-hover p-4 group"
                      initial={{ opacity: 0, y: 8 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ duration: 0.3, ease, delay: si * 0.04 + i * 0.03 }}
                    >
                      <div className="flex items-start gap-3">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-start gap-2 mb-1">
                            <h3 className="text-sm font-medium text-white group-hover:text-cyan-300 transition-colors duration-200 leading-snug flex-1">
                              {link.title}
                            </h3>
                            <ExternalLink className="w-3.5 h-3.5 text-gray-600 group-hover:text-cyan-400 flex-shrink-0 mt-0.5 transition-colors" />
                          </div>
                          <div className="flex items-center gap-2 mb-1.5">
                            <span className={`inline-flex items-center text-xs border rounded px-1.5 py-0.5 ${
                              sourceColors[link.source] ?? "text-gray-500 bg-white/5 border-white/10"
                            }`}>
                              {link.source}
                            </span>
                          </div>
                          <p className="text-xs text-gray-500 leading-relaxed">{link.description}</p>
                        </div>
                      </div>
                    </motion.a>
                  ))}
                </div>
              </motion.div>
            ))}
          </motion.div>
        </AnimatePresence>
      </div>
    </div>
  );
}
