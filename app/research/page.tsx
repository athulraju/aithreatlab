"use client";

import { useState, useEffect } from "react";
import { PageHeader } from "@/components/PageHeader";
import { researchSections, sectionColors, sourceColors } from "@/lib/data/research";
import { ExternalLink } from "lucide-react";

export default function ResearchPage() {
  const [activeSection, setActiveSection] = useState<string>("all");
  useEffect(() => { document.title = "Research — AIDetectLab"; }, []);

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
        <div className="flex flex-wrap gap-2 mb-10">
          <button
            onClick={() => setActiveSection("all")}
            className={`px-3 py-1.5 rounded-md text-xs font-medium border transition-all ${
              activeSection === "all"
                ? "bg-white/10 border-white/20 text-white"
                : "bg-transparent border-white/[0.08] text-gray-500 hover:text-gray-300 hover:border-white/15"
            }`}
          >
            All
          </button>
          {researchSections.map((section) => (
            <button
              key={section.id}
              onClick={() => setActiveSection(section.id)}
              className={`px-3 py-1.5 rounded-md text-xs font-medium border transition-all ${
                activeSection === section.id
                  ? "bg-white/10 border-white/20 text-white"
                  : "bg-transparent border-white/[0.08] text-gray-500 hover:text-gray-300 hover:border-white/15"
              }`}
            >
              {section.title}
            </button>
          ))}
        </div>

        {/* Sections */}
        <div className="space-y-10">
          {visibleSections.map((section) => (
            <div key={section.id}>
              {/* Section header */}
              <div className="flex items-center gap-3 mb-4">
                <span
                  className={`inline-flex items-center text-xs font-semibold border rounded px-2.5 py-1 ${
                    sectionColors[section.id] ?? "text-gray-400 bg-white/5 border-white/10"
                  }`}
                >
                  {section.title}
                </span>
                <span className="text-xs text-gray-600">{section.links.length} references</span>
              </div>

              {/* Paper list */}
              <div className="space-y-2">
                {section.links.map((link, i) => (
                  <a
                    key={i}
                    href={link.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="block card-surface-hover p-4 group"
                  >
                    <div className="flex items-start gap-3">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-start gap-2 mb-1">
                          <h3 className="text-sm font-medium text-white group-hover:text-cyan-300 transition-colors leading-snug flex-1">
                            {link.title}
                          </h3>
                          <ExternalLink className="w-3.5 h-3.5 text-gray-600 group-hover:text-cyan-400 flex-shrink-0 mt-0.5 transition-colors" />
                        </div>
                        <div className="flex items-center gap-2 mb-1.5">
                          <span
                            className={`inline-flex items-center text-xs border rounded px-1.5 py-0.5 ${
                              sourceColors[link.source] ?? "text-gray-500 bg-white/5 border-white/10"
                            }`}
                          >
                            {link.source}
                          </span>
                        </div>
                        <p className="text-xs text-gray-500 leading-relaxed">
                          {link.description}
                        </p>
                      </div>
                    </div>
                  </a>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
