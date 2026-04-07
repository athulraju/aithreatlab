"use client";

import { useState, useMemo, useEffect } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/PageHeader";
import { Badge } from "@/components/Badge";
import {
  detections,
  categories,
  platforms,
  maturityLevels,
} from "@/lib/data/detections/index";
import { severityColor, maturityColor, platformColor, cn } from "@/lib/utils";
import { Search, ChevronRight, Filter } from "lucide-react";

export default function DetectionsPage() {
  const [query, setQuery] = useState("");
  const [selectedCategory, setSelectedCategory] = useState("All");
  const [selectedPlatform, setSelectedPlatform] = useState("All");
  const [selectedMaturity, setSelectedMaturity] = useState("All");

  useEffect(() => { document.title = "Detection Library | AIDetectLab"; }, []);

  const filtered = useMemo(() => {
    return detections.filter((d) => {
      const q = query.toLowerCase();
      const matchesQuery =
        !q ||
        d.title.toLowerCase().includes(q) ||
        d.description.toLowerCase().includes(q) ||
        d.tags.some((t) => t.includes(q)) ||
        d.mitre.some((m) => m.toLowerCase().includes(q));

      const matchesCategory =
        selectedCategory === "All" || d.category === selectedCategory;
      const matchesPlatform =
        selectedPlatform === "All" ||
        d.platform.some((p) => p === selectedPlatform);
      const matchesMaturity =
        selectedMaturity === "All" || d.maturity === selectedMaturity;

      return matchesQuery && matchesCategory && matchesPlatform && matchesMaturity;
    });
  }, [query, selectedCategory, selectedPlatform, selectedMaturity]);

  return (
    <div className="pt-14 min-h-screen">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
        <PageHeader
          eyebrow="Detection Library"
          title="Detection Knowledge Base"
          description="Searchable library of production-grade detections with full logic, tuning guidance, and deployment notes."
          accent="blue"
        />

        {/* Search + Filters */}
        <div className="flex flex-col md:flex-row gap-3 mb-8">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input
              type="text"
              placeholder="Search detections, MITRE IDs, tags..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="w-full pl-9 pr-4 py-2.5 bg-white/[0.04] border border-white/10 rounded-lg text-sm text-white placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:bg-white/[0.06] transition-all"
            />
          </div>

          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="px-3 py-2.5 bg-white/[0.04] border border-white/10 rounded-lg text-sm text-gray-300 focus:outline-none focus:border-white/20 transition-all"
          >
            {categories.map((c) => (
              <option key={c} value={c} className="bg-[#0e0e1a]">
                {c}
              </option>
            ))}
          </select>

          <select
            value={selectedPlatform}
            onChange={(e) => setSelectedPlatform(e.target.value)}
            className="px-3 py-2.5 bg-white/[0.04] border border-white/10 rounded-lg text-sm text-gray-300 focus:outline-none focus:border-white/20 transition-all"
          >
            {platforms.map((p) => (
              <option key={p} value={p} className="bg-[#0e0e1a]">
                {p}
              </option>
            ))}
          </select>

          <select
            value={selectedMaturity}
            onChange={(e) => setSelectedMaturity(e.target.value)}
            className="px-3 py-2.5 bg-white/[0.04] border border-white/10 rounded-lg text-sm text-gray-300 focus:outline-none focus:border-white/20 transition-all"
          >
            {maturityLevels.map((m) => (
              <option key={m} value={m} className="bg-[#0e0e1a] capitalize">
                {m}
              </option>
            ))}
          </select>
        </div>

        {/* Result count */}
        <p className="text-xs text-gray-600 mb-5">
          {filtered.length} detection{filtered.length !== 1 ? "s" : ""}
        </p>

        {/* Detection Cards */}
        <div className="space-y-3">
          {filtered.map((detection) => (
            <Link
              key={detection.id}
              href={`/detections/${detection.id}`}
              className="block card-surface-hover p-5 group"
            >
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap mb-2">
                    <h3 className="text-sm font-semibold text-white group-hover:text-cyan-300 transition-colors">
                      {detection.title}
                    </h3>
                    <span
                      className={`inline-flex items-center text-xs font-medium border rounded px-2 py-0.5 ${severityColor(detection.severity)}`}
                    >
                      {detection.severity}
                    </span>
                  </div>

                  <p className="text-xs text-gray-500 mb-3 line-clamp-2">
                    {detection.description}
                  </p>

                  <div className="flex items-center gap-2 flex-wrap">
                    <span
                      className={`inline-flex items-center text-xs font-medium border rounded px-2 py-0.5 ${maturityColor(detection.maturity)}`}
                    >
                      {detection.maturity}
                    </span>

                    {detection.platform.slice(0, 2).map((p) => (
                      <span
                        key={p}
                        className={`inline-flex items-center text-xs font-medium border rounded px-2 py-0.5 ${platformColor(p)}`}
                      >
                        {p}
                      </span>
                    ))}

                    {detection.mitre.slice(0, 2).map((m) => (
                      <span
                        key={m}
                        className="inline-flex items-center text-xs font-mono text-gray-500 bg-white/[0.03] border border-white/[0.06] rounded px-2 py-0.5"
                      >
                        {m}
                      </span>
                    ))}

                    <span className="text-xs text-gray-600">{detection.category}</span>
                  </div>
                </div>

                <ChevronRight className="w-4 h-4 text-gray-600 group-hover:text-cyan-400 flex-shrink-0 mt-0.5 transition-colors" />
              </div>
            </Link>
          ))}

          {filtered.length === 0 && (
            <div className="text-center py-16 text-gray-600">
              <Filter className="w-8 h-8 mx-auto mb-3 opacity-30" />
              <p className="text-sm text-gray-500 mb-1">No detections match your current filters.</p>
              <p className="text-xs text-gray-600">
                Try clearing the category or platform filter, or search by a different term.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
