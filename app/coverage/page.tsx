"use client";

import { useState, useEffect, useRef } from "react";
import Link from "next/link";
import { motion, useInView, AnimatePresence } from "framer-motion";
import { PageHeader } from "@/components/PageHeader";
import { coverageData, coverageLayers, CoverageItem } from "@/lib/data/coverage";
import { maturityColor } from "@/lib/utils";
import { Brain, Download, Filter, BarChart3, CheckCircle2, AlertTriangle, ExternalLink, ChevronUp, ChevronDown, ChevronsUpDown } from "lucide-react";
import { staggerContainer, staggerItem } from "@/lib/motion";
import { detections } from "@/lib/data/detections/index";

const ease = [0.25, 0.1, 0.25, 1] as const;

const coverageTypeColor: Record<string, string> = {
  "rule-based": "text-cyan-400 bg-cyan-400/10 border-cyan-400/20",
  "ml-based":   "text-purple-400 bg-purple-400/10 border-purple-400/20",
  hybrid:       "text-blue-400 bg-blue-400/10 border-blue-400/20",
  planned:      "text-gray-500 bg-gray-500/10 border-gray-500/20",
};

// Count-up for stat cards
function useCountUp(target: number, duration = 1200) {
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

function StatCard({ label, value, color }: { label: string; value: number; color: string }) {
  const { ref, count } = useCountUp(value);
  return (
    <div ref={ref} className="card-surface p-4 text-center hover:bg-white/[0.06] transition-colors duration-200">
      <div className={`text-2xl font-bold ${color} mb-1 tabular-nums`}>{count}</div>
      <div className="text-xs text-gray-500">{label}</div>
    </div>
  );
}

function exportCSV() {
  const headers = ["ID","Name","Layer","Subcategory","Data Source","Platform","MITRE","Coverage Type","Maturity","AI Security","Detection Link"];
  const rows = coverageData.map((item) => [item.id, item.name, item.layer, item.subcategory, item.dataSource, item.platform, item.mitreTechnique, item.coverageType, item.maturity, item.aiSecurity ? "Yes" : "No", item.detectionId ? `/detections/${item.detectionId}` : ""]);
  const csv = [headers, ...rows].map((row) => row.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(",")).join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href = url; a.download = "detection-coverage.csv"; a.click();
  URL.revokeObjectURL(url);
}

type SortKey = "name" | "layer" | "platform" | "mitreTechnique" | "coverageType" | "maturity";
type SortDir = "asc" | "desc";

const maturityOrder: Record<string, number> = { production: 0, stable: 1, experimental: 2, planned: 3 };

function sortItems(items: CoverageItem[], key: SortKey, dir: SortDir): CoverageItem[] {
  return [...items].sort((a, b) => {
    let cmp: number;
    if (key === "maturity") {
      cmp = (maturityOrder[a.maturity] ?? 99) - (maturityOrder[b.maturity] ?? 99);
    } else {
      cmp = String(a[key]).localeCompare(String(b[key]));
    }
    return dir === "asc" ? cmp : -cmp;
  });
}

function MethodologyTab() {
  return (
    <motion.div
      initial={{ opacity: 0, y: 14 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease }}
    >
      <div className="card-surface p-8 max-w-3xl">
        <p className="text-xs font-medium text-purple-400 mb-3">
          Oracle Cloud Infrastructure Blog · Behind the Scenes with OCI Engineering
        </p>
        <h2 className="text-xl font-semibold text-white mb-2 leading-snug">
          Behind the Scenes: Beyond the Coverage Map—Measuring Cloud Detection Coverage
        </h2>
        <p className="text-xs text-gray-500 mb-5">Written by the author of this site, on the Oracle Cloud Infrastructure Blog.</p>
        <p className="text-sm text-gray-400 leading-relaxed mb-6">
          A piece on detection coverage measurement in cloud environments, published as part of
          Oracle&apos;s &quot;Behind the Scenes with OCI Engineering&quot; series. Read the full post for the
          detail — this page doesn&apos;t attempt to summarize its arguments.
        </p>
        <a
          href="https://blogs.oracle.com/cloud-infrastructure/behind-the-scenes-cloud-detection-coverage"
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] border border-white/10 text-sm text-gray-300 hover:text-white transition-all duration-200"
        >
          Read the full post
          <ExternalLink className="w-4 h-4" />
        </a>
      </div>
    </motion.div>
  );
}

export default function CoveragePage() {
  const [selectedLayer, setSelectedLayer] = useState<string>("All");
  const [showAiOnly,    setShowAiOnly]    = useState(false);
  const [sortKey,       setSortKey]       = useState<SortKey | null>(null);
  const [sortDir,       setSortDir]       = useState<SortDir>("asc");
  const [activeTab,     setActiveTab]     = useState<"map" | "methodology">("map");

  useEffect(() => { document.title = "Coverage Framework | AIDetectLab"; }, []);

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("asc");
    }
  };

  const maxBarTotal = Math.max(1, ...coverageLayers.map((layer) => coverageData.filter((i) => i.layer === layer).length));

  const baseFiltered = coverageData.filter((item) => {
    if (selectedLayer !== "All" && item.layer !== selectedLayer) return false;
    if (showAiOnly && !item.aiSecurity) return false;
    return true;
  });
  const filtered = sortKey ? sortItems(baseFiltered, sortKey, sortDir) : baseFiltered;

  const totalCount      = detections.length;
  const productionCount = coverageData.filter((i) => i.maturity === "production").length;
  const stableCount     = coverageData.filter((i) => i.maturity === "stable").length;
  const aiCount         = coverageData.filter((i) => i.aiSecurity).length;
  const gapCount        = coverageData.filter((i) => i.maturity === "planned").length;

  return (
    <div className="min-h-screen">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
        <div className="flex items-start justify-between mb-8">
          <PageHeader
            eyebrow="Coverage Framework"
            title="Detection Coverage Map"
            description="Structured visibility across 8 detection layers with MITRE mapping and maturity tracking."
            className="mb-0"
            accent="purple"
          />
          <motion.button
            onClick={exportCSV}
            className="hidden sm:flex items-center gap-2 px-4 py-2 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] border border-white/10 text-sm text-gray-400 hover:text-white transition-all mt-1 hover:-translate-y-0.5 duration-200"
            whileTap={{ scale: 0.97 }}
          >
            <Download className="w-4 h-4" />
            Export CSV
          </motion.button>
        </div>

        {/* Tabs */}
        <div className="flex items-center gap-1 mb-8 border-b border-white/[0.06]">
          {([
            { id: "map" as const, label: "Coverage Map" },
            { id: "methodology" as const, label: "Methodology" },
          ]).map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`relative px-4 py-2.5 text-sm font-medium transition-colors duration-200 ${
                activeTab === tab.id ? "text-white" : "text-gray-500 hover:text-gray-300"
              }`}
            >
              {tab.label}
              {activeTab === tab.id && (
                <motion.div layoutId="coverage-tab" className="absolute inset-x-0 -bottom-px h-0.5 bg-cyan-400" transition={{ duration: 0.2, ease }} />
              )}
            </button>
          ))}
        </div>

        {activeTab === "methodology" && <MethodologyTab />}

        {activeTab === "map" && <>

        {/* Summary Stats with count-up */}
        <motion.div
          className="grid grid-cols-2 sm:grid-cols-5 gap-3 mb-8"
          variants={staggerContainer(0.06)}
          initial="hidden"
          animate="visible"
        >
          {[
            { label: "Total Detections", value: totalCount,      color: "text-white" },
            { label: "Production",        value: productionCount, color: "text-emerald-400" },
            { label: "Stable",            value: stableCount,     color: "text-cyan-400" },
            { label: "AI Security",       value: aiCount,         color: "text-purple-400" },
            { label: "Coverage Gaps",     value: gapCount,        color: "text-orange-400" },
          ].map((stat, i) => (
            <motion.div key={stat.label} variants={staggerItem}>
              <StatCard {...stat} />
            </motion.div>
          ))}
        </motion.div>

        {/* Layer Bar Chart */}
        <motion.div
          className="card-surface p-6 mb-8"
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, ease, delay: 0.2 }}
        >
          <div className="flex items-center gap-2 mb-5">
            <BarChart3 className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-semibold text-white">Coverage by Layer</h2>
          </div>
          <div className="space-y-3">
            {coverageLayers.map((layer, i) => {
              const layerItems = coverageData.filter((it) => it.layer === layer);
              const prod  = layerItems.filter((it) => it.maturity === "production").length;
              const stable = layerItems.filter((it) => it.maturity === "stable").length;
              const exp   = layerItems.filter((it) => it.maturity === "experimental").length;
              const plan  = layerItems.filter((it) => it.maturity === "planned").length;
              const total = layerItems.length;
              const pct   = (n: number) => `${(n / maxBarTotal) * 100}%`;

              return (
                <div key={layer} className="flex items-center gap-3">
                  <span className="text-xs text-gray-500 w-40 flex-shrink-0">{layer}</span>
                  <div className="flex-1 flex rounded-full overflow-hidden bg-white/[0.04] h-3">
                    {[
                      { n: prod,  cls: "bg-emerald-500", label: "Production" },
                      { n: stable, cls: "bg-cyan-500",   label: "Stable" },
                      { n: exp,   cls: "bg-purple-500",  label: "Experimental" },
                      { n: plan,  cls: "bg-gray-600",    label: "Planned" },
                    ].map(({ n, cls, label }) =>
                      n > 0 ? (
                        <motion.div
                          key={label}
                          className={`${cls} h-full`}
                          title={`${label}: ${n}`}
                          style={{ width: pct(n) }}
                          initial={{ scaleX: 0, originX: 0 }}
                          whileInView={{ scaleX: 1, originX: 0 }}
                          viewport={{ once: true }}
                          transition={{ duration: 0.65, ease, delay: 0.1 + i * 0.04 }}
                        />
                      ) : null
                    )}
                  </div>
                  <span className="text-xs text-gray-600 w-4">{total}</span>
                </div>
              );
            })}
          </div>
          <div className="flex items-center gap-4 mt-4">
            {[
              { color: "bg-emerald-500", label: "Production" },
              { color: "bg-cyan-500",    label: "Stable" },
              { color: "bg-purple-500",  label: "Experimental" },
              { color: "bg-gray-600",    label: "Planned" },
            ].map((l) => (
              <div key={l.label} className="flex items-center gap-1.5">
                <span className={`w-2 h-2 rounded-full ${l.color}`} />
                <span className="text-xs text-gray-500">{l.label}</span>
              </div>
            ))}
          </div>
        </motion.div>

        {/* Filters */}
        <motion.div
          className="flex flex-wrap items-center gap-2 mb-6"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.3, ease, delay: 0.3 }}
        >
          <Filter className="w-3.5 h-3.5 text-gray-600" />
          {["All", ...coverageLayers].map((layer) => (
            <button
              key={layer}
              onClick={() => setSelectedLayer(layer)}
              className={`relative px-3 py-1 rounded-md text-xs font-medium border transition-colors duration-200 ${
                selectedLayer === layer
                  ? "bg-white/10 border-white/20 text-white"
                  : "bg-transparent border-white/10 text-gray-500 hover:text-gray-300"
              }`}
            >
              {selectedLayer === layer && (
                <motion.div layoutId="layer-filter" className="absolute inset-0 bg-white/10 rounded-md" transition={{ duration: 0.2, ease }} />
              )}
              <span className="relative">{layer === "All" ? "All Layers" : layer}</span>
            </button>
          ))}
          <button
            onClick={() => setShowAiOnly(!showAiOnly)}
            className={`flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium border transition-all duration-200 ml-2 ${
              showAiOnly
                ? "bg-purple-500/10 border-purple-500/20 text-purple-400"
                : "bg-transparent border-white/10 text-gray-500 hover:text-gray-300"
            }`}
          >
            <Brain className="w-3 h-3" />
            AI Security Only
          </button>
        </motion.div>

        {/* Coverage Table */}
        <motion.div
          className="card-surface overflow-hidden"
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, ease, delay: 0.35 }}
        >
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-white/[0.06]">
                  {([
                    { label: "Detection",     key: "name"          as SortKey },
                    { label: "Layer",         key: "layer"         as SortKey },
                    { label: "Data Source",   key: null },
                    { label: "Platform",      key: "platform"      as SortKey },
                    { label: "MITRE",         key: "mitreTechnique"as SortKey },
                    { label: "Coverage Type", key: "coverageType"  as SortKey },
                    { label: "Maturity",      key: "maturity"      as SortKey },
                    { label: "AI",            key: null },
                  ] as const).map(({ label, key }) => (
                    <th
                      key={label}
                      className={`px-4 py-3 text-left text-xs font-medium uppercase tracking-wider whitespace-nowrap select-none ${
                        key ? "text-gray-500 hover:text-gray-300 cursor-pointer transition-colors duration-150" : "text-gray-500"
                      }`}
                      onClick={key ? () => handleSort(key) : undefined}
                    >
                      <span className="flex items-center gap-1">
                        {label}
                        {key && (
                          sortKey === key
                            ? sortDir === "asc"
                              ? <ChevronUp className="w-3 h-3 text-cyan-400" />
                              : <ChevronDown className="w-3 h-3 text-cyan-400" />
                            : <ChevronsUpDown className="w-3 h-3 opacity-30" />
                        )}
                      </span>
                    </th>
                  ))}
                </tr>
              </thead>
              <AnimatePresence mode="wait">
                <motion.tbody
                  key={`${selectedLayer}-${showAiOnly}-${sortKey}-${sortDir}`}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.18 }}
                >
                  {filtered.map((item) => (
                    <tr
                      key={item.id}
                      className={`border-b border-white/[0.04] hover:bg-white/[0.02] transition-colors duration-100 ${item.maturity === "planned" ? "opacity-50" : ""}`}
                    >
                      <td className="px-4 py-3">
                        {item.detectionId ? (
                          <Link href={`/detections/${item.detectionId}`} className="group/link block">
                            <div className="flex items-start gap-1.5">
                              <div>
                                <p className="text-white font-medium mb-0.5 group-hover/link:text-cyan-300 transition-colors">{item.name}</p>
                                <p className="text-gray-600 text-xs">{item.subcategory}</p>
                              </div>
                              <ExternalLink className="w-3 h-3 text-gray-700 group-hover/link:text-cyan-400 flex-shrink-0 mt-0.5 transition-colors" />
                            </div>
                          </Link>
                        ) : (
                          <div>
                            <p className="text-white font-medium mb-0.5">{item.name}</p>
                            <p className="text-gray-600 text-xs">{item.subcategory}</p>
                          </div>
                        )}
                      </td>
                      <td className="px-4 py-3 text-gray-400 whitespace-nowrap">{item.layer}</td>
                      <td className="px-4 py-3 text-gray-500 max-w-[160px] truncate" title={item.dataSource}>{item.dataSource}</td>
                      <td className="px-4 py-3 text-gray-400 whitespace-nowrap">{item.platform}</td>
                      <td className="px-4 py-3"><span className="font-mono text-gray-500">{item.mitreTechnique}</span></td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center text-xs font-medium border rounded px-2 py-0.5 ${coverageTypeColor[item.coverageType]}`}>{item.coverageType}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center text-xs font-medium border rounded px-2 py-0.5 ${maturityColor(item.maturity)}`}>{item.maturity}</span>
                      </td>
                      <td className="px-4 py-3 text-center">
                        {item.aiSecurity ? <Brain className="w-3.5 h-3.5 text-purple-400 mx-auto" /> : <span className="text-gray-700">-</span>}
                      </td>
                    </tr>
                  ))}
                </motion.tbody>
              </AnimatePresence>
            </table>
          </div>
        </motion.div>

        {/* Gaps Section */}
        <motion.div
          className="mt-8 card-surface p-6"
          initial={{ opacity: 0, y: 14 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.4, ease }}
        >
          <div className="flex items-center gap-2 mb-4">
            <AlertTriangle className="w-4 h-4 text-orange-400" />
            <h2 className="text-sm font-semibold text-white">Coverage Gaps</h2>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {[
              { title: "macOS Endpoint Coverage",       desc: "Limited detection coverage for macOS-specific threats. Priority area for expansion.", severity: "high" },
              { title: "Container / Kubernetes Layer",   desc: "No dedicated container runtime or Kubernetes audit log detections in current framework.", severity: "high" },
              { title: "LLM Output Monitoring",          desc: "DLP integration for monitoring LLM response content not yet implemented.", severity: "medium" },
            ].map((gap, i) => (
              <motion.div
                key={gap.title}
                className="bg-orange-400/[0.04] border border-orange-400/10 rounded-lg p-4 hover:bg-orange-400/[0.07] hover:border-orange-400/20 transition-all duration-200"
                initial={{ opacity: 0, y: 10 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.35, ease, delay: i * 0.07 }}
              >
                <div className="flex items-start gap-2">
                  <AlertTriangle className="w-3.5 h-3.5 text-orange-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="text-sm font-medium text-white mb-1">{gap.title}</p>
                    <p className="text-xs text-gray-500">{gap.desc}</p>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        </motion.div>

        {/* Attribution */}
        <motion.div
          className="mt-8 flex items-center gap-3 px-4 py-3.5 rounded-lg border border-white/[0.06] bg-white/[0.02]"
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.4, ease }}
        >
          <CheckCircle2 className="w-3.5 h-3.5 text-gray-600 flex-shrink-0" />
          <p className="text-xs text-gray-600">
            Detection layer taxonomy informed by{" "}
            <a
              href="https://blogs.oracle.com/cloud-infrastructure/behind-the-scenes-logonomics"
              target="_blank"
              rel="noopener noreferrer"
              className="text-gray-500 hover:text-gray-300 underline underline-offset-2 transition-colors inline-flex items-center gap-1"
            >
              Behind the Scenes: Logonomics
              <ExternalLink className="w-3 h-3" />
            </a>
            {" "}— Oracle Cloud Infrastructure Blog.
          </p>
        </motion.div>

        </>}

      </div>
    </div>
  );
}
