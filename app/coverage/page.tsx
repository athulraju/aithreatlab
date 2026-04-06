"use client";

import { useState } from "react";
import { PageHeader } from "@/components/PageHeader";
import { coverageData, coverageLayers, CoverageItem } from "@/lib/data/coverage";
import { maturityColor } from "@/lib/utils";
import { Brain, Download, Filter, BarChart3, CheckCircle2, AlertTriangle } from "lucide-react";

const coverageTypeColor: Record<string, string> = {
  "rule-based": "text-cyan-400 bg-cyan-400/10 border-cyan-400/20",
  "ml-based": "text-purple-400 bg-purple-400/10 border-purple-400/20",
  hybrid: "text-blue-400 bg-blue-400/10 border-blue-400/20",
  planned: "text-gray-500 bg-gray-500/10 border-gray-500/20",
};

export default function CoveragePage() {
  const [selectedLayer, setSelectedLayer] = useState<string>("All");
  const [showAiOnly, setShowAiOnly] = useState(false);

  const filtered = coverageData.filter((item) => {
    if (selectedLayer !== "All" && item.layer !== selectedLayer) return false;
    if (showAiOnly && !item.aiSecurity) return false;
    return true;
  });

  const totalCount = coverageData.length;
  const productionCount = coverageData.filter((i) => i.maturity === "production").length;
  const stableCount = coverageData.filter((i) => i.maturity === "stable").length;
  const aiCount = coverageData.filter((i) => i.aiSecurity).length;
  const gapCount = coverageData.filter((i) => i.maturity === "planned").length;

  return (
    <div className="pt-14 min-h-screen">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
        <div className="flex items-start justify-between mb-8">
          <PageHeader
            eyebrow="Coverage Framework"
            title="Detection Coverage Map"
            description="Structured visibility across 8 detection layers with MITRE mapping and maturity tracking."
            className="mb-0"
          />
          <button className="hidden sm:flex items-center gap-2 px-4 py-2 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] border border-white/10 text-sm text-gray-400 hover:text-white transition-all mt-1">
            <Download className="w-4 h-4" />
            Export CSV
          </button>
        </div>

        {/* Summary Stats */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mb-8">
          {[
            { label: "Total Detections", value: totalCount, color: "text-white" },
            { label: "Production", value: productionCount, color: "text-emerald-400" },
            { label: "Stable", value: stableCount, color: "text-cyan-400" },
            { label: "AI Security", value: aiCount, color: "text-purple-400" },
            { label: "Coverage Gaps", value: gapCount, color: "text-orange-400" },
          ].map((stat) => (
            <div key={stat.label} className="card-surface p-4 text-center">
              <div className={`text-2xl font-bold ${stat.color} mb-1`}>{stat.value}</div>
              <div className="text-xs text-gray-500">{stat.label}</div>
            </div>
          ))}
        </div>

        {/* Layer Bar Chart */}
        <div className="card-surface p-6 mb-8">
          <div className="flex items-center gap-2 mb-5">
            <BarChart3 className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-semibold text-white">Coverage by Layer</h2>
          </div>
          <div className="space-y-3">
            {coverageLayers.map((layer) => {
              const layerItems = coverageData.filter((i) => i.layer === layer);
              const prod = layerItems.filter((i) => i.maturity === "production").length;
              const stable = layerItems.filter((i) => i.maturity === "stable").length;
              const exp = layerItems.filter((i) => i.maturity === "experimental").length;
              const plan = layerItems.filter((i) => i.maturity === "planned").length;
              const total = layerItems.length;
              const maxTotal = 5;

              return (
                <div key={layer} className="flex items-center gap-3">
                  <span className="text-xs text-gray-500 w-40 flex-shrink-0">{layer}</span>
                  <div className="flex-1 flex rounded-full overflow-hidden bg-white/[0.04] h-3">
                    {prod > 0 && (
                      <div
                        className="bg-emerald-500 h-full"
                        style={{ width: `${(prod / maxTotal) * 100}%` }}
                        title={`Production: ${prod}`}
                      />
                    )}
                    {stable > 0 && (
                      <div
                        className="bg-cyan-500 h-full"
                        style={{ width: `${(stable / maxTotal) * 100}%` }}
                        title={`Stable: ${stable}`}
                      />
                    )}
                    {exp > 0 && (
                      <div
                        className="bg-purple-500 h-full"
                        style={{ width: `${(exp / maxTotal) * 100}%` }}
                        title={`Experimental: ${exp}`}
                      />
                    )}
                    {plan > 0 && (
                      <div
                        className="bg-gray-600 h-full"
                        style={{ width: `${(plan / maxTotal) * 100}%` }}
                        title={`Planned: ${plan}`}
                      />
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
              { color: "bg-cyan-500", label: "Stable" },
              { color: "bg-purple-500", label: "Experimental" },
              { color: "bg-gray-600", label: "Planned" },
            ].map((l) => (
              <div key={l.label} className="flex items-center gap-1.5">
                <span className={`w-2 h-2 rounded-full ${l.color}`} />
                <span className="text-xs text-gray-500">{l.label}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-2 mb-6">
          <Filter className="w-3.5 h-3.5 text-gray-600" />
          <button
            onClick={() => setSelectedLayer("All")}
            className={`px-3 py-1 rounded-md text-xs font-medium border transition-all ${
              selectedLayer === "All"
                ? "bg-white/10 border-white/20 text-white"
                : "bg-transparent border-white/10 text-gray-500 hover:text-gray-300"
            }`}
          >
            All Layers
          </button>
          {coverageLayers.map((layer) => (
            <button
              key={layer}
              onClick={() => setSelectedLayer(layer)}
              className={`px-3 py-1 rounded-md text-xs font-medium border transition-all ${
                selectedLayer === layer
                  ? "bg-white/10 border-white/20 text-white"
                  : "bg-transparent border-white/10 text-gray-500 hover:text-gray-300"
              }`}
            >
              {layer}
            </button>
          ))}
          <button
            onClick={() => setShowAiOnly(!showAiOnly)}
            className={`flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium border transition-all ml-2 ${
              showAiOnly
                ? "bg-purple-500/10 border-purple-500/20 text-purple-400"
                : "bg-transparent border-white/10 text-gray-500 hover:text-gray-300"
            }`}
          >
            <Brain className="w-3 h-3" />
            AI Security Only
          </button>
        </div>

        {/* Coverage Table */}
        <div className="card-surface overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-white/[0.06]">
                  {[
                    "Detection",
                    "Layer",
                    "Data Source",
                    "Platform",
                    "MITRE",
                    "Coverage Type",
                    "Maturity",
                    "AI",
                  ].map((col) => (
                    <th
                      key={col}
                      className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap"
                    >
                      {col}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map((item, i) => (
                  <tr
                    key={item.id}
                    className={`border-b border-white/[0.04] hover:bg-white/[0.02] transition-colors ${
                      item.maturity === "planned" ? "opacity-50" : ""
                    }`}
                  >
                    <td className="px-4 py-3">
                      <div>
                        <p className="text-white font-medium mb-0.5">{item.name}</p>
                        <p className="text-gray-600 text-xs">{item.subcategory}</p>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-gray-400 whitespace-nowrap">{item.layer}</td>
                    <td className="px-4 py-3 text-gray-500 max-w-[160px] truncate" title={item.dataSource}>
                      {item.dataSource}
                    </td>
                    <td className="px-4 py-3 text-gray-400 whitespace-nowrap">{item.platform}</td>
                    <td className="px-4 py-3">
                      <span className="font-mono text-gray-500">{item.mitreTechnique}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`inline-flex items-center text-xs font-medium border rounded px-2 py-0.5 ${coverageTypeColor[item.coverageType]}`}
                      >
                        {item.coverageType}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`inline-flex items-center text-xs font-medium border rounded px-2 py-0.5 ${maturityColor(item.maturity)}`}
                      >
                        {item.maturity}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-center">
                      {item.aiSecurity ? (
                        <Brain className="w-3.5 h-3.5 text-purple-400 mx-auto" />
                      ) : (
                        <span className="text-gray-700">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Gaps Section */}
        <div className="mt-8 card-surface p-6">
          <div className="flex items-center gap-2 mb-4">
            <AlertTriangle className="w-4 h-4 text-orange-400" />
            <h2 className="text-sm font-semibold text-white">Coverage Gaps</h2>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {[
              {
                title: "macOS Endpoint Coverage",
                desc: "Limited detection coverage for macOS-specific threats. Priority area for expansion.",
                severity: "high",
              },
              {
                title: "Container / Kubernetes Layer",
                desc: "No dedicated container runtime or Kubernetes audit log detections in current framework.",
                severity: "high",
              },
              {
                title: "LLM Output Monitoring",
                desc: "DLP integration for monitoring LLM response content not yet implemented.",
                severity: "medium",
              },
            ].map((gap) => (
              <div key={gap.title} className="bg-orange-400/[0.04] border border-orange-400/10 rounded-lg p-4">
                <div className="flex items-start gap-2">
                  <AlertTriangle className="w-3.5 h-3.5 text-orange-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="text-sm font-medium text-white mb-1">{gap.title}</p>
                    <p className="text-xs text-gray-500">{gap.desc}</p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
