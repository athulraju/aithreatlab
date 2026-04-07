"use client";

import { useState, useEffect } from "react";
import { PageHeader } from "@/components/PageHeader";
import {
  owaspLLMTop10,
  owaspAgenticTop10,
  researchSpotlights,
  aiCategories,
  OWASPItem,
} from "@/lib/data/aiSecurity";
import {
  Brain,
  AlertTriangle,
  Shield,
  Eye,
  ArrowRight,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Zap,
  Wrench,
  ChevronsDownUp,
  ChevronsUpDown,
} from "lucide-react";

function getCurrentSpotlight() {
  const daysSinceEpoch = Math.floor(Date.now() / (1000 * 60 * 60 * 24));
  const cycleDay = daysSinceEpoch % 30;
  const active = researchSpotlights.find((s) => cycleDay >= s.startDay && cycleDay < s.startDay + 10);
  return active || researchSpotlights[0];
}

function OWASPCard({
  item,
  expanded,
  onToggle,
}: {
  item: OWASPItem;
  expanded: boolean;
  onToggle: () => void;
}) {
  return (
    <div className="card-surface overflow-hidden">
      <button
        onClick={onToggle}
        className="w-full p-5 text-left flex items-start gap-4"
      >
        <div className="flex-shrink-0">
          <div className="w-8 h-8 rounded-lg bg-white/5 flex items-center justify-center">
            <span className="text-xs font-mono font-bold text-gray-400">
              {String(item.rank).padStart(2, "0")}
            </span>
          </div>
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1.5">
            <h3 className="text-sm font-semibold text-white">{item.name}</h3>
            <span
              className={`inline-flex items-center text-xs font-medium border rounded px-2 py-0.5 ${
                item.severity === "critical"
                  ? "text-red-400 bg-red-400/10 border-red-400/20"
                  : item.severity === "high"
                  ? "text-orange-400 bg-orange-400/10 border-orange-400/20"
                  : "text-yellow-400 bg-yellow-400/10 border-yellow-400/20"
              }`}
            >
              {item.severity}
            </span>
          </div>
          <p className="text-xs text-gray-500 leading-relaxed">{item.description}</p>
        </div>
        <div className="flex-shrink-0 mt-0.5">
          {expanded ? (
            <ChevronUp className="w-4 h-4 text-gray-500" />
          ) : (
            <ChevronDown className="w-4 h-4 text-gray-600" />
          )}
        </div>
      </button>

      {expanded && (
        <div className="px-5 pb-5 border-t border-white/[0.06] pt-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-5">
            {/* Protection */}
            <div>
              <div className="flex items-center gap-1.5 mb-2.5">
                <Shield className="w-3.5 h-3.5 text-emerald-400" />
                <h4 className="text-xs font-semibold text-emerald-400 uppercase tracking-wider">Protection</h4>
              </div>
              <ul className="space-y-1.5">
                {item.protection.map((p, i) => (
                  <li key={i} className="text-xs text-gray-400 flex items-start gap-1.5">
                    <CheckCircle2 className="w-3 h-3 text-emerald-500/60 flex-shrink-0 mt-0.5" />
                    {p}
                  </li>
                ))}
              </ul>
            </div>

            {/* Monitoring */}
            <div>
              <div className="flex items-center gap-1.5 mb-2.5">
                <Eye className="w-3.5 h-3.5 text-cyan-400" />
                <h4 className="text-xs font-semibold text-cyan-400 uppercase tracking-wider">Monitoring</h4>
              </div>
              <ul className="space-y-1.5">
                {item.monitoring.map((m, i) => (
                  <li key={i} className="text-xs text-gray-400 flex items-start gap-1.5">
                    <Eye className="w-3 h-3 text-cyan-500/60 flex-shrink-0 mt-0.5" />
                    {m}
                  </li>
                ))}
              </ul>
            </div>

            {/* Logs Required */}
            <div>
              <div className="flex items-center gap-1.5 mb-2.5">
                <Wrench className="w-3.5 h-3.5 text-blue-400" />
                <h4 className="text-xs font-semibold text-blue-400 uppercase tracking-wider">Logs Required</h4>
              </div>
              <ul className="space-y-1.5">
                {item.logsRequired.map((l, i) => (
                  <li key={i} className="text-xs font-mono text-gray-500 bg-white/[0.03] px-2 py-1 rounded">
                    {l}
                  </li>
                ))}
              </ul>
            </div>

            {/* Detection Ideas */}
            <div>
              <div className="flex items-center gap-1.5 mb-2.5">
                <Brain className="w-3.5 h-3.5 text-purple-400" />
                <h4 className="text-xs font-semibold text-purple-400 uppercase tracking-wider">Detection Ideas</h4>
              </div>
              <ul className="space-y-1.5">
                {item.detectionIdeas.map((d, i) => (
                  <li key={i} className="text-xs text-gray-400 flex items-start gap-1.5">
                    <Brain className="w-3 h-3 text-purple-500/60 flex-shrink-0 mt-0.5" />
                    {d}
                  </li>
                ))}
              </ul>
            </div>

            {/* Challenges */}
            <div className="sm:col-span-2">
              <div className="flex items-center gap-1.5 mb-2.5">
                <AlertTriangle className="w-3.5 h-3.5 text-orange-400" />
                <h4 className="text-xs font-semibold text-orange-400 uppercase tracking-wider">Detection Challenges</h4>
              </div>
              <ul className="space-y-1.5">
                {item.challenges.map((c, i) => (
                  <li key={i} className="text-xs text-gray-500 flex items-start gap-1.5">
                    <AlertTriangle className="w-3 h-3 text-orange-500/60 flex-shrink-0 mt-0.5" />
                    {c}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function AISecurityPage() {
  const [activeTab, setActiveTab] = useState<"llm" | "agentic">("llm");
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
  const spotlight = getCurrentSpotlight();

  useEffect(() => { document.title = "AI Security — AIDetectLab"; }, []);

  const activeList = activeTab === "llm" ? owaspLLMTop10 : owaspAgenticTop10;
  const allIds = activeList.map((i) => i.id);
  const allExpanded = allIds.every((id) => expandedIds.has(id));

  // Reset expanded state when switching tabs
  const handleTabChange = (tab: "llm" | "agentic") => {
    setActiveTab(tab);
    setExpandedIds(new Set());
  };

  const handleToggle = (id: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleExpandAll = () => {
    if (allExpanded) {
      setExpandedIds(new Set());
    } else {
      setExpandedIds(new Set(allIds));
    }
  };

  return (
    <div className="pt-14 min-h-screen">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
        <PageHeader
          eyebrow="AI Security"
          title="AI & LLM Threat Detection"
          description="OWASP Top 10 for LLMs and Agentic AI — with detection guidance, monitoring requirements, and practical threat models."
          accent="purple"
        />

        {/* Research Spotlight Banner */}
        <div className="mb-8 relative overflow-hidden rounded-xl border border-purple-500/20 bg-gradient-to-r from-purple-500/10 via-blue-500/5 to-transparent p-5">
          <div className="absolute top-0 right-0 w-64 h-64 bg-purple-500/5 rounded-full blur-3xl" />
          <div className="relative flex items-start justify-between gap-4">
            <div className="flex items-start gap-3">
              <div className="w-8 h-8 rounded-lg bg-purple-500/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                <Brain className="w-4 h-4 text-purple-400" />
              </div>
              <div>
                <div className="flex items-center gap-2 mb-1.5">
                  <span className="text-xs font-semibold text-purple-400 uppercase tracking-wider">Research Spotlight</span>
                  {spotlight.status === "coming-soon" && (
                    <span className="text-xs text-gray-500 bg-white/5 border border-white/10 rounded px-2 py-0.5">
                      Coming Soon
                    </span>
                  )}
                </div>
                <h3 className="text-sm font-semibold text-white mb-1">{spotlight.title}</h3>
                <p className="text-xs text-gray-400 max-w-lg leading-relaxed">{spotlight.summary}</p>
              </div>
            </div>
            {spotlight.status === "published" && (
              <button className="flex-shrink-0 flex items-center gap-1.5 text-xs text-purple-400 hover:text-purple-300 font-medium transition-colors">
                {spotlight.cta}
                <ArrowRight className="w-3 h-3" />
              </button>
            )}
          </div>
        </div>

        {/* Threat Categories */}
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2 mb-8">
          {aiCategories.map((cat) => (
            <div key={cat.id} className="card-surface p-3 text-center">
              <p className="text-xs font-medium text-gray-300 mb-1">{cat.name}</p>
              <p className="text-xs text-gray-600">{cat.count} items</p>
            </div>
          ))}
        </div>

        {/* OWASP Tabs + expand/collapse controls */}
        <div className="flex items-center justify-between gap-4 mb-6 flex-wrap">
          <div className="flex gap-1 p-1 bg-white/[0.03] border border-white/[0.06] rounded-lg">
            <button
              onClick={() => handleTabChange("llm")}
              className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all ${
                activeTab === "llm"
                  ? "bg-white/10 text-white"
                  : "text-gray-500 hover:text-gray-300"
              }`}
            >
              <Brain className="w-3.5 h-3.5" />
              OWASP LLM Top 10
            </button>
            <button
              onClick={() => handleTabChange("agentic")}
              className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all ${
                activeTab === "agentic"
                  ? "bg-white/10 text-white"
                  : "text-gray-500 hover:text-gray-300"
              }`}
            >
              <Zap className="w-3.5 h-3.5" />
              OWASP Agentic Top 10
            </button>
          </div>

          <div className="flex items-center gap-3">
            <span className="text-xs text-gray-600">
              {expandedIds.size} of {allIds.length} expanded
            </span>
            <button
              onClick={handleExpandAll}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium border border-white/[0.08] bg-white/[0.03] hover:bg-white/[0.06] text-gray-400 hover:text-white transition-all"
            >
              {allExpanded ? (
                <>
                  <ChevronsDownUp className="w-3.5 h-3.5" />
                  Collapse All
                </>
              ) : (
                <>
                  <ChevronsUpDown className="w-3.5 h-3.5" />
                  Expand All
                </>
              )}
            </button>
          </div>
        </div>

        <div className="space-y-2">
          {activeList.map((item) => (
            <OWASPCard
              key={item.id}
              item={item}
              expanded={expandedIds.has(item.id)}
              onToggle={() => handleToggle(item.id)}
            />
          ))}
        </div>
      </div>
    </div>
  );
}
