"use client";

import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { cn } from "@/lib/utils";
import { agentSkills, skillCategories, type AgentSkill, type SkillType } from "@/lib/data/agentSkills";
import {
  ChevronRight,
  Copy,
  CheckCircle2,
  Cpu,
  Wrench,
  Terminal,
  FileCode2,
  Zap,
} from "lucide-react";

const ease = [0.25, 0.1, 0.25, 1] as const;

const categoryIcon: Record<SkillType, React.ReactNode> = {
  detection:   <Cpu className="w-3.5 h-3.5" />,
  maintenance: <Wrench className="w-3.5 h-3.5" />,
};

const categoryAccent: Record<SkillType, string> = {
  detection:   "text-cyan-400 bg-cyan-400/10 border-cyan-400/25",
  maintenance: "text-violet-400 bg-violet-400/10 border-violet-400/25",
};

type PanelTab = "prompt" | "output";

export default function AgentSkillsPage() {
  const [activeCategory, setActiveCategory] = useState<SkillType>("detection");
  const [selectedSkill, setSelectedSkill]   = useState<AgentSkill | null>(null);
  const [activeTab, setActiveTab]           = useState<PanelTab>("prompt");
  const [copied, setCopied]                 = useState(false);

  useEffect(() => {
    document.title = "Agent Skills | AIDetectLab";
    setSelectedSkill(agentSkills.find((s) => s.type === "detection") ?? null);
  }, []);

  const visibleSkills = agentSkills.filter((s) => s.type === activeCategory);

  const handleCategoryChange = (cat: SkillType) => {
    setActiveCategory(cat);
    setSelectedSkill(agentSkills.find((s) => s.type === cat) ?? null);
    setActiveTab("prompt");
  };

  const handleSelectSkill = (skill: AgentSkill) => {
    setSelectedSkill(skill);
    setActiveTab("prompt");
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  const activeContent = selectedSkill
    ? activeTab === "prompt"
      ? selectedSkill.prompt
      : selectedSkill.expectedOutput
    : "";

  return (
    <div className="pt-14 min-h-screen bg-[#060609] relative overflow-hidden">

      {/* ── Ambient background blobs ──────────────────────────────────── */}
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        <div className="animate-glow-pulse absolute -top-40 -right-40 w-[700px] h-[700px] rounded-full bg-cyan-500/[0.04] blur-[130px]" />
        <div className="animate-glow-pulse absolute top-1/2 -translate-y-1/2 -left-60 w-[500px] h-[500px] rounded-full bg-violet-500/[0.04] blur-[120px]" style={{ animationDelay: "3s" }} />
        <div className="animate-glow-pulse absolute bottom-0 right-1/3 w-[400px] h-[400px] rounded-full bg-cyan-400/[0.03] blur-[100px]" style={{ animationDelay: "1.5s" }} />
        <div className="absolute inset-0 opacity-[0.12]" style={{ backgroundImage: "radial-gradient(circle, #ffffff 1px, transparent 1px)", backgroundSize: "28px 28px" }} />
      </div>

      {/* ── Top bar ───────────────────────────────────────────────────── */}
      <div className="relative border-b border-white/[0.06] bg-gradient-to-r from-[#07070e]/95 via-[#08091a]/85 to-[#07070e]/95 backdrop-blur-sm">
        <div className="max-w-[1400px] mx-auto px-4 sm:px-6 lg:px-8 py-4 flex items-center justify-between gap-4 flex-wrap">
          <motion.div
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, ease }}
          >
            <div className="flex items-center gap-2 mb-1">
              <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-md bg-cyan-500/10 border border-cyan-500/20">
                <Zap className="w-2.5 h-2.5 text-cyan-400" />
                <span className="text-[9px] font-mono font-bold text-cyan-400 uppercase tracking-widest">v1.0 · experimental</span>
              </div>
            </div>
            <h1 className="text-xl font-bold bg-gradient-to-r from-white via-gray-100 to-gray-400 bg-clip-text text-transparent tracking-tight">
              Agent Skills
            </h1>
            <p className="text-xs text-gray-500 mt-0.5">
              Composable detection and maintenance skill prompts for AI security workflows
            </p>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.35, ease, delay: 0.1 }}
            className="flex items-center gap-1.5 text-[10px] font-mono text-gray-500 border border-white/[0.07] rounded-md px-2.5 py-1.5 bg-white/[0.02]"
          >
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.9)] animate-pulse" />
            {agentSkills.length} skills loaded
          </motion.div>
        </div>
        <div className="absolute bottom-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-cyan-500/25 to-transparent" />
      </div>

      {/* ── Workbench layout ──────────────────────────────────────────── */}
      <div className="relative max-w-[1400px] mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex min-h-[calc(100vh-112px)]">

          {/* ── LEFT: Category + Skill list ──────────────────────────── */}
          <motion.aside
            className="w-56 shrink-0 border-r border-white/[0.05] py-5 pr-3 flex flex-col gap-1"
            initial={{ opacity: 0, x: -16 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.45, ease, delay: 0.05 }}
          >
            {skillCategories.map((cat) => {
              const isActive = activeCategory === cat.id;
              const isCyan   = cat.id === "detection";
              return (
                <div key={cat.id} className="mb-1">
                  <button
                    onClick={() => handleCategoryChange(cat.id)}
                    className={cn(
                      "w-full flex items-center gap-2 px-3 py-2 rounded-lg text-left text-xs font-semibold transition-all duration-200 border",
                      isActive
                        ? isCyan
                          ? "bg-cyan-500/10 text-cyan-300 border-cyan-500/25 shadow-[0_0_14px_rgba(6,182,212,0.1)]"
                          : "bg-violet-500/10 text-violet-300 border-violet-500/25 shadow-[0_0_14px_rgba(139,92,246,0.1)]"
                        : "text-gray-500 hover:text-gray-300 hover:bg-white/[0.04] border-transparent"
                    )}
                  >
                    <span className={cn(
                      "transition-all duration-200",
                      isActive
                        ? isCyan
                          ? "text-cyan-400 drop-shadow-[0_0_5px_rgba(6,182,212,0.8)]"
                          : "text-violet-400 drop-shadow-[0_0_5px_rgba(139,92,246,0.8)]"
                        : "text-gray-600"
                    )}>
                      {categoryIcon[cat.id]}
                    </span>
                    {cat.label}
                  </button>

                  <AnimatePresence initial={false}>
                    {isActive && (
                      <motion.div
                        key={cat.id}
                        initial={{ opacity: 0, y: -4 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -4 }}
                        transition={{ duration: 0.2, ease: "easeOut" }}
                        className="mt-1 ml-2 flex flex-col gap-0.5"
                      >
                        {visibleSkills.map((skill) => {
                          const isSelected = selectedSkill?.id === skill.id;
                          return (
                            <button
                              key={skill.id}
                              onClick={() => handleSelectSkill(skill)}
                              className={cn(
                                "w-full flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-left text-[11px] transition-all duration-150 group border-l-2",
                                isSelected
                                  ? isCyan
                                    ? "text-cyan-300 bg-cyan-500/10 border-cyan-400"
                                    : "text-violet-300 bg-violet-500/10 border-violet-400"
                                  : "text-gray-500 hover:text-gray-300 border-transparent hover:border-white/10 hover:bg-white/[0.02]"
                              )}
                            >
                              <ChevronRight className={cn(
                                "w-3 h-3 shrink-0 transition-transform duration-150",
                                isSelected
                                  ? isCyan ? "rotate-90 text-cyan-400" : "rotate-90 text-violet-400"
                                  : "text-gray-700 group-hover:text-gray-500"
                              )} />
                              <span className="truncate">{skill.name}</span>
                            </button>
                          );
                        })}
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              );
            })}

            {/* Stats footer */}
            <div className="mt-auto pt-4 border-t border-white/[0.04]">
              <div className="space-y-1.5 px-1">
                {skillCategories.map((cat) => (
                  <div key={cat.id} className="flex items-center justify-between">
                    <span className="text-[10px] text-gray-600">{cat.label}</span>
                    <span className={cn(
                      "text-[10px] font-mono px-1.5 py-0.5 rounded",
                      cat.id === "detection" ? "text-cyan-400 bg-cyan-500/10" : "text-violet-400 bg-violet-500/10"
                    )}>
                      {agentSkills.filter((s) => s.type === cat.id).length}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </motion.aside>

          {/* ── CENTER: Skill cards ───────────────────────────────────── */}
          <motion.div
            className="w-64 shrink-0 border-r border-white/[0.05] py-5 px-3 overflow-y-auto"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, ease, delay: 0.1 }}
          >
            <div className="flex items-center gap-2 mb-3 px-1">
              <span className={cn(
                "w-1 h-3.5 rounded-full",
                activeCategory === "detection" ? "bg-gradient-to-b from-cyan-400 to-cyan-600" : "bg-gradient-to-b from-violet-400 to-violet-600"
              )} />
              <span className="text-[9px] font-mono text-gray-600 uppercase tracking-[0.15em]">
                {skillCategories.find((c) => c.id === activeCategory)?.label}
              </span>
            </div>

            <AnimatePresence mode="wait">
              <motion.div
                key={activeCategory}
                className="flex flex-col gap-2"
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -4 }}
                transition={{ duration: 0.2, ease: "easeOut" }}
              >
                {visibleSkills.map((skill, i) => {
                  const isSelected = selectedSkill?.id === skill.id;
                  const isCyan     = skill.type === "detection";
                  return (
                    <motion.button
                      key={skill.id}
                      onClick={() => handleSelectSkill(skill)}
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ duration: 0.25, ease, delay: i * 0.04 }}
                      className={cn(
                        "w-full text-left rounded-xl border p-3 transition-all duration-200 group relative overflow-hidden",
                        isSelected
                          ? isCyan
                            ? "bg-gradient-to-br from-cyan-500/10 to-cyan-500/[0.04] border-cyan-500/35 shadow-[0_0_20px_rgba(6,182,212,0.13)]"
                            : "bg-gradient-to-br from-violet-500/10 to-violet-500/[0.04] border-violet-500/35 shadow-[0_0_20px_rgba(139,92,246,0.13)]"
                          : "bg-white/[0.02] border-white/[0.06] hover:bg-white/[0.04] hover:border-white/[0.10] hover:-translate-y-0.5 hover:shadow-[0_4px_16px_rgba(0,0,0,0.3)]"
                      )}
                    >
                      {isSelected && (
                        <div className={cn(
                          "absolute top-0 left-0 right-0 h-px",
                          isCyan ? "bg-gradient-to-r from-transparent via-cyan-400/70 to-transparent" : "bg-gradient-to-r from-transparent via-violet-400/70 to-transparent"
                        )} />
                      )}

                      <div className="flex items-center justify-between mb-2">
                        <span className={cn("inline-flex items-center gap-1 text-[9px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded border", categoryAccent[skill.type])}>
                          {categoryIcon[skill.type]}
                          {skill.type}
                        </span>
                        <ChevronRight className={cn("w-3 h-3 transition-all duration-200", isSelected ? isCyan ? "text-cyan-400 rotate-90" : "text-violet-400 rotate-90" : "text-gray-700 group-hover:text-gray-500")} />
                      </div>

                      <p className={cn("text-[12px] font-semibold leading-snug mb-1.5 transition-colors duration-150", isSelected ? "text-white" : "text-gray-300 group-hover:text-white")}>
                        {skill.name}
                      </p>
                      <p className="text-[10px] text-gray-600 leading-relaxed line-clamp-2 mb-2">{skill.description}</p>

                      <div className="flex flex-wrap gap-1">
                        {skill.tags.slice(0, 3).map((tag) => (
                          <span key={tag} className="text-[9px] font-mono text-gray-600 bg-white/[0.03] border border-white/[0.05] rounded px-1.5 py-0.5">{tag}</span>
                        ))}
                        {skill.tags.length > 3 && <span className="text-[9px] font-mono text-gray-700">+{skill.tags.length - 3}</span>}
                      </div>
                    </motion.button>
                  );
                })}
              </motion.div>
            </AnimatePresence>
          </motion.div>

          {/* ── RIGHT: Skill detail ───────────────────────────────────── */}
          <div className="flex-1 min-w-0 flex flex-col overflow-hidden">
            <AnimatePresence mode="wait">
              {selectedSkill ? (
                <motion.div
                  key={selectedSkill.id}
                  className="flex flex-col flex-1 overflow-hidden"
                  initial={{ opacity: 0, x: 12 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -8 }}
                  transition={{ duration: 0.22, ease: "easeOut" }}
                >
                  {/* Detail header */}
                  <div className="border-b border-white/[0.05] px-6 py-4 flex items-start justify-between gap-4 shrink-0 bg-gradient-to-r from-white/[0.015] to-transparent">
                    <div>
                      <div className="flex items-center gap-2 mb-1.5">
                        <span className={cn("inline-flex items-center gap-1 text-[9px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded border", categoryAccent[selectedSkill.type])}>
                          {categoryIcon[selectedSkill.type]}
                          {selectedSkill.type}
                        </span>
                        <span className="text-[9px] font-mono text-gray-700 bg-white/[0.03] border border-white/[0.05] rounded px-2 py-0.5">
                          {selectedSkill.id}
                        </span>
                      </div>
                      <h2 className={cn(
                        "text-base font-bold bg-gradient-to-r bg-clip-text text-transparent",
                        selectedSkill.type === "detection" ? "from-white via-white to-cyan-200" : "from-white via-white to-violet-200"
                      )}>
                        {selectedSkill.name}
                      </h2>
                      <p className="text-xs text-gray-500 mt-0.5 max-w-2xl leading-relaxed">{selectedSkill.description}</p>
                    </div>

                    <motion.button
                      onClick={() => handleCopy(activeContent)}
                      whileTap={{ scale: 0.95 }}
                      className={cn(
                        "flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs transition-all duration-200 shrink-0",
                        copied
                          ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400 shadow-[0_0_10px_rgba(52,211,153,0.1)]"
                          : "bg-white/[0.04] hover:bg-white/[0.07] border-white/[0.08] hover:border-white/[0.15] text-gray-400 hover:text-white"
                      )}
                    >
                      <AnimatePresence mode="wait" initial={false}>
                        {copied
                          ? <motion.span key="check" initial={{ scale: 0.6, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.6, opacity: 0 }} transition={{ duration: 0.15 }}><CheckCircle2 className="w-3.5 h-3.5" /></motion.span>
                          : <motion.span key="copy"  initial={{ scale: 0.6, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.6, opacity: 0 }} transition={{ duration: 0.15 }}><Copy className="w-3.5 h-3.5" /></motion.span>
                        }
                      </AnimatePresence>
                      {copied ? "Copied!" : "Copy"}
                    </motion.button>
                  </div>

                  {/* Tabs */}
                  <div className="flex border-b border-white/[0.05] shrink-0 bg-[#040409]/60">
                    {(["prompt", "output"] as PanelTab[]).map((tab) => {
                      const isActive = activeTab === tab;
                      const label    = tab === "prompt" ? "Skill Prompt" : "Expected Output";
                      const Icon     = tab === "prompt" ? FileCode2 : Terminal;
                      const activeStyle = tab === "prompt" ? "text-cyan-300 border-cyan-500 bg-cyan-500/[0.06]" : "text-emerald-300 border-emerald-500 bg-emerald-500/[0.06]";
                      return (
                        <button
                          key={tab}
                          onClick={() => setActiveTab(tab)}
                          className={cn(
                            "flex items-center gap-1.5 px-5 py-2.5 text-[11px] font-medium border-b-2 transition-all duration-200 -mb-px",
                            isActive ? activeStyle : "text-gray-600 border-transparent hover:text-gray-400 hover:bg-white/[0.02]"
                          )}
                        >
                          <Icon className="w-3.5 h-3.5" />
                          {label}
                        </button>
                      );
                    })}
                  </div>

                  {/* Content — animated on tab switch */}
                  <AnimatePresence mode="wait">
                    <motion.div
                      key={activeTab}
                      className="flex-1 overflow-auto bg-[#020207] relative"
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                      transition={{ duration: 0.15 }}
                    >
                      <div
                        className="absolute inset-0 pointer-events-none opacity-[0.035]"
                        style={{ backgroundImage: "linear-gradient(rgba(255,255,255,0.8) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.8) 1px, transparent 1px)", backgroundSize: "40px 40px" }}
                      />
                      <div className={cn(
                        "absolute top-0 left-0 bottom-0 w-px",
                        activeTab === "prompt"
                          ? "bg-gradient-to-b from-cyan-500/30 via-cyan-500/10 to-transparent"
                          : "bg-gradient-to-b from-emerald-500/30 via-emerald-500/10 to-transparent"
                      )} />
                      <pre className="relative text-[11px] font-mono text-gray-300/90 leading-relaxed p-6 whitespace-pre-wrap">
                        {activeContent}
                      </pre>
                    </motion.div>
                  </AnimatePresence>

                  {/* Tags footer */}
                  <div className="shrink-0 border-t border-white/[0.05] px-6 py-3 flex items-center gap-2 flex-wrap bg-gradient-to-r from-[#05050b] to-[#04040a]">
                    <span className="text-[9px] font-mono text-gray-700 uppercase tracking-[0.12em] mr-1">tags</span>
                    {selectedSkill.tags.map((tag) => (
                      <motion.span
                        key={tag}
                        className="text-[9px] font-mono text-gray-500 bg-white/[0.03] border border-white/[0.06] rounded px-2 py-0.5 hover:text-gray-300 hover:border-white/[0.12] transition-colors cursor-default"
                        whileHover={{ y: -1 }}
                        transition={{ duration: 0.12 }}
                      >
                        {tag}
                      </motion.span>
                    ))}
                  </div>
                </motion.div>
              ) : (
                <motion.div
                  key="empty"
                  className="flex items-center justify-center h-full"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.2 }}
                >
                  <div className="text-center">
                    <div className="w-14 h-14 mx-auto mb-3 rounded-2xl border border-white/[0.07] bg-gradient-to-br from-white/[0.04] to-transparent flex items-center justify-center">
                      <Cpu className="w-6 h-6 text-gray-700" />
                    </div>
                    <p className="text-sm text-gray-600">Select a skill to inspect</p>
                    <p className="text-xs text-gray-700 mt-1">Choose from the panel on the left</p>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>
    </div>
  );
}
