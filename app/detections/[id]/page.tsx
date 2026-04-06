"use client";

import { useState } from "react";
import Link from "next/link";
import { notFound } from "next/navigation";
import dynamic from "next/dynamic";
import { getDetectionById } from "@/lib/data/detections";
import { severityColor, maturityColor, platformColor } from "@/lib/utils";
import {
  ArrowLeft,
  Copy,
  CheckCircle2,
  AlertTriangle,
  Info,
  Shield,
  Wrench,
  Terminal,
  FileText,
  Eye,
} from "lucide-react";

const MonacoEditor = dynamic(() => import("@monaco-editor/react"), { ssr: false });

type LogicTab = "sigma" | "splunk" | "pyspark";

export default function DetectionDetailPage({ params }: { params: { id: string } }) {
  const detection = getDetectionById(params.id);
  if (!detection) notFound();

  const [logicTab, setLogicTab] = useState<LogicTab>("sigma");
  const [copied, setCopied] = useState(false);

  const logicContent = {
    sigma: detection.sigma,
    splunk: detection.splunk,
    pyspark: detection.pyspark,
  };

  const monacoLang = {
    sigma: "yaml",
    splunk: "plaintext",
    pyspark: "python",
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(logicContent[logicTab]);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="pt-14 min-h-screen">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
        {/* Back */}
        <Link
          href="/detections"
          className="inline-flex items-center gap-1.5 text-sm text-gray-500 hover:text-white transition-colors mb-8"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          Detection Library
        </Link>

        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-2 flex-wrap mb-3">
            <span
              className={`inline-flex items-center text-xs font-medium border rounded px-2 py-0.5 ${severityColor(detection.severity)}`}
            >
              {detection.severity}
            </span>
            <span
              className={`inline-flex items-center text-xs font-medium border rounded px-2 py-0.5 ${maturityColor(detection.maturity)}`}
            >
              {detection.maturity}
            </span>
            {detection.platform.map((p) => (
              <span
                key={p}
                className={`inline-flex items-center text-xs font-medium border rounded px-2 py-0.5 ${platformColor(p)}`}
              >
                {p}
              </span>
            ))}
            {detection.mitre.map((m) => (
              <span
                key={m}
                className="inline-flex items-center text-xs font-mono text-gray-500 bg-white/[0.03] border border-white/[0.06] rounded px-2 py-0.5"
              >
                {m}
              </span>
            ))}
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold text-white mb-3">
            {detection.title}
          </h1>
          <p className="text-gray-400 text-sm">{detection.description}</p>
          <p className="text-xs text-gray-600 mt-2">
            Updated {detection.updated} · by {detection.author}
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Main content */}
          <div className="lg:col-span-2 space-y-6">
            {/* Problem Statement */}
            <div className="card-surface p-6">
              <div className="flex items-center gap-2 mb-3">
                <Shield className="w-4 h-4 text-cyan-400" />
                <h2 className="text-sm font-semibold text-white">Problem Statement</h2>
              </div>
              <p className="text-sm text-gray-400 leading-relaxed">{detection.problemStatement}</p>
            </div>

            {/* Logic Tabs */}
            <div className="card-surface overflow-hidden">
              <div className="flex items-center justify-between px-4 pt-4 border-b border-white/[0.06] mb-0">
                <div className="flex gap-1">
                  {(["sigma", "splunk", "pyspark"] as LogicTab[]).map((tab) => (
                    <button
                      key={tab}
                      onClick={() => setLogicTab(tab)}
                      className={`px-3 py-2 text-xs font-medium rounded-t transition-all border-b-2 ${
                        logicTab === tab
                          ? "text-white border-cyan-400"
                          : "text-gray-500 border-transparent hover:text-gray-300"
                      }`}
                    >
                      {tab === "sigma" ? "Sigma YAML" : tab === "splunk" ? "Splunk SPL" : "PySpark"}
                    </button>
                  ))}
                </div>
                <button
                  onClick={handleCopy}
                  className="flex items-center gap-1 px-2 py-1 mb-1 rounded text-xs text-gray-500 hover:text-white hover:bg-white/5 transition-all"
                >
                  {copied ? <CheckCircle2 className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3" />}
                  {copied ? "Copied" : "Copy"}
                </button>
              </div>
              <div className="h-[320px]">
                <MonacoEditor
                  height="100%"
                  language={monacoLang[logicTab]}
                  value={logicContent[logicTab]}
                  theme="vs-dark"
                  options={{
                    fontSize: 12,
                    minimap: { enabled: false },
                    scrollBeyondLastLine: false,
                    readOnly: true,
                    lineNumbers: "on",
                    renderLineHighlight: "none",
                    padding: { top: 12, bottom: 12 },
                    fontFamily: "'JetBrains Mono', monospace",
                  }}
                />
              </div>
            </div>

            {/* Sample Logs */}
            <div className="card-surface p-6">
              <div className="flex items-center gap-2 mb-4">
                <Terminal className="w-4 h-4 text-gray-400" />
                <h2 className="text-sm font-semibold text-white">Sample Logs</h2>
              </div>
              <div className="space-y-3">
                {detection.sampleLogs.map((log, i) => (
                  <pre
                    key={i}
                    className="text-xs font-mono text-gray-400 bg-black/30 rounded-lg p-4 overflow-x-auto leading-relaxed whitespace-pre-wrap break-all"
                  >
                    {log}
                  </pre>
                ))}
              </div>
            </div>
          </div>

          {/* Sidebar */}
          <div className="space-y-4">
            {/* Required Fields */}
            <div className="card-surface p-5">
              <div className="flex items-center gap-2 mb-3">
                <FileText className="w-4 h-4 text-gray-400" />
                <h3 className="text-sm font-semibold text-white">Required Fields</h3>
              </div>
              <div className="space-y-1.5">
                {detection.requiredFields.map((field) => (
                  <div
                    key={field}
                    className="text-xs font-mono text-gray-400 bg-white/[0.03] px-2.5 py-1.5 rounded"
                  >
                    {field}
                  </div>
                ))}
              </div>
            </div>

            {/* False Positives */}
            <div className="card-surface p-5">
              <div className="flex items-center gap-2 mb-3">
                <AlertTriangle className="w-4 h-4 text-orange-400" />
                <h3 className="text-sm font-semibold text-white">False Positives</h3>
              </div>
              <ul className="space-y-2">
                {detection.falsePositives.map((fp) => (
                  <li key={fp} className="text-xs text-gray-500 flex items-start gap-1.5">
                    <span className="text-orange-400 mt-0.5">·</span>
                    {fp}
                  </li>
                ))}
              </ul>
            </div>

            {/* Tuning Guidance */}
            <div className="card-surface p-5">
              <div className="flex items-center gap-2 mb-3">
                <Wrench className="w-4 h-4 text-blue-400" />
                <h3 className="text-sm font-semibold text-white">Tuning Guidance</h3>
              </div>
              <p className="text-xs text-gray-500 leading-relaxed">{detection.tuningGuidance}</p>
            </div>

            {/* Deployment Notes */}
            <div className="card-surface p-5">
              <div className="flex items-center gap-2 mb-3">
                <Info className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-semibold text-white">Deployment Notes</h3>
              </div>
              <p className="text-xs text-gray-500 leading-relaxed">{detection.deploymentNotes}</p>
            </div>

            {/* Evasion Considerations */}
            <div className="card-surface p-5">
              <div className="flex items-center gap-2 mb-3">
                <Eye className="w-4 h-4 text-purple-400" />
                <h3 className="text-sm font-semibold text-white">Evasion Considerations</h3>
              </div>
              <p className="text-xs text-gray-500 leading-relaxed">{detection.evasionConsiderations}</p>
            </div>

            {/* Tags */}
            <div className="card-surface p-5">
              <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Tags</h3>
              <div className="flex flex-wrap gap-1.5">
                {detection.tags.map((tag) => (
                  <span
                    key={tag}
                    className="text-xs text-gray-500 bg-white/[0.03] border border-white/[0.06] rounded px-2 py-0.5"
                  >
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
