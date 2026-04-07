"use client";

import { useState, useCallback, useEffect } from "react";
import dynamic from "next/dynamic";
import { PageHeader } from "@/components/PageHeader";
import { Badge } from "@/components/Badge";
import { sigmaToSplunk, ConversionResult } from "@/lib/converters/sigmaToSplunk";
import { sigmaToPySpark } from "@/lib/converters/sigmaToPySpark";
import { splunkToSigma } from "@/lib/converters/splunkToSigma";
import { pysparkToSigma } from "@/lib/converters/pysparkToSigma";
import { detections } from "@/lib/data/detections";
import {
  ArrowRight,
  Copy,
  Download,
  CheckCircle2,
  AlertTriangle,
  Info,
  ChevronDown,
  RefreshCw,
  ExternalLink,
  BookOpen,
} from "lucide-react";

const MonacoEditor = dynamic(() => import("@monaco-editor/react"), { ssr: false });

type Format = "sigma" | "splunk" | "pyspark";

const formatLabels: Record<Format, string> = {
  sigma: "Sigma YAML",
  splunk: "Splunk SPL",
  pyspark: "PySpark",
};

const formatColors: Record<Format, string> = {
  sigma: "text-cyan-400",
  splunk: "text-orange-400",
  pyspark: "text-yellow-400",
};

const monacoLang: Record<Format, string> = {
  sigma: "yaml",
  splunk: "plaintext",
  pyspark: "python",
};

const sampleInputs: Record<Format, string> = {
  sigma: detections[0].sigma,
  splunk: detections[0].splunk,
  pyspark: detections[0].pyspark,
};

const availableConversions: Record<Format, Format[]> = {
  sigma: ["splunk", "pyspark"],
  splunk: ["sigma"],
  pyspark: ["sigma"],
};

function convert(input: string, from: Format, to: Format): ConversionResult {
  if (from === "sigma" && to === "splunk") return sigmaToSplunk(input);
  if (from === "sigma" && to === "pyspark") return sigmaToPySpark(input);
  if (from === "splunk" && to === "sigma") return splunkToSigma(input);
  if (from === "pyspark" && to === "sigma") return pysparkToSigma(input);
  return { output: "", notes: [], warnings: [], valid: false };
}

export default function ConverterPage() {
  const [inputFormat, setInputFormat] = useState<Format>("sigma");
  const [outputFormat, setOutputFormat] = useState<Format>("splunk");
  const [inputValue, setInputValue] = useState(sampleInputs.sigma);
  const [result, setResult] = useState<ConversionResult | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => { document.title = "Converter — AIDetectLab"; }, []);

  const handleConvert = useCallback(() => {
    const r = convert(inputValue, inputFormat, outputFormat);
    setResult(r);
  }, [inputValue, inputFormat, outputFormat]);

  const handleInputFormatChange = (fmt: Format) => {
    setInputFormat(fmt);
    setInputValue(sampleInputs[fmt]);
    const available = availableConversions[fmt];
    setOutputFormat(available[0]);
    setResult(null);
  };

  const handleOutputFormatChange = (fmt: Format) => {
    setOutputFormat(fmt);
    setResult(null);
  };

  const handleCopy = () => {
    if (result?.output) {
      navigator.clipboard.writeText(result.output);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleDownload = () => {
    if (!result?.output) return;
    const ext = outputFormat === "sigma" ? "yml" : outputFormat === "splunk" ? "spl" : "py";
    const blob = new Blob([result.output], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `detection.${ext}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleLoadSample = (id: string) => {
    const det = detections.find((d) => d.id === id);
    if (!det) return;
    const field = inputFormat === "sigma" ? "sigma" : inputFormat === "splunk" ? "splunk" : "pyspark";
    setInputValue(det[field]);
    setResult(null);
  };

  return (
    <div className="pt-14 min-h-screen">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
        <PageHeader
          eyebrow="Converter"
          title="Detection Format Converter"
          description="Translate detections between Sigma, Splunk SPL, and PySpark with validation and translation notes."
          accent="cyan"
        />

        {/* Format selectors + convert */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4 mb-6">
          {/* Input format */}
          <div>
            <label className="text-xs text-gray-500 mb-1.5 block">Input Format</label>
            <div className="flex gap-1.5">
              {(["sigma", "splunk", "pyspark"] as Format[]).map((fmt) => (
                <button
                  key={fmt}
                  onClick={() => handleInputFormatChange(fmt)}
                  className={`px-3 py-1.5 rounded-md text-xs font-medium border transition-all ${
                    inputFormat === fmt
                      ? "bg-white/10 border-white/20 text-white"
                      : "bg-transparent border-white/10 text-gray-500 hover:text-gray-300 hover:border-white/15"
                  }`}
                >
                  {formatLabels[fmt]}
                </button>
              ))}
            </div>
          </div>

          <ArrowRight className="w-4 h-4 text-gray-600 hidden sm:block mt-5" />

          {/* Output format */}
          <div>
            <label className="text-xs text-gray-500 mb-1.5 block">Output Format</label>
            <div className="flex gap-1.5">
              {availableConversions[inputFormat].map((fmt) => (
                <button
                  key={fmt}
                  onClick={() => handleOutputFormatChange(fmt)}
                  className={`px-3 py-1.5 rounded-md text-xs font-medium border transition-all ${
                    outputFormat === fmt
                      ? "bg-white/10 border-white/20 text-white"
                      : "bg-transparent border-white/10 text-gray-500 hover:text-gray-300 hover:border-white/15"
                  }`}
                >
                  {formatLabels[fmt]}
                </button>
              ))}
            </div>
          </div>

          <div className="sm:ml-auto sm:mt-5">
            <button
              onClick={handleConvert}
              className="flex items-center gap-2 px-5 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-white text-sm font-medium transition-all shadow-lg shadow-cyan-500/20"
            >
              <RefreshCw className="w-4 h-4" />
              Convert
            </button>
          </div>
        </div>

        {/* Sample rules */}
        <div className="flex items-center gap-2 mb-6 flex-wrap">
          <span className="text-xs text-gray-600">Load sample:</span>
          {detections.slice(0, 5).map((d) => (
            <button
              key={d.id}
              onClick={() => handleLoadSample(d.id)}
              className="text-xs font-mono text-gray-500 hover:text-cyan-400 bg-white/[0.03] border border-white/[0.06] hover:border-cyan-500/30 px-2 py-0.5 rounded transition-all"
            >
              {d.id}
            </button>
          ))}
        </div>

        {/* Editors */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
          {/* Input Editor */}
          <div className="card-surface overflow-hidden">
            <div className="flex items-center justify-between px-4 py-3 border-b border-white/[0.06]">
              <div className="flex items-center gap-2">
                <span className={`w-2 h-2 rounded-full ${
                  inputFormat === "sigma" ? "bg-cyan-400" :
                  inputFormat === "splunk" ? "bg-orange-400" : "bg-yellow-400"
                }`} />
                <span className="text-xs font-medium text-gray-400">{formatLabels[inputFormat]}</span>
              </div>
              <span className="text-xs text-gray-600">Input</span>
            </div>
            <div className="h-[420px]">
              <MonacoEditor
                height="100%"
                language={monacoLang[inputFormat]}
                value={inputValue}
                onChange={(v) => setInputValue(v || "")}
                theme="vs-dark"
                options={{
                  fontSize: 12,
                  minimap: { enabled: false },
                  scrollBeyondLastLine: false,
                  lineNumbers: "on",
                  renderLineHighlight: "none",
                  padding: { top: 12, bottom: 12 },
                  fontFamily: "'JetBrains Mono', monospace",
                }}
              />
            </div>
          </div>

          {/* Output Editor */}
          <div className="card-surface overflow-hidden">
            <div className="flex items-center justify-between px-4 py-3 border-b border-white/[0.06]">
              <div className="flex items-center gap-2">
                <span className={`w-2 h-2 rounded-full ${
                  outputFormat === "sigma" ? "bg-cyan-400" :
                  outputFormat === "splunk" ? "bg-orange-400" : "bg-yellow-400"
                }`} />
                <span className="text-xs font-medium text-gray-400">{formatLabels[outputFormat]}</span>
              </div>
              <div className="flex items-center gap-2">
                {result?.valid && (
                  <Badge variant="green">Valid</Badge>
                )}
                <button
                  onClick={handleCopy}
                  className="flex items-center gap-1 px-2 py-1 rounded text-xs text-gray-500 hover:text-white hover:bg-white/5 transition-all"
                >
                  {copied ? <CheckCircle2 className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3" />}
                  {copied ? "Copied" : "Copy"}
                </button>
                <button
                  onClick={handleDownload}
                  className="flex items-center gap-1 px-2 py-1 rounded text-xs text-gray-500 hover:text-white hover:bg-white/5 transition-all"
                >
                  <Download className="w-3 h-3" />
                  Download
                </button>
              </div>
            </div>
            <div className="h-[420px]">
              <MonacoEditor
                height="100%"
                language={monacoLang[outputFormat]}
                value={result?.output || "// Click Convert to generate output"}
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
        </div>

        {/* Validation + Notes panels */}
        {result && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Validation */}
            <div className="card-surface p-5">
              <div className="flex items-center gap-2 mb-4">
                {result.valid ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                ) : (
                  <AlertTriangle className="w-4 h-4 text-red-400" />
                )}
                <h3 className="text-sm font-semibold text-white">Validation</h3>
              </div>

              {result.warnings.length > 0 ? (
                <div className="space-y-2">
                  {result.warnings.map((w, i) => (
                    <div key={i} className="flex items-start gap-2 text-xs text-orange-300">
                      <AlertTriangle className="w-3 h-3 mt-0.5 flex-shrink-0 text-orange-400" />
                      {w}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-emerald-400">All validation checks passed.</p>
              )}
            </div>

            {/* Translation notes */}
            <div className="card-surface p-5">
              <div className="flex items-center gap-2 mb-4">
                <Info className="w-4 h-4 text-blue-400" />
                <h3 className="text-sm font-semibold text-white">Translation Notes</h3>
              </div>

              {result.notes.length > 0 ? (
                <div className="space-y-2">
                  {result.notes.map((note, i) => (
                    <div key={i} className="flex items-start gap-2 text-xs text-gray-400">
                      <Info className="w-3 h-3 mt-0.5 flex-shrink-0 text-blue-400" />
                      {note}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-gray-500">No notes.</p>
              )}
            </div>
          </div>
        )}

        {/* Useful Resources */}
        <div className="mt-10">
          <div className="flex items-center gap-2 mb-5">
            <BookOpen className="w-4 h-4 text-gray-500" />
            <h2 className="text-sm font-semibold text-white">Useful Resources</h2>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {[
              {
                title: "Sigma Rule Writing Guide",
                description:
                  "Official Sigma HQ documentation — rule syntax, field modifiers, logsource definitions, and condition logic.",
                label: "Sigma HQ",
                href: "https://sigmahq.io/docs/guide/getting-started.html",
                accent: "text-cyan-400 bg-cyan-400/10 border-cyan-400/20",
                dot: "bg-cyan-400",
              },
              {
                title: "Splunk SPL Reference",
                description:
                  "Splunk Search Processing Language reference — commands, functions, eval expressions, and search optimization.",
                label: "Splunk Docs",
                href: "https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/WhatsInThisManual",
                accent: "text-orange-400 bg-orange-400/10 border-orange-400/20",
                dot: "bg-orange-400",
              },
              {
                title: "PySpark SQL Functions",
                description:
                  "Apache Spark Python API reference — DataFrame operations, SQL functions, window functions, and streaming.",
                label: "Apache Spark Docs",
                href: "https://spark.apache.org/docs/latest/api/python/reference/pyspark.sql/functions.html",
                accent: "text-yellow-400 bg-yellow-400/10 border-yellow-400/20",
                dot: "bg-yellow-400",
              },
            ].map((resource) => (
              <a
                key={resource.title}
                href={resource.href}
                target="_blank"
                rel="noopener noreferrer"
                className="card-surface-hover p-5 block group"
              >
                <div className="flex items-start justify-between gap-2 mb-3">
                  <div className="flex items-center gap-2">
                    <span className={`w-2 h-2 rounded-full ${resource.dot}`} />
                    <span
                      className={`text-xs font-medium border rounded px-2 py-0.5 ${resource.accent}`}
                    >
                      {resource.label}
                    </span>
                  </div>
                  <ExternalLink className="w-3.5 h-3.5 text-gray-600 group-hover:text-gray-400 transition-colors flex-shrink-0" />
                </div>
                <h3 className="text-sm font-semibold text-white mb-1.5 group-hover:text-cyan-300 transition-colors">
                  {resource.title}
                </h3>
                <p className="text-xs text-gray-500 leading-relaxed">{resource.description}</p>
              </a>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
