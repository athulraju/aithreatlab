"use client";

import { useState, useCallback, useEffect } from "react";
import dynamic from "next/dynamic";
import { motion, AnimatePresence } from "framer-motion";
import { PageHeader } from "@/components/PageHeader";
import { Badge } from "@/components/Badge";
import { sigmaToSplunk, ConversionResult } from "@/lib/converters/sigmaToSplunk";
import { sigmaToPySpark } from "@/lib/converters/sigmaToPySpark";
import { splunkToSigma } from "@/lib/converters/splunkToSigma";
import { pysparkToSigma } from "@/lib/converters/pysparkToSigma";
import { splunkToPySpark } from "@/lib/converters/splunkToPySpark";
import { pysparkToSplunk } from "@/lib/converters/pysparkToSplunk";
import { sigmaSample, splunkSample, pysparkSample } from "@/lib/converters/samples";
import { detections } from "@/lib/data/detections/index";
import {
  ArrowRight,
  Copy,
  Download,
  CheckCircle2,
  AlertTriangle,
  Info,
  RefreshCw,
  ExternalLink,
  BookOpen,
} from "lucide-react";

const MonacoEditor = dynamic(() => import("@monaco-editor/react"), { ssr: false });

type Format = "sigma" | "splunk" | "pyspark";

const formatLabels: Record<Format, string> = {
  sigma:   "Sigma YAML",
  splunk:  "Splunk SPL",
  pyspark: "PySpark",
};

const monacoLang: Record<Format, string> = {
  sigma:   "yaml",
  splunk:  "plaintext",
  pyspark: "python",
};

const sampleInputs: Record<Format, string> = {
  sigma:   sigmaSample,
  splunk:  splunkSample,
  pyspark: pysparkSample,
};

const availableConversions: Record<Format, Format[]> = {
  sigma:   ["splunk", "pyspark"],
  splunk:  ["sigma", "pyspark"],
  pyspark: ["sigma", "splunk"],
};

const formatDot: Record<Format, string> = {
  sigma:   "bg-cyan-400",
  splunk:  "bg-orange-400",
  pyspark: "bg-yellow-400",
};

function convert(input: string, from: Format, to: Format): ConversionResult {
  if (from === "sigma"   && to === "splunk")  return sigmaToSplunk(input);
  if (from === "sigma"   && to === "pyspark") return sigmaToPySpark(input);
  if (from === "splunk"  && to === "sigma")   return splunkToSigma(input);
  if (from === "splunk"  && to === "pyspark") return splunkToPySpark(input);
  if (from === "pyspark" && to === "sigma")   return pysparkToSigma(input);
  if (from === "pyspark" && to === "splunk")  return pysparkToSplunk(input);
  return { output: "", notes: [], warnings: [], valid: false };
}

const ease = [0.25, 0.1, 0.25, 1] as const;

function FormatButton({
  fmt,
  active,
  onClick,
}: {
  fmt: Format;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={`relative px-3 py-1.5 rounded-md text-xs font-medium border transition-colors duration-200 ${
        active
          ? "bg-white/10 border-white/20 text-white"
          : "bg-transparent border-white/10 text-gray-500 hover:text-gray-300 hover:border-white/15"
      }`}
    >
      {active && (
        <motion.div
          layoutId="format-active"
          className="absolute inset-0 bg-white/10 rounded-md border border-white/20"
          transition={{ duration: 0.2, ease }}
        />
      )}
      <span className="relative">{formatLabels[fmt]}</span>
    </button>
  );
}

export default function ConverterPage() {
  const [inputFormat,  setInputFormat]  = useState<Format>("sigma");
  const [outputFormat, setOutputFormat] = useState<Format>("splunk");
  const [inputValue,   setInputValue]   = useState(sampleInputs.sigma);
  const [result,       setResult]       = useState<ConversionResult | null>(null);
  const [copied,       setCopied]       = useState(false);
  const [converting,   setConverting]   = useState(false);

  useEffect(() => { document.title = "Converter | AIDetectLab"; }, []);

  const handleConvert = useCallback(async () => {
    setConverting(true);
    // Tiny delay so the button spin is visible — feels more tool-like
    await new Promise((r) => setTimeout(r, 120));
    const r = convert(inputValue, inputFormat, outputFormat);
    setResult(r);
    setConverting(false);
  }, [inputValue, inputFormat, outputFormat]);

  const handleInputFormatChange = (fmt: Format) => {
    setInputFormat(fmt);
    setInputValue(sampleInputs[fmt]);
    setOutputFormat(availableConversions[fmt][0]);
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
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href = url; a.download = `detection.${ext}`; a.click();
    URL.revokeObjectURL(url);
  };

  const handleLoadSample = (id: string) => {
    const det   = detections.find((d) => d.id === id);
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

        {/* Format selectors + convert button */}
        <motion.div
          className="flex flex-col sm:flex-row items-start sm:items-center gap-4 mb-6"
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.35, ease, delay: 0.15 }}
        >
          <div>
            <label className="text-xs text-gray-500 mb-1.5 block">Input Format</label>
            <div className="flex gap-1.5">
              {(["sigma", "splunk", "pyspark"] as Format[]).map((fmt) => (
                <FormatButton
                  key={fmt}
                  fmt={fmt}
                  active={inputFormat === fmt}
                  onClick={() => handleInputFormatChange(fmt)}
                />
              ))}
            </div>
          </div>

          <ArrowRight className="w-4 h-4 text-gray-600 hidden sm:block mt-5" />

          <div>
            <label className="text-xs text-gray-500 mb-1.5 block">Output Format</label>
            <div className="flex gap-1.5">
              {availableConversions[inputFormat].map((fmt) => (
                <FormatButton
                  key={fmt}
                  fmt={fmt}
                  active={outputFormat === fmt}
                  onClick={() => handleOutputFormatChange(fmt)}
                />
              ))}
            </div>
          </div>

          <div className="sm:ml-auto sm:mt-5">
            <motion.button
              onClick={handleConvert}
              disabled={converting}
              whileTap={{ scale: 0.97 }}
              className="flex items-center gap-2 px-5 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 disabled:opacity-60 text-white text-sm font-medium transition-colors shadow-lg shadow-cyan-500/20 hover:shadow-cyan-500/35 cursor-pointer"
            >
              <motion.div animate={{ rotate: converting ? 360 : 0 }} transition={{ repeat: converting ? Infinity : 0, duration: 0.7, ease: "linear" }}>
                <RefreshCw className="w-4 h-4" />
              </motion.div>
              {converting ? "Converting…" : "Convert"}
            </motion.button>
          </div>
        </motion.div>

        {/* Sample rules */}
        <motion.div
          className="flex items-center gap-2 mb-6 flex-wrap"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.3, ease, delay: 0.2 }}
        >
          <span className="text-xs text-gray-600">Load sample:</span>
          {detections.slice(0, 5).map((d) => (
            <button
              key={d.id}
              onClick={() => handleLoadSample(d.id)}
              className="text-xs font-mono text-gray-500 hover:text-cyan-400 bg-white/[0.03] border border-white/[0.06] hover:border-cyan-500/30 px-2 py-0.5 rounded transition-all duration-150 hover:-translate-y-0.5"
            >
              {d.id}
            </button>
          ))}
        </motion.div>

        {/* Editors */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
          {/* Input */}
          <motion.div
            className="card-surface overflow-hidden"
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, ease, delay: 0.1 }}
          >
            <div className="flex items-center justify-between px-4 py-3 border-b border-white/[0.06]">
              <div className="flex items-center gap-2">
                <span className={`w-2 h-2 rounded-full ${formatDot[inputFormat]}`} />
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
                options={{ fontSize: 12, minimap: { enabled: false }, scrollBeyondLastLine: false, lineNumbers: "on", renderLineHighlight: "none", padding: { top: 12, bottom: 12 }, fontFamily: "'JetBrains Mono', monospace" }}
              />
            </div>
          </motion.div>

          {/* Output */}
          <motion.div
            className="card-surface overflow-hidden"
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, ease, delay: 0.18 }}
          >
            <div className="flex items-center justify-between px-4 py-3 border-b border-white/[0.06]">
              <div className="flex items-center gap-2">
                <span className={`w-2 h-2 rounded-full ${formatDot[outputFormat]}`} />
                <span className="text-xs font-medium text-gray-400">{formatLabels[outputFormat]}</span>
              </div>
              <div className="flex items-center gap-2">
                <AnimatePresence>
                  {result?.valid && (
                    <motion.div
                      initial={{ opacity: 0, scale: 0.8 }}
                      animate={{ opacity: 1, scale: 1 }}
                      exit={{ opacity: 0, scale: 0.8 }}
                      transition={{ duration: 0.2, ease }}
                    >
                      <Badge variant="green">Valid</Badge>
                    </motion.div>
                  )}
                </AnimatePresence>
                <button
                  onClick={handleCopy}
                  className="flex items-center gap-1 px-2 py-1 rounded text-xs text-gray-500 hover:text-white hover:bg-white/5 transition-all duration-150"
                >
                  <AnimatePresence mode="wait" initial={false}>
                    {copied
                      ? <motion.span key="check" initial={{ scale: 0.7, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.7, opacity: 0 }} transition={{ duration: 0.15 }}><CheckCircle2 className="w-3 h-3 text-green-400" /></motion.span>
                      : <motion.span key="copy"  initial={{ scale: 0.7, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.7, opacity: 0 }} transition={{ duration: 0.15 }}><Copy className="w-3 h-3" /></motion.span>
                    }
                  </AnimatePresence>
                  {copied ? "Copied" : "Copy"}
                </button>
                <button
                  onClick={handleDownload}
                  className="flex items-center gap-1 px-2 py-1 rounded text-xs text-gray-500 hover:text-white hover:bg-white/5 transition-all duration-150"
                >
                  <Download className="w-3 h-3" />
                  Download
                </button>
              </div>
            </div>
            <div className="h-[420px] relative">
              {!result && (
                <div className="absolute inset-0 flex flex-col items-center justify-center gap-3 z-10 pointer-events-none">
                  <div className="w-10 h-10 rounded-full bg-white/5 flex items-center justify-center">
                    <RefreshCw className="w-4 h-4 text-gray-600" />
                  </div>
                  <p className="text-xs text-gray-600">Press <span className="font-medium text-gray-500">Convert</span> to generate output</p>
                </div>
              )}
              <MonacoEditor
                height="100%"
                language={monacoLang[outputFormat]}
                value={result?.output || ""}
                theme="vs-dark"
                options={{ fontSize: 12, minimap: { enabled: false }, scrollBeyondLastLine: false, readOnly: true, lineNumbers: "on", renderLineHighlight: "none", padding: { top: 12, bottom: 12 }, fontFamily: "'JetBrains Mono', monospace" }}
              />
            </div>
          </motion.div>
        </div>

        {/* Validation + Notes — animate in when result appears */}
        <AnimatePresence>
          {result && (
            <motion.div
              className="grid grid-cols-1 lg:grid-cols-2 gap-4"
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 8 }}
              transition={{ duration: 0.3, ease }}
            >
              {/* Validation */}
              <div className={`card-surface p-5 border transition-colors duration-300 ${
                result.valid ? "border-emerald-500/20" : "border-red-500/20"
              }`}>
                <div className="flex items-center gap-2 mb-4">
                  <AnimatePresence mode="wait" initial={false}>
                    {result.valid
                      ? <motion.div key="ok"   initial={{ scale: 0.7, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.7, opacity: 0 }} transition={{ duration: 0.15 }}><CheckCircle2 className="w-4 h-4 text-emerald-400" /></motion.div>
                      : <motion.div key="warn" initial={{ scale: 0.7, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.7, opacity: 0 }} transition={{ duration: 0.15 }}><AlertTriangle className="w-4 h-4 text-red-400" /></motion.div>
                    }
                  </AnimatePresence>
                  <h3 className="text-sm font-semibold text-white">Validation</h3>
                </div>
                {result.warnings.length > 0 ? (
                  <div className="space-y-2">
                    {result.warnings.map((w, i) => (
                      <div key={i} className="flex items-start gap-2 text-xs text-orange-300">
                        <AlertTriangle className="w-3 h-3 mt-0.5 flex-shrink-0 text-orange-400" />{w}
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
                        <Info className="w-3 h-3 mt-0.5 flex-shrink-0 text-blue-400" />{note}
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-gray-500">No notes.</p>
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Resources */}
        <motion.div
          className="mt-10"
          initial={{ opacity: 0, y: 12 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.4, ease }}
        >
          <div className="flex items-center gap-2 mb-5">
            <BookOpen className="w-4 h-4 text-gray-500" />
            <h2 className="text-sm font-semibold text-white">Useful Resources</h2>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {[
              { title: "Sigma Rule Writing Guide",    description: "Official Sigma HQ documentation: rule syntax, field modifiers, logsource definitions, and condition logic.", label: "Sigma HQ",          href: "https://sigmahq.io/docs/guide/getting-started.html", accent: "text-cyan-400 bg-cyan-400/10 border-cyan-400/20",     dot: "bg-cyan-400" },
              { title: "Splunk SPL Reference",         description: "Splunk Search Processing Language reference: commands, functions, eval expressions, and search optimization.", label: "Splunk Docs",        href: "https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/WhatsInThisManual", accent: "text-orange-400 bg-orange-400/10 border-orange-400/20", dot: "bg-orange-400" },
              { title: "PySpark SQL Functions",        description: "Apache Spark Python API reference: DataFrame operations, SQL functions, window functions, and streaming.", label: "Apache Spark Docs",  href: "https://spark.apache.org/docs/latest/api/python/reference/pyspark.sql/functions.html", accent: "text-yellow-400 bg-yellow-400/10 border-yellow-400/20", dot: "bg-yellow-400" },
            ].map((resource, i) => (
              <motion.a
                key={resource.title}
                href={resource.href}
                target="_blank"
                rel="noopener noreferrer"
                className="card-surface-hover p-5 block group"
                initial={{ opacity: 0, y: 12 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.35, ease, delay: i * 0.07 }}
              >
                <div className="flex items-start justify-between gap-2 mb-3">
                  <div className="flex items-center gap-2">
                    <span className={`w-2 h-2 rounded-full ${resource.dot}`} />
                    <span className={`text-xs font-medium border rounded px-2 py-0.5 ${resource.accent}`}>{resource.label}</span>
                  </div>
                  <ExternalLink className="w-3.5 h-3.5 text-gray-600 group-hover:text-gray-400 transition-colors flex-shrink-0" />
                </div>
                <h3 className="text-sm font-semibold text-white mb-1.5 group-hover:text-cyan-300 transition-colors duration-200">{resource.title}</h3>
                <p className="text-xs text-gray-500 leading-relaxed">{resource.description}</p>
              </motion.a>
            ))}
          </div>
        </motion.div>
      </div>
    </div>
  );
}
