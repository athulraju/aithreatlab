"use client";

import Link from "next/link";
import { notFound } from "next/navigation";
import { getArticleById } from "@/lib/data/research";
import { formatDate } from "@/lib/utils";
import { ArrowLeft, Clock, Calendar } from "lucide-react";

const categoryColors: Record<string, string> = {
  "Detection Engineering": "text-cyan-400 bg-cyan-400/10 border-cyan-400/20",
  "AI Security": "text-purple-400 bg-purple-400/10 border-purple-400/20",
  "Insider Threat": "text-orange-400 bg-orange-400/10 border-orange-400/20",
  "Sigma Portability": "text-blue-400 bg-blue-400/10 border-blue-400/20",
  "PySpark Detections": "text-yellow-400 bg-yellow-400/10 border-yellow-400/20",
  "Class Imbalance": "text-red-400 bg-red-400/10 border-red-400/20",
  "Agent Detection": "text-violet-400 bg-violet-400/10 border-violet-400/20",
};

function renderMarkdown(content: string) {
  // Very simple markdown-like rendering
  const lines = content.split("\n");
  const elements: React.ReactNode[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    if (line.startsWith("## ")) {
      elements.push(
        <h2 key={i} className="text-xl font-bold text-white mt-8 mb-4">
          {line.slice(3)}
        </h2>
      );
    } else if (line.startsWith("### ")) {
      elements.push(
        <h3 key={i} className="text-base font-semibold text-white mt-6 mb-3">
          {line.slice(4)}
        </h3>
      );
    } else if (line.startsWith("```")) {
      const lang = line.slice(3).trim();
      const codeLines: string[] = [];
      i++;
      while (i < lines.length && !lines[i].startsWith("```")) {
        codeLines.push(lines[i]);
        i++;
      }
      elements.push(
        <pre
          key={i}
          className="bg-black/40 border border-white/[0.06] rounded-lg p-4 overflow-x-auto text-xs font-mono text-gray-300 my-4 leading-relaxed"
        >
          {codeLines.join("\n")}
        </pre>
      );
    } else if (line.startsWith("- **")) {
      const match = line.match(/- \*\*(.+?)\*\*:?\s*(.*)/);
      if (match) {
        elements.push(
          <li key={i} className="text-sm text-gray-400 mb-2 ml-4 list-disc">
            <strong className="text-white">{match[1]}</strong>
            {match[2] ? `: ${match[2]}` : ""}
          </li>
        );
      }
    } else if (line.startsWith("- ")) {
      elements.push(
        <li key={i} className="text-sm text-gray-400 mb-2 ml-4 list-disc">
          {line.slice(2)}
        </li>
      );
    } else if (line.startsWith("1. ") || line.match(/^\d+\. /)) {
      elements.push(
        <li key={i} className="text-sm text-gray-400 mb-2 ml-4 list-decimal">
          {line.replace(/^\d+\. /, "")}
        </li>
      );
    } else if (line.startsWith("|")) {
      // Table row
      const cells = line.split("|").filter(Boolean).map((c) => c.trim());
      const isHeader = lines[i + 1]?.includes("---");
      elements.push(
        <tr key={i} className={isHeader ? "border-b border-white/10" : "border-b border-white/[0.04]"}>
          {cells.map((cell, ci) => (
            isHeader ? (
              <th key={ci} className="px-3 py-2 text-left text-xs font-medium text-gray-400">
                {cell}
              </th>
            ) : (
              <td key={ci} className="px-3 py-2 text-xs text-gray-500">
                {cell}
              </td>
            )
          ))}
        </tr>
      );
      if (isHeader) i++; // skip separator row
    } else if (line.trim() === "") {
      // skip blank lines within context
    } else {
      // Regular paragraph
      const formatted = line
        .replace(/\*\*(.+?)\*\*/g, '<strong class="text-white">$1</strong>')
        .replace(/`(.+?)`/g, '<code class="text-cyan-300 font-mono text-xs bg-cyan-400/10 px-1 py-0.5 rounded">$1</code>');

      elements.push(
        <p
          key={i}
          className="text-sm text-gray-400 leading-relaxed mb-4"
          dangerouslySetInnerHTML={{ __html: formatted }}
        />
      );
    }

    i++;
  }

  return elements;
}

export default function ArticlePage({ params }: { params: { id: string } }) {
  const article = getArticleById(params.id);
  if (!article) notFound();

  return (
    <div className="pt-14 min-h-screen">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
        <Link
          href="/research"
          className="inline-flex items-center gap-1.5 text-sm text-gray-500 hover:text-white transition-colors mb-8"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          Research
        </Link>

        {/* Article Header */}
        <div className="mb-10">
          <div className="flex items-center gap-2 flex-wrap mb-4">
            <span
              className={`inline-flex items-center text-xs font-medium border rounded px-2 py-0.5 ${
                categoryColors[article.category] || "text-gray-400 bg-white/5 border-white/10"
              }`}
            >
              {article.category}
            </span>
            {article.tags.slice(0, 4).map((tag) => (
              <span
                key={tag}
                className="text-xs text-gray-600 bg-white/[0.03] border border-white/[0.05] rounded px-2 py-0.5"
              >
                {tag}
              </span>
            ))}
          </div>

          <h1 className="text-2xl sm:text-3xl font-bold text-white mb-4 leading-snug">
            {article.title}
          </h1>

          <p className="text-gray-400 text-base leading-relaxed mb-5">
            {article.summary}
          </p>

          <div className="flex items-center gap-4 text-xs text-gray-600">
            <div className="flex items-center gap-1.5">
              <Calendar className="w-3.5 h-3.5" />
              {formatDate(article.date)}
            </div>
            <div className="flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5" />
              {article.readTime} min read
            </div>
          </div>
        </div>

        {/* Article Content */}
        <div className="prose prose-sm max-w-none">
          <div className="space-y-1">
            {renderMarkdown(article.content)}
          </div>
        </div>
      </div>
    </div>
  );
}
