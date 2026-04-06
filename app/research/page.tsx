"use client";

import { useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/PageHeader";
import { articles, articleCategories } from "@/lib/data/research";
import { formatDate } from "@/lib/utils";
import { Clock, ChevronRight, Star } from "lucide-react";

const categoryColors: Record<string, string> = {
  "Detection Engineering": "text-cyan-400 bg-cyan-400/10 border-cyan-400/20",
  "AI Security": "text-purple-400 bg-purple-400/10 border-purple-400/20",
  "Insider Threat": "text-orange-400 bg-orange-400/10 border-orange-400/20",
  "Sigma Portability": "text-blue-400 bg-blue-400/10 border-blue-400/20",
  "PySpark Detections": "text-yellow-400 bg-yellow-400/10 border-yellow-400/20",
  "Class Imbalance": "text-red-400 bg-red-400/10 border-red-400/20",
  "Agent Detection": "text-violet-400 bg-violet-400/10 border-violet-400/20",
};

export default function ResearchPage() {
  const [selectedCategory, setSelectedCategory] = useState("All");

  const filtered = articles.filter(
    (a) => selectedCategory === "All" || a.category === selectedCategory
  );

  const featured = filtered.filter((a) => a.featured);
  const regular = filtered.filter((a) => !a.featured);

  return (
    <div className="pt-14 min-h-screen">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
        <PageHeader
          eyebrow="Research"
          title="Detection Engineering Research"
          description="Technical articles on detection engineering, AI security, PySpark analytics, and security ML."
        />

        {/* Category Filters */}
        <div className="flex flex-wrap gap-2 mb-8">
          {articleCategories.map((cat) => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`px-3 py-1.5 rounded-md text-xs font-medium border transition-all ${
                selectedCategory === cat
                  ? "bg-white/10 border-white/20 text-white"
                  : "bg-transparent border-white/[0.08] text-gray-500 hover:text-gray-300 hover:border-white/15"
              }`}
            >
              {cat}
            </button>
          ))}
        </div>

        {/* Featured Articles */}
        {featured.length > 0 && (
          <div className="mb-10">
            <p className="text-xs font-semibold text-gray-600 uppercase tracking-wider mb-4">Featured</p>
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              {featured.map((article) => (
                <Link
                  key={article.id}
                  href={`/research/${article.id}`}
                  className="card-surface-hover p-6 group block"
                >
                  <div className="flex items-start justify-between mb-3">
                    <span
                      className={`inline-flex items-center text-xs font-medium border rounded px-2 py-0.5 ${
                        categoryColors[article.category] || "text-gray-400 bg-white/5 border-white/10"
                      }`}
                    >
                      {article.category}
                    </span>
                    <Star className="w-3.5 h-3.5 text-yellow-400/50 flex-shrink-0" />
                  </div>

                  <h3 className="text-sm font-semibold text-white mb-2.5 group-hover:text-cyan-300 transition-colors leading-snug">
                    {article.title}
                  </h3>

                  <p className="text-xs text-gray-500 leading-relaxed mb-4 line-clamp-3">
                    {article.summary}
                  </p>

                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3 text-xs text-gray-600">
                      <span>{formatDate(article.date)}</span>
                      <div className="flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {article.readTime} min
                      </div>
                    </div>
                    <ChevronRight className="w-3.5 h-3.5 text-gray-600 group-hover:text-cyan-400 transition-colors" />
                  </div>
                </Link>
              ))}
            </div>
          </div>
        )}

        {/* Regular Articles */}
        {regular.length > 0 && (
          <div>
            <p className="text-xs font-semibold text-gray-600 uppercase tracking-wider mb-4">All Articles</p>
            <div className="space-y-3">
              {regular.map((article) => (
                <Link
                  key={article.id}
                  href={`/research/${article.id}`}
                  className="card-surface-hover p-5 group block"
                >
                  <div className="flex items-start gap-4">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap mb-2">
                        <span
                          className={`inline-flex items-center text-xs font-medium border rounded px-2 py-0.5 ${
                            categoryColors[article.category] || "text-gray-400 bg-white/5 border-white/10"
                          }`}
                        >
                          {article.category}
                        </span>
                        <div className="flex items-center gap-1 text-xs text-gray-600">
                          <Clock className="w-3 h-3" />
                          {article.readTime} min read
                        </div>
                      </div>
                      <h3 className="text-sm font-semibold text-white mb-1.5 group-hover:text-cyan-300 transition-colors">
                        {article.title}
                      </h3>
                      <p className="text-xs text-gray-500 leading-relaxed line-clamp-2">{article.summary}</p>
                    </div>
                    <div className="flex-shrink-0">
                      <ChevronRight className="w-4 h-4 text-gray-600 group-hover:text-cyan-400 mt-1 transition-colors" />
                    </div>
                  </div>
                </Link>
              ))}
            </div>
          </div>
        )}

        {filtered.length === 0 && (
          <div className="text-center py-16 text-gray-600">
            <p className="text-sm">No articles in this category yet.</p>
          </div>
        )}
      </div>
    </div>
  );
}
