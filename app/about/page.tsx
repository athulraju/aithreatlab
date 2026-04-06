import { PageHeader } from "@/components/PageHeader";
import { MapPin, Mail, Linkedin, Github } from "lucide-react";

export default function AboutPage() {
  return (
    <div className="pt-14 min-h-screen">
      <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
        <p className="text-xs font-semibold text-cyan-400 uppercase tracking-widest mb-3">About</p>
        <h1 className="text-3xl sm:text-4xl font-bold text-white mb-1 tracking-tight">
          Athul Raju
        </h1>
        <p className="text-base text-gray-400 mb-8">Detection & Response Engineer · AI Security Researcher</p>

        <div className="space-y-4 text-gray-400 leading-relaxed mb-10">
          <p>
            Detection engineer focused on building scalable, portable, and operationally effective detections across cloud, endpoint, identity, and AI security domains. I work across Sigma, Splunk SPL, PySpark, and cloud-native platforms to bridge the gap between raw telemetry and actionable security logic.
          </p>
          <p>
            AIDetectLab reflects my approach to detection engineering — structured coverage frameworks, multi-format rule portability, behavioral analytics at scale, and staying ahead of emerging threats in AI-integrated environments including OCI cloud and autonomous agent systems.
          </p>
          <p className="text-gray-500 text-sm">
            Current focus: detection engineering for agentic AI systems, OWASP LLM and Agentic Top 10 threat coverage, and OCI cloud detection patterns.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3 mb-10">
          <div className="flex items-center gap-1.5 text-xs text-gray-600">
            <MapPin className="w-3.5 h-3.5" />
            Detection Engineering & AI Security
          </div>
          <span className="text-gray-700">·</span>
          <div className="flex items-center gap-1.5 text-xs text-emerald-400">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            Open to collaboration
          </div>
        </div>

        <div className="flex items-center gap-3">
          <a
            href="https://www.linkedin.com/in/athul-raju-38745552"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] border border-white/10 text-xs text-gray-400 hover:text-white transition-all"
          >
            <Linkedin className="w-3.5 h-3.5" />
            LinkedIn
          </a>
          <a
            href="#"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] border border-white/10 text-xs text-gray-400 hover:text-white transition-all"
          >
            <Github className="w-3.5 h-3.5" />
            GitHub
          </a>
          <a
            href="mailto:contact@aidetectlab.io"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] border border-white/10 text-xs text-gray-400 hover:text-white transition-all"
          >
            <Mail className="w-3.5 h-3.5" />
            Contact
          </a>
        </div>
      </div>
    </div>
  );
}
