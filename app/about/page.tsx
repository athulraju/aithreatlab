import { PageHeader } from "@/components/PageHeader";
import {
  MapPin,
  Mail,
  Linkedin,
  Github,
  Shield,
  Brain,
  Cloud,
  BarChart3,
  Terminal,
  BookOpen,
  ExternalLink,
  CheckCircle2,
  Database,
  Code2,
} from "lucide-react";
import Link from "next/link";

const focusAreas = [
  {
    icon: Shield,
    title: "Detection Engineering",
    description:
      "Building scalable, portable detections across Sigma, Splunk SPL, and PySpark. Focused on detection lifecycle management, coverage frameworks, and rule quality.",
    color: "text-cyan-400 bg-cyan-400/10",
  },
  {
    icon: BarChart3,
    title: "UEBA & Behavioral Analytics",
    description:
      "User and Entity Behavior Analytics using statistical baselining and machine learning at scale. Handling class imbalance and model evaluation in security contexts.",
    color: "text-blue-400 bg-blue-400/10",
  },
  {
    icon: Cloud,
    title: "Cloud Security Detections",
    description:
      "AWS and OCI cloud detection engineering — CloudTrail analytics, IAM anomaly detection, and cloud-native threat coverage across multi-cloud environments.",
    color: "text-yellow-400 bg-yellow-400/10",
  },
  {
    icon: Brain,
    title: "AI Security",
    description:
      "Threat modeling and detection for LLM deployments and autonomous AI agent architectures. Covering prompt injection, tool misuse, and agentic threat patterns.",
    color: "text-purple-400 bg-purple-400/10",
  },
];

const skills = [
  { group: "Detection Formats", items: ["Sigma", "Splunk SPL", "PySpark", "KQL / Sentinel", "Elastic DSL"] },
  { group: "Cloud Platforms", items: ["AWS (CloudTrail, GuardDuty, IAM)", "OCI (Audit Logs, IAM)", "Azure (Sentinel, Defender)"] },
  { group: "Analytics & ML", items: ["UEBA Baselining", "Anomaly Detection", "Isolation Forest", "Class Imbalance Handling", "PySpark ML"] },
  { group: "Security Domains", items: ["Endpoint Detection (EDR)", "Identity & IAM", "Network Detections", "AI/LLM Security", "Insider Threat"] },
];

const experience = [
  {
    role: "Detection & Response Engineer",
    company: "Enterprise Security — Financial Services",
    period: "2022 — Present",
    highlights: [
      "Designed and maintains a detection coverage framework spanning 8 layers — Host OS, Application, Network, Identity, Cloud, and AI Security",
      "Built a PySpark-based UEBA pipeline for behavioral anomaly detection at scale, handling significant class imbalance in security event data",
      "Developed OCI and AWS cloud detection capabilities covering IAM policy changes, privilege escalation, and data exfiltration patterns",
      "Led detection portability initiative translating Sigma rules across Splunk, Elastic, and Microsoft Sentinel backends",
      "Implemented AI Security detection layer covering OWASP LLM Top 10 threats as the company expanded its LLM-integrated product surface",
    ],
  },
  {
    role: "Security Operations & Detection",
    company: "Managed Security Services",
    period: "2019 — 2022",
    highlights: [
      "Authored Sigma rules for cross-platform threat detection — Windows endpoint, Linux, cloud audit logs, and network telemetry",
      "Built detection coverage for credential access, lateral movement, and privilege escalation across hybrid environments",
      "Collaborated with red team to identify detection gaps and improve coverage across MITRE ATT&CK framework",
      "Introduced PySpark as a complement to SIEM for large-scale behavioral detection workloads",
    ],
  },
  {
    role: "SOC Analyst",
    company: "Information Security Team",
    period: "2017 — 2019",
    highlights: [
      "Performed triage, investigation, and escalation of security events across endpoint, network, and cloud platforms",
      "Developed triage playbooks that reduced mean response time and improved analyst consistency",
      "Identified recurring detection gaps that drove the transition toward engineering-led detection development",
    ],
  },
];

const projects = [
  {
    title: "DetectLab Platform",
    description:
      "This platform — a full detection engineering workbench with multi-format converter, searchable detection library, 8-layer coverage framework, AI Security module, and interactive playground.",
    tags: ["Next.js", "TypeScript", "Sigma", "PySpark", "Monaco Editor"],
    href: "/",
  },
  {
    title: "OCI Audit Log Detection Library",
    description:
      "Detection suite for Oracle Cloud Infrastructure covering object storage exfiltration, IAM policy abuse, API key persistence, login anomalies, and cross-compartment lateral movement.",
    tags: ["OCI", "Sigma", "PySpark", "Cloud Detections"],
    href: "/detections",
  },
  {
    title: "AI Agent Threat Detection Framework",
    description:
      "Detection engineering framework for AI agent threats — tool misuse, goal drift, data exfiltration via agent APIs, and multi-agent trust exploitation. Based on OWASP Agentic Top 10.",
    tags: ["AI Security", "LLM", "Agent Detection"],
    href: "/ai-security",
  },
];

const researchInterests = [
  "Detection portability across SIEM platforms (Sigma → SPL → KQL)",
  "Behavioral analytics and UEBA at petabyte scale with PySpark",
  "ML evaluation frameworks for imbalanced security datasets",
  "LLM and agentic AI threat modeling and detection",
  "OCI and multi-cloud detection engineering patterns",
  "Graph-based lateral movement and privilege escalation detection",
  "Detection engineering process, lifecycle, and quality metrics",
  "Insider threat detection using statistical and ML methods",
];

export default function AboutPage() {
  return (
    <div className="pt-14 min-h-screen">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
        {/* Profile Header */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-14">
          <div className="lg:col-span-2">
            <p className="text-xs font-semibold text-cyan-400 uppercase tracking-widest mb-3">About</p>
            <h1 className="text-3xl sm:text-4xl font-bold text-white mb-1 tracking-tight">
              Athul Raju
            </h1>
            <p className="text-base text-gray-400 mb-5">Detection & Response Engineer · AI Security Researcher</p>

            <p className="text-gray-400 leading-relaxed mb-4 max-w-xl">
              Detection engineer with a focus on building scalable, portable, and operationally effective detections across cloud, endpoint, identity, and AI security domains. I work across Sigma, Splunk, PySpark, and cloud-native platforms to bridge the gap between raw telemetry and actionable detections.
            </p>
            <p className="text-gray-500 text-sm leading-relaxed max-w-xl">
              This platform reflects my approach to detection engineering — structured coverage frameworks, multi-format rule portability, behavioral analytics at scale, and staying ahead of emerging threats in AI-integrated environments including OCI cloud and autonomous agent systems.
            </p>

            <div className="flex items-center gap-3 mt-4">
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

            <div className="flex items-center gap-3 mt-5">
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
                href="mailto:contact@detectlab.io"
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] border border-white/10 text-xs text-gray-400 hover:text-white transition-all"
              >
                <Mail className="w-3.5 h-3.5" />
                Contact
              </a>
            </div>
          </div>

          {/* Quick stats */}
          <div className="space-y-3">
            {[
              { label: "Years in Security", value: "12+" },
              { label: "Detection Formats", value: "Sigma · SPL · PySpark" },
              { label: "Cloud Platforms", value: "AWS · OCI · Azure" },
              { label: "Key Focus", value: "Detection & AI Security" },
            ].map((stat) => (
              <div key={stat.label} className="card-surface p-4">
                <div className="text-sm font-bold text-white mb-0.5">{stat.value}</div>
                <div className="text-xs text-gray-500">{stat.label}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Focus Areas */}
        <section className="mb-14">
          <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-6">Focus Areas</p>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {focusAreas.map((area) => (
              <div key={area.title} className="card-surface p-5">
                <div className={`w-9 h-9 rounded-lg flex items-center justify-center mb-4 ${area.color}`}>
                  <area.icon className="w-5 h-5" />
                </div>
                <h3 className="text-sm font-semibold text-white mb-2">{area.title}</h3>
                <p className="text-xs text-gray-500 leading-relaxed">{area.description}</p>
              </div>
            ))}
          </div>
        </section>

        {/* Skills */}
        <section className="mb-14">
          <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-6">Skills & Tooling</p>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {skills.map((group) => (
              <div key={group.group} className="card-surface p-5">
                <p className="text-xs font-semibold text-gray-400 mb-3">{group.group}</p>
                <div className="flex flex-wrap gap-1.5">
                  {group.items.map((item) => (
                    <span
                      key={item}
                      className="text-xs text-gray-500 bg-white/[0.04] border border-white/[0.07] rounded px-2 py-0.5"
                    >
                      {item}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* Experience */}
        <section className="mb-14">
          <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-6">Experience</p>
          <div className="space-y-4">
            {experience.map((exp) => (
              <div key={exp.role} className="card-surface p-6">
                <div className="flex items-start justify-between gap-4 mb-4">
                  <div>
                    <h3 className="text-sm font-semibold text-white">{exp.role}</h3>
                    <p className="text-xs text-gray-500 mt-0.5">{exp.company}</p>
                  </div>
                  <span className="text-xs text-gray-600 flex-shrink-0">{exp.period}</span>
                </div>
                <ul className="space-y-2">
                  {exp.highlights.map((h) => (
                    <li key={h} className="flex items-start gap-2 text-xs text-gray-400">
                      <CheckCircle2 className="w-3.5 h-3.5 text-cyan-500/60 flex-shrink-0 mt-0.5" />
                      {h}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </section>

        {/* Projects */}
        <section className="mb-14">
          <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-6">Projects</p>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {projects.map((project) => (
              <Link key={project.title} href={project.href} className="card-surface-hover p-5 block group">
                <div className="flex items-start justify-between gap-2 mb-2">
                  <h3 className="text-sm font-semibold text-white group-hover:text-cyan-300 transition-colors">
                    {project.title}
                  </h3>
                  <ExternalLink className="w-3.5 h-3.5 text-gray-600 group-hover:text-cyan-400 flex-shrink-0 transition-colors" />
                </div>
                <p className="text-xs text-gray-500 leading-relaxed mb-3">{project.description}</p>
                <div className="flex flex-wrap gap-1.5">
                  {project.tags.map((tag) => (
                    <span
                      key={tag}
                      className="text-xs text-gray-600 bg-white/[0.03] border border-white/[0.05] rounded px-2 py-0.5"
                    >
                      {tag}
                    </span>
                  ))}
                </div>
              </Link>
            ))}
          </div>
        </section>

        {/* Research Interests */}
        <section className="mb-14">
          <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-6">Research Interests</p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {researchInterests.map((interest) => (
              <div key={interest} className="flex items-center gap-2.5 card-surface px-4 py-3">
                <BookOpen className="w-3.5 h-3.5 text-cyan-400/60 flex-shrink-0" />
                <span className="text-sm text-gray-400">{interest}</span>
              </div>
            ))}
          </div>
        </section>

        {/* Talks */}
        <section className="mb-14">
          <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-6">Talks & Research Direction</p>
          <div className="space-y-3">
            {[
              {
                title: "Detection Engineering for OCI: Cloud Audit Log Analysis and Coverage Frameworks",
                venue: "Cloud Security Engineering Forum",
                year: "2024",
                type: "Talk",
              },
              {
                title: "Sigma at Scale: Portability, Translation Fidelity, and Cross-Platform Testing",
                venue: "Detection Engineering Summit",
                year: "2024",
                type: "Talk",
              },
              {
                title: "Behavioral Detections with PySpark: Class Imbalance and Operational ML for Security",
                venue: "Security Data Science Conference",
                year: "2024",
                type: "Talk",
              },
              {
                title: "Detecting AI Agent Threats: From Prompt Injection to Tool Misuse and Goal Drift",
                venue: "AI Security Research Workshop",
                year: "2024",
                type: "Paper",
              },
              {
                title: "UEBA at Scale: Lessons from Building Behavioral Analytics Pipelines",
                venue: "SIEM & Analytics Track, SecOps Conference",
                year: "2023",
                type: "Talk",
              },
            ].map((talk) => (
              <div key={talk.title} className="card-surface p-4 flex items-center justify-between gap-4">
                <div>
                  <h3 className="text-sm text-white mb-1">{talk.title}</h3>
                  <p className="text-xs text-gray-500">{talk.venue} · {talk.year}</p>
                </div>
                <span className={`text-xs font-medium border rounded px-2 py-0.5 flex-shrink-0 ${
                  talk.type === "Paper"
                    ? "text-purple-400 bg-purple-400/10 border-purple-400/20"
                    : "text-cyan-400 bg-cyan-400/10 border-cyan-400/20"
                }`}>
                  {talk.type}
                </span>
              </div>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}
