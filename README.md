# AIDetectLab — Detection Engineering Platform

A full-stack platform for building, translating, testing, and operationalizing security detection rules across **Sigma**, **Splunk SPL**, and **PySpark** — with a dedicated **AI Security** layer covering OWASP Top 10 for LLMs and Agentic AI.

---

## Features

| Module | Description |
|---|---|
| **Multi-Format Converter** | Bidirectional translation between all three formats (6 conversion paths) with validation output and translation notes |
| **Detection Library** | Searchable, filterable library of production-grade rules with full logic, tuning guidance, false positive analysis, and deployment notes |
| **Coverage Framework** | Structured visibility across 8 detection layers mapped to MITRE ATT&CK techniques |
| **AI Security** | OWASP Top 10 for LLMs and Agentic AI with monitoring guidance, required log sources, and detection ideas |
| **Detection Playground** | Interactive Monaco Editor workbench to write and validate detections against 5 simulated event scenarios |
| **Research Hub** | Curated technical references — arXiv papers, OWASP standards, conference talks, and blog posts |
| **Agent Skills** | 10 AI-powered detection engineering skills for rule generation, optimization, coverage mapping, and threat analysis |

---

## Architecture

```
detection-engineering-site/
├── app/                        # Next.js App Router pages
│   ├── page.tsx                # Landing page
│   ├── layout.tsx              # Root layout (Navbar, Footer)
│   ├── converter/              # Multi-format converter
│   ├── detections/             # Detection library + detail views
│   ├── coverage/               # Coverage framework
│   ├── ai-security/            # OWASP LLM & Agentic AI Top 10
│   ├── playground/             # Interactive detection workbench
│   ├── research/               # Research hub
│   ├── agent-skills/           # AI agent skill catalog
│   └── about/                  # About page
│
├── components/                 # Shared UI components
│   ├── Navbar.tsx
│   ├── Footer.tsx
│   ├── Badge.tsx
│   ├── Logo.tsx
│   └── PageHeader.tsx
│
├── lib/
│   ├── converters/             # 6 bidirectional converter engines
│   │   ├── sigmaToSplunk.ts
│   │   ├── sigmaToPySpark.ts
│   │   ├── splunkToSigma.ts
│   │   ├── splunkToPySpark.ts
│   │   ├── pysparkToSigma.ts
│   │   ├── pysparkToSplunk.ts
│   │   └── samples.ts          # Sample rules for each format
│   │
│   ├── data/                   # Static data layer
│   │   ├── detections/
│   │   │   ├── types.ts        # Detection interface
│   │   │   ├── core.ts         # Core detection rules
│   │   │   ├── oci.ts          # Oracle Cloud Infrastructure rules
│   │   │   ├── oci-linux-asi.ts# OCI Linux + AI Security rules
│   │   │   └── index.ts        # Aggregated exports + filter metadata
│   │   ├── coverage.ts         # Coverage items + 8-layer taxonomy
│   │   ├── aiSecurity.ts       # OWASP LLM & Agentic Top 10 data
│   │   ├── research.ts         # Research links and sections
│   │   └── agentSkills.ts      # Agent skill definitions
│   │
│   ├── skills/                 # AI agent skill prompts (10 skills)
│   │   ├── detection-generator.ts
│   │   ├── detection-rule-optimizer.ts
│   │   ├── detection-coverage-mapper.ts
│   │   ├── detection-consistency-checker.ts
│   │   ├── prompt-injection-detector.ts
│   │   ├── tool-misuse-detector.ts
│   │   ├── goal-drift-detector.ts
│   │   ├── data-exfiltration-detector.ts
│   │   ├── log-anomaly-analyzer.ts
│   │   └── pyspark-query-reviewer.ts
│   │
│   ├── motion.ts               # Framer Motion animation variants
│   └── utils.ts                # Tailwind class utilities (cn)
│
├── public/                     # Static assets
├── next.config.js
├── tailwind.config.ts
└── tsconfig.json
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Framework | [Next.js 14](https://nextjs.org/) (App Router, React Server Components) |
| Language | TypeScript 5 |
| Styling | Tailwind CSS 3 |
| Animations | Framer Motion 11 |
| Code Editor | Monaco Editor (`@monaco-editor/react`) |
| UI Primitives | Radix UI (Tabs, Select, Dialog, Tooltip, ScrollArea) |
| Icons | Lucide React |
| Utilities | clsx, tailwind-merge, class-variance-authority |

---

## Detection Data Model

Each detection rule carries the full operational context needed to deploy and maintain it:

```typescript
interface Detection {
  id: string;
  title: string;
  description: string;
  platform: string[];           // Windows, Linux, Cloud, AWS, OCI, Network, AI/ML
  mitre: string[];              // ATT&CK technique IDs
  category: string;             // Execution, Credential Access, Persistence, etc.
  maturity: "production" | "stable" | "experimental" | "deprecated";
  severity: "critical" | "high" | "medium" | "low";
  sigma: string;                // Sigma YAML rule
  splunk: string;               // Splunk SPL query
  pyspark: string;              // PySpark / Spark SQL query
  sampleLogs: string[];
  requiredFields: string[];
  falsePositives: string[];
  tuningGuidance: string;
  deploymentNotes: string;
  evasionConsiderations: string;
  problemStatement: string;
}
```

---

## Coverage Framework

Detection coverage is organized across **8 layers**, each mapped to MITRE ATT&CK:

| Layer | Description |
|---|---|
| Host OS | Process execution, file system, registry, scheduled tasks |
| Host Application | Application-level events, web servers, databases |
| Host Network | Host-based firewall, DNS, socket activity |
| Middle Network | East-west traffic, IDS/IPS, network flow |
| Large Application | SaaS platforms, collaboration tools, email |
| Identity | Authentication, MFA, directory services, privilege changes |
| Perimeter | Edge firewall, VPN, proxy, ingress/egress |
| AI Security Extension | LLM API calls, agent actions, prompt injection, tool misuse |

Coverage items track `coverageType` (`rule-based` / `ml-based` / `hybrid` / `planned`) and `maturity` (`production` / `stable` / `experimental` / `planned`).

---

## Converter

All six bidirectional conversion paths are supported:

```
Sigma       ←→  Splunk SPL
Sigma       ←→  PySpark
Splunk SPL  ←→  PySpark
```

The converter provides:
- Syntax-highlighted Monaco Editor input/output panels
- Per-conversion validation status and translation notes
- One-click copy and download of output
- Load-from-library: import any detection from the library directly into the converter

---

## Detection Playground

The playground provides an interactive Monaco Editor environment with **5 pre-built event scenarios**:

| Scenario | Description |
|---|---|
| Data Exfiltration | Large volume transfer to external IP — PySpark query |
| Login Anomaly | Impossible travel & MFA fatigue pattern — Sigma YAML |
| Agent Misuse | AI agent accessing out-of-scope resources — JavaScript logs |
| Cloud Audit Trail | AWS IAM privilege escalation sequence — CloudTrail events |
| Endpoint Execution | LOLBin execution chain on Windows host — Sigma YAML |

---

## AI Security Module

Covers **OWASP Top 10 for LLMs** and **OWASP Top 10 for Agentic AI**, each entry including:

- Threat description and attack vectors
- Detection ideas and monitoring signals
- Required log sources
- Protection and mitigation guidance

Threat categories include: Prompt Injection, Insecure Output Handling, Tool Misuse, Agent Goal Drift, Data Exfiltration via LLM, Sensitive Information Disclosure, API Abuse, Supply Chain Attacks, and more.

---

## Agent Skills

10 AI-powered skills designed for use in detection engineering workflows:

| Skill | Purpose |
|---|---|
| Detection Generator | Generates Sigma, Splunk, and PySpark rules from a threat description |
| Detection Rule Optimizer | Reviews and improves existing detection logic |
| Detection Coverage Mapper | Maps a rule set against MITRE ATT&CK coverage gaps |
| Detection Consistency Checker | Validates cross-format rule equivalence |
| Prompt Injection Detector | Analyzes LLM inputs for injection patterns |
| Tool Misuse Detector | Identifies unauthorized agent tool usage |
| Goal Drift Detector | Detects agentic AI deviation from intended behavior |
| Data Exfiltration Detector | Surfaces suspicious data movement patterns |
| Log Anomaly Analyzer | Identifies statistical outliers in log streams |
| PySpark Query Reviewer | Reviews Spark SQL queries for correctness and efficiency |

---

## Getting Started

**Prerequisites:** Node.js 18+

```bash
# Install dependencies
npm install

# Start development server (runs on port 8000)
npm run dev

# Build for production
npm run build

# Start production server
npm start
```

The app runs at `http://localhost:8000`.

---

## Project Conventions

- **Data-only files** live under `lib/data/` — no React, no side effects.
- **Converter engines** under `lib/converters/` are pure functions: `(input: string) => ConversionResult`.
- **Pages** are thin: they import from `lib/data/` and delegate rendering to co-located components.
- **Animations** use shared Framer Motion variants from `lib/motion.ts` (`fadeUp`, `staggerContainer`, `staggerItem`, `revealItem`).
- **Dark-only UI** — the `dark` class is set on `<html>` globally; no light-mode toggle exists.
