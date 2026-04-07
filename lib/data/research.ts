export interface ResearchLink {
  title: string;
  description: string;
  url: string;
  source: "arXiv" | "paper" | "blog" | "report" | "conference" | "standard";
}

export interface ResearchSection {
  id: string;
  title: string;
  links: ResearchLink[];
}

export const researchSections: ResearchSection[] = [
  {
    id: "ai-security",
    title: "AI Security",
    links: [
      {
        title: "Universal and Transferable Adversarial Attacks on Aligned Language Models",
        description: "Demonstrates that suffix-based adversarial attacks can reliably jailbreak aligned LLMs, challenging the robustness of RLHF-based safety training.",
        url: "https://arxiv.org/abs/2307.15043",
        source: "arXiv",
      },
      {
        title: "OWASP Top 10 for Large Language Model Applications (2025)",
        description: "The definitive practitioner reference for LLM security risks, prompt injection, insecure output handling, supply chain vulnerabilities, and more.",
        url: "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        source: "standard",
      },
      {
        title: "Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications",
        description: "First systematic analysis of prompt injection in real-world LLM integrations, introducing the concept of indirect injection via external data sources.",
        url: "https://arxiv.org/abs/2302.12173",
        source: "arXiv",
      },
      {
        title: "Baseline Defenses for Adversarial Attacks Against Aligned Language Models",
        description: "Evaluates detection and mitigation strategies against adversarial prompt attacks including perplexity filtering and paraphrasing.",
        url: "https://arxiv.org/abs/2309.00614",
        source: "arXiv",
      },
      {
        title: "Securing LLM Systems Against Prompt Injection",
        description: "Practical defense architectures for LLM deployments, covering sandboxing, output validation, and privilege separation patterns.",
        url: "https://research.nccgroup.com/",
        source: "blog",
      },
      {
        title: "Red-Teaming Large Language Models",
        description: "Anthropic's framework for systematic adversarial evaluation of LLMs, covering threat taxonomies and structured attack methodologies.",
        url: "https://arxiv.org/abs/2202.03286",
        source: "arXiv",
      },
      {
        title: "AI Security Risk Assessment Framework",
        description: "NIST guidance for assessing and managing risks specific to AI systems across the full development and deployment lifecycle.",
        url: "https://www.nist.gov/artificial-intelligence",
        source: "report",
      },
      {
        title: "SaTML '24: Security and Privacy of Machine Learning",
        description: "Proceedings covering adversarial robustness, privacy attacks on ML models, and emerging AI security research from the 2024 IEEE SaTML conference.",
        url: "https://satml.org/",
        source: "conference",
      },
    ],
  },
  {
    id: "agentic-ai",
    title: "Agentic AI",
    links: [
      {
        title: "OWASP Top 10 for Agentic AI Applications",
        description: "Security risks specific to autonomous AI agents, unsafe tool invocation, goal drift, multi-agent trust exploitation, and data exfiltration patterns.",
        url: "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        source: "standard",
      },
      {
        title: "ReAct: Synergizing Reasoning and Acting in Language Models",
        description: "Foundational paper introducing the ReAct pattern that enables LLMs to interleave reasoning and action, forming the basis of modern agentic architectures.",
        url: "https://arxiv.org/abs/2210.03629",
        source: "arXiv",
      },
      {
        title: "Identifying the Risks of LM Agents with an LM-Emulated Sandbox",
        description: "ToolEmu: automated evaluation of LM agent risks across tool use scenarios, revealing systematic failure modes in production-like environments.",
        url: "https://arxiv.org/abs/2309.15817",
        source: "arXiv",
      },
      {
        title: "Agent Security Bench: Evaluating the Security of LLM Agents",
        description: "Comprehensive benchmark covering 10 agent attack types across 55 test cases, providing a structured framework for measuring agentic AI security posture.",
        url: "https://arxiv.org/abs/2410.02644",
        source: "arXiv",
      },
      {
        title: "Attacking Vision-Language Computer Use Agents with Indirect Prompt Injection",
        description: "Demonstrates indirect prompt injection attacks against computer-use agents via manipulated screen content, highlighting a new attack surface.",
        url: "https://arxiv.org/abs/2502.11358",
        source: "arXiv",
      },
      {
        title: "The Danger of Fully Autonomous AI Agents",
        description: "Analysis of goal misalignment and catastrophic risk in fully autonomous AI systems, with recommendations for oversight mechanisms.",
        url: "https://arxiv.org/abs/2406.05946",
        source: "arXiv",
      },
      {
        title: "Model Context Protocol (MCP) Security Considerations",
        description: "Security analysis of the MCP standard for AI tool integration, covering trust boundaries, authorization risks, and recommended mitigations.",
        url: "https://spec.modelcontextprotocol.io/",
        source: "standard",
      },
      {
        title: "Multi-Agent Systems Security: Trust and Verification Challenges",
        description: "Research on authentication and trust propagation in multi-agent pipelines, covering orchestrator compromise and inter-agent injection vectors.",
        url: "https://arxiv.org/abs/2402.01263",
        source: "arXiv",
      },
    ],
  },
  {
    id: "detection-engineering",
    title: "Detection Engineering",
    links: [
      {
        title: "MITRE ATT&CK: Design and Philosophy",
        description: "The foundational paper describing the ATT&CK framework's design, intended use for adversary behavior modeling and detection gap analysis.",
        url: "https://attack.mitre.org/resources/philosophy/",
        source: "paper",
      },
      {
        title: "Sigma: Generic Signature Format for SIEM Systems",
        description: "Original Sigma specification paper describing the YAML-based signature format for SIEM-agnostic detection rule authoring.",
        url: "https://github.com/SigmaHQ/sigma/wiki/Specification",
        source: "standard",
      },
      {
        title: "Detection Engineering Maturity Matrix",
        description: "Kyle Bailey's framework for measuring and advancing detection engineering capability maturity across people, process, and technology dimensions.",
        url: "https://detectionengineering.io/",
        source: "blog",
      },
      {
        title: "Alerting and Detection Strategy Framework",
        description: "Palantir's ADS framework for structuring detection hypotheses, covering goal, categorization, technical context, and response guidance.",
        url: "https://github.com/palantir/alerting-detection-strategy-framework",
        source: "paper",
      },
      {
        title: "The Pyramid of Pain",
        description: "David Bianco's classic model illustrating the relative difficulty of denying adversaries different types of IOCs, from hash values to TTPs.",
        url: "https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html",
        source: "blog",
      },
      {
        title: "Detection Engineering with PySpark at Scale",
        description: "Engineering patterns for implementing distributed behavioral detection pipelines using Apache Spark, handling class imbalance, windowing, and UDFs.",
        url: "https://databricks.com/blog/security-analytics",
        source: "blog",
      },
      {
        title: "Evasion Attacks Against Machine Learning at Test Time",
        description: "Foundational adversarial ML paper on evasion attacks, essential for understanding how detection ML models can be evaded.",
        url: "https://arxiv.org/abs/1708.06131",
        source: "arXiv",
      },
      {
        title: "SOC Prime Threat Detection Marketplace: Community Detection Patterns",
        description: "Analysis of production detection rule patterns across enterprise deployments, covering rule quality metrics and coverage distribution.",
        url: "https://tdm.socprime.com/",
        source: "blog",
      },
    ],
  },
  {
    id: "insider-threat",
    title: "Insider Threat",
    links: [
      {
        title: "Common Sense Guide to Mitigating Insider Threats (7th Edition)",
        description: "CERT/CC's authoritative guide to insider threat program development, incident analysis, and technical controls for detection.",
        url: "https://www.sei.cmu.edu/our-work/insider-threat/",
        source: "report",
      },
      {
        title: "Insider Threat Indicator Ontology",
        description: "CERT research defining a structured ontology for insider threat indicators across technical and behavioral signal categories.",
        url: "https://resources.sei.cmu.edu/library/asset-view.cfm?assetid=540644",
        source: "paper",
      },
      {
        title: "User and Entity Behavior Analytics (UEBA): Baseline Construction and Drift Detection",
        description: "Statistical methods for building behavioral baselines, detecting drift, and managing false positive rates in enterprise UEBA deployments.",
        url: "https://arxiv.org/abs/2005.06271",
        source: "arXiv",
      },
      {
        title: "Detecting Malicious Insider Threat: A Survey",
        description: "Comprehensive survey of insider threat detection techniques including anomaly detection, machine learning, and psychological indicators.",
        url: "https://arxiv.org/abs/1803.04513",
        source: "arXiv",
      },
      {
        title: "Graph-Based Anomaly Detection for Insider Threat",
        description: "Using graph analytics on enterprise activity data to detect lateral movement and privilege abuse patterns indicative of insider threats.",
        url: "https://arxiv.org/abs/1903.01680",
        source: "arXiv",
      },
      {
        title: "CERT Insider Threat Dataset (CERT/CC)",
        description: "Reference documentation for the widely-used CERT synthetic insider threat dataset, covering log types, scenario descriptions, and evaluation methodology.",
        url: "https://resources.sei.cmu.edu/library/asset-view.cfm?assetid=508099",
        source: "report",
      },
      {
        title: "Handling Class Imbalance in Security Anomaly Detection",
        description: "Techniques for training anomaly detectors under extreme positive-class scarcity, oversampling, cost-sensitive learning, and evaluation framework.",
        url: "https://arxiv.org/abs/1901.01203",
        source: "arXiv",
      },
    ],
  },
  {
    id: "llm-security",
    title: "LLM Security",
    links: [
      {
        title: "Prompt Injection Attacks Against GPT-3",
        description: "First systematic study of prompt injection in deployed GPT-3 applications, introducing direct and indirect injection taxonomy.",
        url: "https://arxiv.org/abs/2302.12173",
        source: "arXiv",
      },
      {
        title: "Jailbroken: How Does LLM Safety Training Fail?",
        description: "Analysis of failure modes in RLHF safety training, identifying competing objectives and generalization failures that enable jailbreaks.",
        url: "https://arxiv.org/abs/2307.02483",
        source: "arXiv",
      },
      {
        title: "Backdoor Attacks on Language Models",
        description: "Survey of training-time backdoor attacks against LLMs, poisoning datasets to create triggered behaviors that bypass safety evaluations.",
        url: "https://arxiv.org/abs/2211.11958",
        source: "arXiv",
      },
      {
        title: "Privacy Side Channels in Machine Learning Systems",
        description: "How LLMs memorize and leak training data through inference-time attacks, membership inference, extraction attacks, and mitigations.",
        url: "https://arxiv.org/abs/2309.05610",
        source: "arXiv",
      },
      {
        title: "Do Anything Now (DAN): Jailbreak Taxonomy and Defenses",
        description: "Comprehensive taxonomy of LLM jailbreak techniques in the wild, with analysis of defense effectiveness across attack categories.",
        url: "https://arxiv.org/abs/2308.03825",
        source: "arXiv",
      },
      {
        title: "Extracting Training Data from Large Language Models",
        description: "Demonstrates that LLMs memorize and reproduce verbatim training sequences, enabling PII and sensitive data extraction at scale.",
        url: "https://arxiv.org/abs/2012.07805",
        source: "arXiv",
      },
      {
        title: "SmoothLLM: Defending Large Language Models Against Jailbreaking Attacks",
        description: "Randomized smoothing defense against adversarial prompt attacks, the first provably robust defense for aligned LLMs.",
        url: "https://arxiv.org/abs/2310.03684",
        source: "arXiv",
      },
      {
        title: "LLM Security: Threat Modeling for Production Deployments",
        description: "Practical threat modeling guide for LLM-integrated applications, covering attack surfaces, trust boundaries, and monitoring recommendations.",
        url: "https://llmsecurity.net/",
        source: "blog",
      },
    ],
  },
];

export type ResearchSectionId = "ai-security" | "agentic-ai" | "detection-engineering" | "insider-threat" | "llm-security";

export const sectionColors: Record<string, string> = {
  "ai-security": "text-purple-400 bg-purple-400/10 border-purple-400/20",
  "agentic-ai": "text-violet-400 bg-violet-400/10 border-violet-400/20",
  "detection-engineering": "text-cyan-400 bg-cyan-400/10 border-cyan-400/20",
  "insider-threat": "text-orange-400 bg-orange-400/10 border-orange-400/20",
  "llm-security": "text-blue-400 bg-blue-400/10 border-blue-400/20",
};

export const sourceColors: Record<string, string> = {
  arXiv: "text-green-400 bg-green-400/10 border-green-400/20",
  paper: "text-blue-400 bg-blue-400/10 border-blue-400/20",
  blog: "text-yellow-400 bg-yellow-400/10 border-yellow-400/20",
  report: "text-orange-400 bg-orange-400/10 border-orange-400/20",
  conference: "text-pink-400 bg-pink-400/10 border-pink-400/20",
  standard: "text-cyan-400 bg-cyan-400/10 border-cyan-400/20",
};
