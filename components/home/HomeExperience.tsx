"use client";

import Link from "next/link";
import { ArrowRight, ArrowUpRight, BookOpen, Braces, FlaskConical, Layers3, Shield, Workflow } from "lucide-react";
import styles from "./HomeExperience.module.css";
import { StreamFlowCanvas } from "./StreamFlowCanvas";

type HomeExperienceProps = {
  detection: { id: string; title: string; category: string; severity: string; sigma: string };
  research: { title: string; description: string; url: string; source: string; section: string }[];
};

const metrics = [
  ["110", "Detection Rules"], ["8", "Coverage Layers"], ["3", "Output Formats"], ["OWASP", "LLM & Agentic Top 10"],
] as const;

const capabilities = [
  { title: "Detection library", detail: "Operational rules with context, tuning and deployment notes.", href: "/detections", icon: Braces, trace: "Research → logic" },
  { title: "Format converter", detail: "Translate between Sigma, Splunk SPL and PySpark without losing intent.", href: "/converter", icon: Workflow, trace: "Logic → portable output" },
  { title: "Coverage framework", detail: "See where telemetry, techniques and detections meet across eight layers.", href: "/coverage", icon: Layers3, trace: "Signals → architecture" },
  { title: "AI security", detail: "Detection guidance for language models and autonomous agent systems.", href: "/ai-security", icon: Shield, trace: "Behavior → intervention" },
  { title: "Playground", detail: "Test assumptions and explore rule quality in a transparent workbench.", href: "/playground", icon: FlaskConical, trace: "Experiment → validation" },
  { title: "Research", detail: "Follow evidence from practitioner intelligence into operational defense.", href: "/research", icon: BookOpen, trace: "Source → evidence" },
] as const;

function ChipGraphic({ kind }: { kind: "wave" | "map" | "feed" }) {
  if (kind === "wave") return (
    <svg viewBox="0 0 96 60" fill="none" aria-hidden="true" className={styles.chipGraphic}>
      <path d="M2 40C10 38 13 46 22 38S35 20 44 27 54 42 63 35s12-18 20-11 11 16 19 9" stroke="#9ff0c8" strokeWidth="1" strokeOpacity=".85"/>
      <path d="M2 48h92M2 30h92M2 12h92" stroke="#9ff0c8" strokeOpacity=".07"/>
      <circle cx="63" cy="20" r="1.6" fill="#e6a16d"/><circle cx="78" cy="33" r="1.3" fill="#9ff0c8"/>
    </svg>
  );
  if (kind === "map") return (
    <svg viewBox="0 0 96 60" fill="none" aria-hidden="true" className={styles.chipGraphic}>
      <path d="M6 44 20 30 34 36 50 18 66 26 82 14" stroke="#9ff0c8" strokeOpacity=".2" strokeWidth=".7" strokeDasharray="1 2.4"/>
      <circle cx="20" cy="30" r="1.4" fill="#9ff0c8"/><circle cx="50" cy="18" r="1.4" fill="#e6a16d"/>
      <circle cx="66" cy="26" r="1.4" fill="#9ff0c8"/><circle cx="82" cy="14" r="1.8" fill="#eaf7f0"/>
    </svg>
  );
  return (
    <svg viewBox="0 0 96 60" fill="none" aria-hidden="true" className={styles.chipGraphic}>
      {[10, 20, 30, 40, 50].map((y, i) => (
        <rect key={y} x="6" y={y - 3} width={18 + (i * 11) % 40} height="2.4" rx="1" fill="#9ff0c8" fillOpacity={0.55 - i * 0.07} />
      ))}
    </svg>
  );
}

function Annotation({ kind, title, code, rows, chip, mirror }: { kind: string; title: string; code: string; rows: [string, string][]; chip: "wave" | "map" | "feed"; mirror?: boolean }) {
  return <div className={`${styles.annotation} ${styles[kind]}`}>
    <div className={styles.annotationLabel}><span className={styles.dot} />{title}</div>
    <div className={styles.annotationRule} />
    <div className={styles.annotationCode}>{code}</div>
    <div className={styles.annotationStats}>
      {rows.map(([label, value]) => <div className={styles.statLine} key={label}><span>{label}</span><strong>{value}</strong></div>)}
    </div>
    <div className={`${styles.leaderWrap} ${mirror ? styles.mirror : ""}`}>
      <svg className={styles.leaderSvg} viewBox="0 0 168 96" fill="none" aria-hidden="true">
        <polyline points="4,2 40,56 108,43" stroke="#9ff0c8" strokeOpacity=".38" strokeWidth="1" />
        <circle cx="40" cy="56" r="2.2" fill="#9ff0c8" className={styles.anchorDot} />
      </svg>
      <div className={styles.chip}><ChipGraphic kind={chip} /></div>
    </div>
  </div>;
}

export function HomeExperience({ detection, research }: HomeExperienceProps) {
  return <div className="bg-[#05110f] text-[#dce8e1]">
    <section className={styles.hero}>
      <div className={styles.environment}>
        <StreamFlowCanvas />
      </div>
      <div className={styles.atmosphere}/>
      <div className={styles.panels}>
        <Annotation kind="threat" title="Threat research" code="TR-9910" chip="map" mirror rows={[["New actor activity","linked"],["Indicators","3 related"]]}/>
        <Annotation kind="detection" title="Detection logic" code="DL-7183" chip="wave" rows={[["Behavioral match","0.87"],["Rule state","validated"]]}/>
        <Annotation kind="coverage" title="Coverage" code="CVG-4062" chip="map" mirror rows={[["Mapped assets","14"],["Layer status","operational"]]}/>
        <Annotation kind="ai" title="AI security" code="AIS-2307" chip="feed" mirror rows={[["Agent behavior","observed"],["Action","review"]]}/>
      </div>

      <div className={`atl-shell ${styles.heroContent}`}>
        <div className={styles.copy}>
          <h1 className="max-w-[610px] text-[clamp(3rem,5.2vw,5.4rem)] font-light leading-[.97] tracking-[-.055em] text-[#eef6f1]">Build. Translate.<br/>Operationalize.</h1>
          <p className="mt-7 max-w-[620px] text-[15px] leading-7 text-[#9ab0a6] sm:text-base">A platform for building, translating, testing, and operationalizing detections across Sigma, Splunk, and PySpark, with a dedicated AI Security layer.</p>
          <div className="mt-9 flex flex-wrap gap-3"><Link href="/converter" className="atl-button-primary">Try the Converter <ArrowRight className="h-4 w-4"/></Link><Link href="/detections" className="atl-button-secondary">Browse Detections <ArrowUpRight className="h-4 w-4 text-[#83d7b6]"/></Link></div>
        </div>
        <div className={`${styles.metrics} grid grid-cols-2 sm:grid-cols-4`}>
          {metrics.map(([value,label],i)=><div key={label} className={`py-5 pr-4 ${i%2 ? 'pl-4' : ''} sm:border-r sm:border-[#bce2d2]/10 sm:px-5 first:pl-0 last:border-r-0`}><strong className="block text-xl font-medium tracking-[-.03em] text-[#e2eee8]">{value}</strong><span className="mt-1 block text-[11px] leading-4 text-[#718a80]">{label}</span></div>)}
        </div>
      </div>
    </section>

    <section className="atl-page-lineage py-24 sm:py-32"><div className="atl-shell">
      <div className="grid gap-10 lg:grid-cols-[.65fr_1.35fr]"><div><p className="text-xs text-[#83d7b6]">One connected system</p><h2 className="mt-4 max-w-md text-3xl font-medium leading-tight tracking-[-.04em] sm:text-5xl">Follow evidence all the way to defense.</h2></div><p className="max-w-xl text-sm leading-7 text-[#8da59b] lg:pt-9">Every surface keeps the relationship between source evidence, observable behavior, portable logic and architectural coverage intact.</p></div>
      <div className="mt-16 divide-y divide-[#bce2d2]/10 border-y border-[#bce2d2]/10">
        {capabilities.map((item)=><Link key={item.title} href={item.href} className="group grid gap-5 py-7 transition-colors hover:bg-[#83d7b6]/[.025] sm:grid-cols-[44px_1fr_1.25fr_190px_24px] sm:items-center sm:px-4"><item.icon className="h-4 w-4 text-[#83d7b6]"/><h3 className="font-medium text-[#dce8e1]">{item.title}</h3><p className="text-sm leading-6 text-[#718a80]">{item.detail}</p><span className="font-mono text-[9px] text-[#648276]">{item.trace}</span><ArrowRight className="h-4 w-4 text-[#4d6a5f] transition-transform group-hover:translate-x-1 group-hover:text-[#83d7b6]"/></Link>)}
      </div>
    </div></section>

    <section className="border-y border-[#bce2d2]/10 bg-[#071713] py-24"><div className="atl-shell grid gap-12 lg:grid-cols-[.72fr_1.28fr]">
      <div><p className="text-xs text-[#d08a5d]">Active detection object</p><h2 className="mt-4 text-3xl font-medium tracking-[-.04em]">{detection.title}</h2><p className="mt-5 text-sm leading-7 text-[#8da59b]">Real rule logic remains connected to its operational context, data requirements and tuning guidance.</p><div className="mt-7 flex gap-4 text-xs text-[#718a80]"><span>{detection.category}</span><span className="text-[#d08a5d]">{detection.severity}</span><span>Sigma</span></div><Link href={`/detections/${detection.id}`} className="atl-button-secondary mt-8">Inspect detection <ArrowRight className="h-4 w-4"/></Link></div>
      <div className="atl-panel overflow-hidden"><div className="flex justify-between border-b border-[#bce2d2]/10 px-5 py-3 font-mono text-[9px] text-[#648276]"><span>{detection.id}</span><span>rule.yml</span></div><pre className="max-h-[390px] overflow-hidden p-6 text-[11px] leading-6 text-[#9ab0a6]"><code>{detection.sigma.split("\n").slice(0,23).join("\n")}</code></pre></div>
    </div></section>

    <section className="py-24 sm:py-32"><div className="atl-shell"><div className="flex items-end justify-between gap-6"><div><p className="text-xs text-[#83d7b6]">Research intelligence</p><h2 className="mt-4 text-3xl font-medium tracking-[-.04em] sm:text-5xl">Current lines of inquiry.</h2></div><Link href="/research" className="hidden text-sm text-[#9ab0a6] hover:text-[#dce8e1] sm:inline-flex">Open research index <ArrowUpRight className="ml-2 h-4 w-4"/></Link></div><div className="mt-14 grid gap-px overflow-hidden border border-[#bce2d2]/10 bg-[#bce2d2]/10 lg:grid-cols-3">{research.map((item)=><a key={item.title} href={item.url} target="_blank" rel="noreferrer" className="group flex min-h-72 flex-col bg-[#061411] p-6 transition-colors hover:bg-[#0b211b]"><span className="text-[10px] text-[#648276]">{item.source} / {item.section}</span><h3 className="mt-auto text-xl font-medium leading-snug text-[#dce8e1]">{item.title}</h3><p className="mt-4 line-clamp-3 text-xs leading-5 text-[#718a80]">{item.description}</p></a>)}</div></div></section>
  </div>;
}
