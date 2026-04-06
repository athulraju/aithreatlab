Use the ui-ux skill for ALL UI generation in this project.

The ui-ux skill defines the design system, layout principles, spacing, typography, and overall product feel.

Apply it consistently across:
- all pages
- all components
- all layouts
- all interactions

Do not fall back to generic layouts or default styling.
Maintain a consistent, premium, product-grade design throughout the entire site.

Prioritize consistency over creativity.
Reuse the same card styles, spacing, and visual patterns across all pages.

---

Build a premium, dark-theme, production-style Detection Engineering platform in Next.js, TypeScript, Tailwind CSS, shadcn/ui, Framer Motion, and Monaco Editor.

This should feel like a real security product, not a generic portfolio or template site.

Project goal:
Create a polished frontend-first platform for building, translating, testing, exploring, and researching detections across Sigma, Splunk, and PySpark, with a strong AI Security section and a custom detection coverage framework.

Core positioning:
“A platform for building, translating, testing, and operationalizing detections across Sigma, Splunk, and PySpark.”

---

Technical requirements:
- Next.js latest with App Router
- TypeScript
- Tailwind CSS
- shadcn/ui
- Framer Motion (subtle only)
- Monaco Editor for detection/query editing
- Dark mode default
- Fully responsive
- Clean modular structure
- Mock data in lib/data
- No broken routes
- No lorem ipsum
- Use realistic detection/security content

---

Local hosting requirement:
- The project must run locally on http://localhost:8000
- Configure the project so it starts on port 8000
- Provide a working dev script to run it locally

---

Before building pages, define and apply a consistent design system:
- color palette
- background surfaces
- card styles
- borders
- button variants
- typography hierarchy
- spacing scale
- badge styles

---

Build the following pages and routes:

---

1. Home page

High-end product landing page.

Include:
- premium navbar
- hero with headline, subheadline, CTA
- feature cards
- converter preview
- detection library preview
- coverage framework preview
- AI Security preview
- research preview
- CTA section
- footer

---

2. Converter page

Core tool UI.

Include:
- input format selector (Sigma, Splunk, PySpark)
- output format selector
- Monaco input editor
- Monaco output editor
- convert button
- copy + download buttons
- validation panel
- translation notes panel
- sample rules

Create placeholder converters in:
- lib/converters/sigmaToSplunk.ts
- lib/converters/sigmaToPySpark.ts
- lib/converters/splunkToSigma.ts
- lib/converters/pysparkToSigma.ts

Use mock logic but clean structure.

---

3. Detection Library

Searchable detection knowledge base.

Include:
- search
- filters (platform, MITRE, category, maturity)
- detection cards

Detection detail page:
- problem statement
- logic (Sigma / Splunk / PySpark tabs)
- sample logs
- required fields
- false positives
- tuning guidance
- deployment notes
- evasion considerations

Use realistic mock detections.

---

4. Coverage Framework

Signature visual page.

Layers:
- Host OS
- Host Application
- Host Network
- Middle Network
- Large Application
- Identity
- Perimeter
- AI Security Extension

Include:
- structured visual layout
- coverage summary
- MITRE mapping concept
- service dimension
- coverage gaps
- downloadable coverage concept

Mock data columns:
- detection name
- layer
- subcategory
- data source
- platform
- MITRE technique
- use case
- coverage type
- maturity
- AI Security flag
- notes

---

5. AI Security page

Strong, practical page.

Include:
- OWASP Top 10 for LLM
- OWASP Top 10 for Agentic AI

For each:
- explanation
- protection
- monitoring
- logs required
- detection ideas
- challenges

Categories:
- prompt injection
- tool misuse
- agent goal drift
- data exfiltration
- API abuse
- endpoint agent abuse
- cloud agent abuse

Add a “Research Spotlight” banner:
- rotates every 10 days
- uses local data
- no backend
- supports “coming soon”
- shows title, summary, tag, CTA

Store data in lib/data.

---

6. Playground page

Detection workbench.

Include:
- query editor
- log panel
- validation panel
- results panel
- explanation panel
- scenario selector
- dummy data generator

Support scenarios:
- exfiltration
- login anomaly
- agent misuse
- cloud audit
- endpoint execution

Simulate execution (no real engine required).

---

7. Research page

Technical research hub.

Include:
- article cards
- categories
- clean layout

Topics:
- detection engineering
- AI security
- insider threat
- Sigma portability
- PySpark detections
- class imbalance
- agent detection

Include article detail routes.

---

8. About page

Professional profile.

Include:
- background
- work
- focus areas
- projects
- talks
- research interests
- contact placeholders

Focus:
- detection engineering
- UEBA
- cloud detections
- AI security

---

Global requirements:
- reusable components (navbar, cards, filters, tabs, badges, editors)
- consistent styling
- modular code
- realistic mock data
- polished UI
- subtle motion only
- converter and playground must feel like real tools
- AI Security and homepage must be highly polished

---

Stretch goals:
- export/download pattern for detections
- command palette if cleanly possible

---

Final instruction:
Do not spend many tokens explaining.
Implement directly.
Create the files and code.
