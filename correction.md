Use the ui-ux skill.

Make the following targeted enhancements to the existing project. Do NOT redesign the whole site. Keep current structure and styling, only extend functionality and content.

---

1. Detection Library – Add OCI-specific detections

Enhance the detection library with Oracle Cloud Infrastructure (OCI) audit log–based detections.

Add realistic sample OCI Audit logs with fields like:
- eventName
- requestAction
- principalId
- sourceIPAddress
- compartmentId
- responseStatus
- timestamp

Create detection use cases such as:
- Object storage mass download (exfiltration)
- IAM policy changes
- API key usage anomalies
- Console login anomalies
- Cross-compartment access anomalies

Each detection must include:
- sample logs (JSON)
- detection logic (Sigma, Splunk, PySpark)
- explanation
- false positives
- tuning guidance

Store data in lib/data and render properly in the Detection Library UI.

---

2. Converter Page – Add Useful Links section

Add a clean section on the Converter page titled “Useful Resources”.

Include links for:
- Sigma rule creation (Sigma HQ / docs)
- Splunk SPL documentation
- PySpark query/reference documentation

Design:
- card-based layout
- consistent with existing UI
- subtle icons + short descriptions

---

3. Playground – Detection Quality Scoring

Add a new section in the Playground:

- Input box (Monaco or textarea) to paste a detection rule
- “Evaluate” button

On submit:
- generate a detection quality score (0–100)

Score based on:
- completeness (fields, logic)
- clarity
- presence of filtering conditions
- noise reduction considerations
- basic best practices

Output:
- score (number + badge)
- short feedback (strengths + improvements)

No backend needed, implement as heuristic/mock scoring logic.

---

4. About Page – Populate from LinkedIn

Update the About page using details from:
https://www.linkedin.com/in/athul-raju-38745552

Include:
- professional summary
- current role and focus (detection engineering, AI security)
- key skills (UEBA, cloud detections, ML in security)
- talks / research direction
- clean structured sections

Keep it concise, professional, and aligned with the platform.

---

Ensure all additions follow existing design system and remain visually consistent.
Do not introduce new design styles.
