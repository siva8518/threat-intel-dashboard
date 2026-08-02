// Client-side export of an AI Summarization report to PDF and Word --
// deliberately no new heavyweight dependency (no jspdf/puppeteer/docx): PDF
// uses the browser's own print engine (a real, selectable-text PDF via
// "Save as PDF" in the print dialog, not a rasterized screenshot), and Word
// uses the well-established technique of serving well-formed HTML with the
// `xmlns:w="urn:schemas-microsoft-com:office:word"` namespace and a .doc
// extension -- Word's own HTML import filter opens this natively (this is
// how many enterprise "export to Word" features have worked for two decades,
// not a hack). Both share one HTML-building pass over the report so the
// two output formats can never drift out of sync with each other.
import type { AiThreatSummaryReport } from "@/types/threat-intel";
import { buildOperationalGuidanceRows } from "@/lib/operationalGuidance";

function esc(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function safeFilename(title: string): string {
  return (
    title
      .trim()
      .replace(/[^a-z0-9]+/gi, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 80) || "ai-threat-summary-report"
  );
}

function heading(level: 1 | 2 | 3 | 4, text: string): string {
  return `<h${level}>${esc(text)}</h${level}>`;
}

function paragraph(text: string): string {
  return `<p>${esc(text)}</p>`;
}

/** Same "Not Reported"/empty-string skip already used by AiSummarization.tsx's KeyValueBlock, so the exported document never pads out fields the model didn't have an answer for. */
function keyValueSection(title: string, pairs: Array<[string, string | null]>): string {
  const shown = pairs.filter(([, v]) => v && v !== "Not Reported");
  if (shown.length === 0) return "";
  const rows = shown.map(([label, value]) => `<p><strong>${esc(label)}:</strong> ${esc(value as string)}</p>`).join("");
  return `${title ? heading(3, title) : ""}${rows}`;
}

/** Groups of string[] keyed by a human label -- mirrors AiSummarization.tsx's GroupedLists/GroupedCodeLists, minus the two components' only difference (monospace styling), which doesn't matter for a printed/Word document. */
function groupedListsSection(title: string, groups: Array<[string, string[]]>): string {
  const nonEmpty = groups.filter(([, items]) => items.length > 0);
  if (nonEmpty.length === 0) return "";
  const body = nonEmpty
    .map(([label, items]) => `<p class="group-label"><strong>${esc(label)}</strong></p><ul>${items.map((item) => `<li>${esc(item)}</li>`).join("")}</ul>`)
    .join("");
  return `${title ? heading(3, title) : ""}${body}`;
}

function iocRow(label: string, values: string[]): string {
  if (values.length === 0) return "";
  return `<p><strong>${esc(label)} (${values.length}):</strong> ${values.map(esc).join(", ")}</p>`;
}

const NOT_AVAILABLE = "Not Available in Source";

function cellList(items: string[]): string {
  if (items.length === 0) return `<em>${NOT_AVAILABLE}</em>`;
  return `<ul>${items.map((i) => `<li>${esc(i)}</li>`).join("")}</ul>`;
}

function cellText(text: string | null | undefined): string {
  if (!text || text === "Not Reported" || text === "Not Applicable") return `<em>${NOT_AVAILABLE}</em>`;
  return esc(text);
}

/**
 * Real HTML <table>, one row per team, built from the same shared
 * buildOperationalGuidanceRows() as the on-screen OperationalGuidanceTable
 * (src/components/dashboard/AiSummarization.tsx) -- both consume identical
 * row data, so this can never drift from what the tab itself shows.
 */
function operationalGuidanceTable(report: AiThreatSummaryReport): string {
  const rows = buildOperationalGuidanceRows(report);
  const body = rows
    .map(
      (r) =>
        `<tr><td><strong>${esc(r.team)}</strong></td><td>${esc(r.priority)}</td><td>${cellList(r.actions)}</td><td>${cellList(r.detailedGuidance)}</td>` +
        `<td>${cellList(r.telemetry)}</td><td>${cellList(r.detectionOpportunities)}</td><td>${cellText(r.nextSteps)}</td><td>${cellList(r.rationale)}</td></tr>`,
    )
    .join("");
  return (
    `${heading(2, "Operational Guidance")}` +
    `<table class="ops-table"><thead><tr><th>Team</th><th>Priority</th><th>Recommended Action</th><th>Detailed Guidance</th>` +
    `<th>Telemetry / Log Sources</th><th>Detection / Hunting Opportunities</th><th>Immediate Next Steps</th><th>Rationale</th></tr></thead>` +
    `<tbody>${body}</tbody></table>`
  );
}

/**
 * Renders the same content/skip-logic as AiSummarization.tsx's ReportRow,
 * as static semantic HTML instead of React -- kept in one place so PDF and
 * Word export can never show different content from each other, or from
 * what the tab itself displays.
 */
function buildReportBodyHtml(report: AiThreatSummaryReport): string {
  const namedThreatActors = report.threatActors.filter((a) => a.group !== "Not Reported");
  const namedMalware = report.malware.filter((m) => m.family !== "Not Reported");
  const totalIocs = Object.values(report.iocs).reduce((sum, list) => sum + (list?.length ?? 0), 0);
  const kevCount = report.cves.filter((c) => c.knownExploited).length;
  const risk = report.businessRisk;
  const tech = report.technicalAnalysis;
  const actions = report.operationalActions;

  const parts: string[] = [];

  parts.push(heading(1, report.articleTitle));
  parts.push(
    `<p class="meta">${esc(report.articleSource)} &middot; ${esc(new Date(report.publishedDate).toLocaleDateString())} &middot; Severity: ${esc(report.severity)} &middot; ` +
      `AI Risk Priority: ${esc(report.aiRiskScoring.priority)} (${report.aiRiskScoring.score == null ? "—" : `${report.aiRiskScoring.score}/100`})${
        kevCount > 0 ? ` &middot; ${kevCount} Known Exploited Vulnerabilit${kevCount === 1 ? "y" : "ies"}` : ""
      }</p>`,
  );
  // Same clarification as the on-screen tab (AiSummarization.tsx) -- placed
  // right next to the risk/priority line, Confidence otherwise reads as
  // another severity signal instead of what it actually is: how certain the
  // model is that *this report* reflects the source article.
  parts.push(`<p class="meta">Analysis Confidence: ${esc(report.confidenceAssessment.level)} (the model's certainty in this report, not a severity signal)</p>`);

  // 1. Executive Summary + Business Risk + Threat Relevance
  parts.push(heading(2, "Executive Summary"));
  if (report.executiveHeadline) parts.push(`<p><strong>${esc(report.executiveHeadline)}</strong></p>`);
  parts.push(paragraph(report.executiveSummary));
  if (risk?.overallRiskLevel) parts.push(`<p><strong>Overall Risk: ${esc(risk.overallRiskLevel)}</strong>${risk.requiresExecutiveAttention ? " -- Requires executive attention" : ""}</p>`);
  if (risk) {
    parts.push(
      keyValueSection("", [
        ["Business risk", risk.businessRisk],
        ["Operational disruption", risk.operationalDisruption],
        ["Likelihood of exploitation", risk.likelihoodOfExploitation],
        ["Impact if unpatched", risk.impactIfUnpatched],
      ]),
    );
    parts.push(
      groupedListsSection("", [
        ["Regions impacted", risk.regionsCommonlyTargeted ?? []],
        ["Technologies targeted", report.threatRelevance?.technologiesTargeted ?? []],
        ["Geographic focus", report.threatRelevance?.geographicFocus ?? []],
        ["MITRE tactics", report.threatRelevance?.mitreTactics ?? []],
      ]),
    );
  }

  // 2. Threat Assessment
  parts.push(heading(2, "Threat Assessment"));
  parts.push(
    paragraph(
      `Risk Score: ${report.aiRiskScoring.score == null ? "—" : `${report.aiRiskScoring.score}/100`} (${report.aiRiskScoring.priority}) &middot; Analysis Confidence: ${report.confidenceAssessment.level}${report.confidenceAssessment.score != null ? ` (${report.confidenceAssessment.score}%)` : ""}`,
    ),
  );
  if (report.intelligenceAssessment && report.intelligenceAssessment !== "Not Reported") {
    parts.push(report.intelligenceAssessment.split(/\n{2,}/).map((p) => paragraph(p)).join(""));
  }
  // Evidence supporting the confidence score above, in place of a free-text
  // "reasoning" paragraph -- mirrors AiSummarization.tsx's Threat Assessment
  // section (concrete, checkable facts read as more trustworthy than a
  // restated sentence).
  if (report.confidenceAssessment.factorsPresent?.length > 0 || report.confidenceAssessment.factorsMissing?.length > 0) {
    parts.push(heading(3, "Evidence Supporting Confidence"));
    if (report.confidenceAssessment.factorsPresent?.length > 0) {
      parts.push(`<ul>${report.confidenceAssessment.factorsPresent.map((f) => `<li>&check; ${esc(f)}</li>`).join("")}</ul>`);
    }
    if (report.confidenceAssessment.factorsMissing?.length > 0) {
      parts.push(`<p><em>Missing:</em></p><ul>${report.confidenceAssessment.factorsMissing.map((f) => `<li>${esc(f)}</li>`).join("")}</ul>`);
    }
  }

  // 3. Should I Care + Exposure Assessment + affected technologies/products
  if (report.shouldICare || report.exposureAssessment?.applicable || tech) {
    parts.push(heading(2, "Should I Care & Exposure"));
    if (report.shouldICare) parts.push(paragraph(`${report.shouldICare.verdict}. ${report.shouldICare.reasoning}`));
    // Static rendering of the interactive widget shown in the AI
    // Summarization tab (AiSummarization.tsx's ExposureAssessment) -- no
    // Yes/No/Unsure state in a static document, so both guidance branches
    // are printed together for the reader to apply themselves once they've
    // checked their version.
    if (report.exposureAssessment?.applicable) {
      const exp = report.exposureAssessment;
      parts.push(paragraph(`Do you have ${exp.product}?`));
      parts.push(paragraph(`How to check your version: ${exp.howToCheckVersion}`));
      parts.push(paragraph(`Affected versions (per this article): ${exp.affectedVersions}`));
      parts.push(paragraph(`If your version is listed above: ${exp.affectedGuidance}`));
      parts.push(paragraph(`If it isn't: ${exp.notAffectedGuidance}`));
    }
    if (tech) {
      parts.push(
        groupedListsSection("Affected Technologies & Products", [
          ["Products", tech.products],
          ["Versions", tech.versions],
          ["Operating systems", tech.operatingSystems],
          ["Cloud services", tech.cloudServices],
          ["Applications", tech.applications],
        ]),
      );
    }
  }

  // 4. Affected Industries -- only industries the article genuinely supports
  //    flagging, not the full 10-sector scored heatmap (mirrors
  //    AiSummarization.tsx's simplified per-report view).
  {
    const flagged = (report.industryRelevance ?? []).filter((r) => r.relevance !== "Not Applicable");
    parts.push(heading(2, "Affected Industries"));
    if (flagged.length === 0) {
      parts.push(paragraph("Affected Industries: Not specifically identified by the vendor."));
    } else {
      const rows = flagged.map((r) => `<li><strong>${esc(r.relevance)}</strong> -- ${esc(r.industry)}</li>`).join("");
      parts.push(`<ul>${rows}</ul>`);
    }
  }

  // 5. Technical Analysis, Attack Details, Kill Chain & MITRE ATT&CK Mapping
  //    (+ named threat actors/malware, the "who/what" half of the same
  //    technical picture)
  if (tech || report.mitreAttack.length > 0 || namedThreatActors.length > 0 || namedMalware.length > 0) {
    parts.push(heading(2, "Technical Analysis, Attack Details, Kill Chain & MITRE ATT&CK Mapping"));
  }
  if (tech) {
    parts.push(
      keyValueSection("Technical Analysis", [
        ["What happened", tech.whatHappened],
        ["Why it matters", tech.whyItMatters],
        ["Who is affected", tech.whoIsAffected],
        ["Active exploitation", tech.activeExploitation],
      ]),
    );
    if (tech.exploitationStatus && tech.exploitationStatus !== "Not Reported") {
      const sourceLink = report.references[0] ? ` <a href="${esc(report.references[0].url)}">(see source)</a>` : "";
      parts.push(`<p><strong>Exploitation status:</strong> ${esc(tech.exploitationStatus)}${sourceLink}</p>`);
    }
    if (tech.vendorSeverity && tech.vendorSeverity !== "Not Reported") {
      // Vendor's own stated rating -- can legitimately differ from this
      // report's overall severity (KEV/CVSS/active exploitation also
      // factored in there), mirrors AiSummarization.tsx's clarification.
      parts.push(
        `<p><strong>Vendor severity:</strong> ${esc(tech.vendorSeverity)} <em>(the vendor's own rating -- this report's overall severity also factors in KEV/CVSS/active exploitation, so it can differ)</em></p>`,
      );
    }
    parts.push(
      groupedListsSection("Attack Details", [
        ["Attack vector", tech.attackVector],
        ["Root cause", tech.rootCause],
        ["Exploitation details", tech.exploitationDetails],
        ["Technical findings", tech.technicalFindings],
      ]),
    );
    // Relocated here from the former standalone "Operational Impact" section
    // (removed -- its businessImpact field duplicated businessRisk, and this
    // is technical attacker-behavior detail that belongs alongside Attack
    // Details, not a section of its own).
    if (report.operationalImpact) {
      parts.push(
        groupedListsSection("Detection Challenges & Evasion", [
          ["Detection challenges", report.operationalImpact.detectionChallenges],
          ["Evasion techniques", report.operationalImpact.evasionTechniques],
          ["Attacker objectives", report.operationalImpact.attackerObjectives],
        ]),
      );
    }
    parts.push(
      keyValueSection("Kill Chain", [
        ["Attack chain", tech.attackChain],
        ["Initial access", tech.initialAccess],
        ["Privilege escalation", tech.privilegeEscalation],
        ["Execution", tech.execution],
        ["Persistence", tech.persistence],
        ["Defense evasion", tech.defenseEvasion],
        ["Lateral movement", tech.lateralMovement],
        ["Command & control", tech.commandAndControl],
        ["Data theft", tech.dataTheft],
        ["Ransomware deployment", tech.ransomwareDeployment],
      ]),
    );
  }

  if (report.mitreAttack.length > 0) {
    const rows = report.mitreAttack
      .map((t) => {
        const confidence = t.confidence ? ` [${esc(t.confidence)} confidence]` : "";
        const evidence = t.evidence ? `<br/><em>Evidence: &ldquo;${esc(t.evidence)}&rdquo;</em>` : "";
        return `<li><strong>${esc(t.techniqueId ?? "T????")} -- ${esc(t.technique)}</strong> (${esc(t.killChainPhase)})${confidence}<br/>${esc(t.reason)}${evidence}</li>`;
      })
      .join("");
    parts.push(`${heading(3, "MITRE ATT&CK Mapping")}<ul>${rows}</ul>`);
  }

  if (namedThreatActors.length > 0) {
    const rows = namedThreatActors
      .map((a) => {
        const details = [
          a.aliases.length > 0 ? `aka ${a.aliases.join(", ")}` : null,
          a.motivation ? `Motivation: ${a.motivation}` : null,
          a.geography ? `Geography: ${a.geography}` : null,
          a.targetSectors.length > 0 ? `Target sectors: ${a.targetSectors.join(", ")}` : null,
          a.knownCampaigns.length > 0 ? `Known campaigns: ${a.knownCampaigns.join(", ")}` : null,
        ].filter((x): x is string => Boolean(x));
        return `<li><strong>${esc(a.group)}</strong>${details.length > 0 ? `<br/>${details.map(esc).join("<br/>")}` : ""}</li>`;
      })
      .join("");
    parts.push(`${heading(3, "Threat Actors")}<ul>${rows}</ul>`);
  }

  if (namedMalware.length > 0) {
    const rows = namedMalware
      .map((m) => {
        const details = [
          m.capabilities.length > 0 ? `Capabilities: ${m.capabilities.join(", ")}` : null,
          m.persistence ? `Persistence: ${m.persistence}` : null,
          m.payload ? `Payload: ${m.payload}` : null,
          m.deliveryMechanism ? `Delivery: ${m.deliveryMechanism}` : null,
        ].filter((x): x is string => Boolean(x));
        return `<li><strong>${esc(m.family)}</strong>${details.length > 0 ? `<br/>${details.map(esc).join("<br/>")}` : ""}</li>`;
      })
      .join("");
    parts.push(`${heading(3, "Malware")}<ul>${rows}</ul>`);
  }

  // 6. Top Actions & What's Missing
  if ((risk?.topActions?.length ?? 0) > 0 || risk?.whatsMissing) {
    parts.push(heading(2, "Top Actions & What's Missing"));
    parts.push(groupedListsSection("", [["Top actions", risk?.topActions ?? []]]));
    if (risk?.whatsMissing) parts.push(`<p><em>What's missing: ${esc(risk.whatsMissing)}</em></p>`);
  }

  // 7. IOCs (CVEs shown alongside -- same "Vendor Confirmed Intelligence"
  //    category) -- always renders (not gated on totalIocs > 0) so a
  //    genuinely IOC-free article shows the explicit fallback line rather
  //    than the whole section silently vanishing.
  parts.push(heading(2, "Indicators of Compromise (verified, extracted from source text)"));
  if (report.cves.length > 0) {
    const rows = report.cves
      .map(
        (cve) =>
          `<li><strong>${esc(cve.id)}</strong> -- ${esc(cve.severity)}${cve.cvssScore != null ? `, CVSS ${cve.cvssScore}` : ""}${
            cve.epssScore != null ? `, EPSS ${(cve.epssScore * 100).toFixed(1)}%` : ""
          }${cve.knownExploited ? ", Known Exploited (KEV)" : ""}</li>`,
      )
      .join("");
    parts.push(`${heading(3, "CVEs (verified CVSS/EPSS/KEV)")}<ul>${rows}</ul>`);
  }
  if (totalIocs === 0) {
    parts.push(paragraph("No Indicators of Compromise were published by the vendor."));
  } else {
    const provenanceNote = report.iocProvenance
      ? paragraph(`All indicators below are ${report.iocProvenance.confidence.toLowerCase()} -- extracted directly from ${esc(report.iocProvenance.source)}'s own text, never model-generated. First seen ${new Date(report.iocProvenance.firstSeen).toLocaleDateString()}.`)
      : "";
    parts.push(
      provenanceNote +
        iocRow("IP Addresses", report.iocs.ipAddresses) +
        iocRow("Domains", report.iocs.domains) +
        iocRow("URLs", report.iocs.urls) +
        iocRow("Hashes", report.iocs.hashes) +
        iocRow("Email Addresses", report.iocs.emailAddresses) +
        iocRow("Registry Keys", report.iocs.registryKeys ?? []) +
        iocRow("File Paths", report.iocs.filePaths ?? []) +
        iocRow("File Names", report.iocs.fileNames ?? []) +
        iocRow("Ports", report.iocs.ports ?? []) +
        iocRow("Event IDs", report.iocs.eventIds ?? []) +
        iocRow("Named Pipes", report.iocs.namedPipes ?? []) +
        iocRow("Mutexes", report.iocs.mutexes ?? []) +
        iocRow("Scheduled Tasks", report.iocs.scheduledTasks ?? []) +
        iocRow("Services", report.iocs.services ?? []) +
        iocRow("CWE IDs", report.iocs.cweIds ?? []) +
        iocRow("CLI / PowerShell Commands", report.iocs.cliCommands ?? []) +
        iocRow("User Agents", report.iocs.userAgents ?? []) +
        iocRow("MITRE ATT&CK IDs (in article text)", report.iocs.attackTechniqueIds ?? []) +
        iocRow("Malware Names (in article text)", report.iocs.malwareNames ?? []),
    );
  }

  // 8. Operational Guidance -- one table replacing both the former flat
  //    "Operational Actions" priority table and the five separate per-team
  //    detailed-guidance sections (Intelligence/Executive Takeaway
  //    intentionally dropped from display -- repeated points already
  //    covered above; threatIntelTakeaway itself still feeds the Threat
  //    Intelligence row's Detailed Guidance column).
  parts.push(operationalGuidanceTable(report));

  // 9. Recommendations -- platform/tooling-specific guidance, distinct from
  //     the team-action table above.
  const plat = actions?.platformRecommendations;
  // userRecommendations deliberately excluded from this check -- it's no
  // longer rendered within this section (see End User Recommendations
  // below), so its presence alone shouldn't make an otherwise-empty
  // Recommendations heading render with nothing under it.
  const platSecurityTeamFields = plat ? Object.entries(plat).filter(([key]) => key !== "userRecommendations") : [];
  if (plat && platSecurityTeamFields.some(([, list]) => list.length > 0)) {
    parts.push(heading(2, "Recommendations"));
    parts.push(
      groupedListsSection("", [
        ["Log sources to review", plat.logSourcesToReview],
        ["Microsoft Defender XDR", plat.microsoftDefenderRecommendations],
        ["Microsoft Sentinel", plat.microsoftSentinelRecommendations],
        ["Firewall / DNS", plat.firewallDnsRecommendations],
        ["Email security (Defender for Office 365)", plat.emailSecurityRecommendations],
        ["Identity monitoring", plat.identityMonitoringRecommendations],
        ["EDR", plat.edrRecommendations],
      ]),
    );
  }

  // 10. End User Recommendations -- its own section, deliberately last
  //     before Source (mirrors AiSummarization.tsx) since it's addressed to
  //     a different audience (employees, not security staff).
  const userRecs = actions?.platformRecommendations?.userRecommendations ?? [];
  if (userRecs.length > 0) {
    parts.push(`${heading(2, "End User Recommendations")}<ul>${userRecs.map((r) => `<li>${esc(r)}</li>`).join("")}</ul>`);
  }

  // 11. Source -- last, always.
  if (report.references.length > 0) {
    const rows = report.references.map((ref) => `<li><a href="${esc(ref.url)}">${esc(ref.label)}</a></li>`).join("");
    parts.push(`${heading(2, "Source")}<ul>${rows}</ul>`);
  }

  return parts.filter(Boolean).join("\n");
}

const SHARED_STYLES = `
  body { font-family: Calibri, Arial, sans-serif; color: #1a1a1a; line-height: 1.5; }
  h1 { font-size: 20pt; margin-bottom: 4px; }
  h2 { font-size: 15pt; margin-top: 24px; border-bottom: 1px solid #ccc; padding-bottom: 4px; }
  h3 { font-size: 12pt; margin-top: 16px; margin-bottom: 4px; }
  h4 { font-size: 10.5pt; margin-top: 10px; margin-bottom: 2px; }
  p.meta { color: #555; font-size: 10pt; margin: 2px 0; }
  p.group-label { margin-bottom: 2px; }
  ul { margin-top: 4px; }
  li { margin-bottom: 4px; }
  a { color: #1a5fb4; }
  table.ops-table { border-collapse: collapse; width: 100%; margin-top: 8px; font-size: 9pt; }
  table.ops-table th, table.ops-table td { border: 1px solid #ccc; padding: 6px 8px; text-align: left; vertical-align: top; }
  table.ops-table th { background: #f0f0f0; font-size: 8pt; text-transform: uppercase; letter-spacing: 0.03em; }
  table.ops-table td ul { margin: 0; padding-left: 16px; }
  table.ops-table td li { margin-bottom: 2px; }
`;

function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/** Real .doc file Word opens natively via its own HTML import filter -- the xmlns:w namespace is what tells Word to treat this as "HTML from Word" rather than a generic renamed file, avoiding the "format differs from extension" warning. */
export function downloadReportAsWord(report: AiThreatSummaryReport) {
  const body = buildReportBodyHtml(report);
  const html =
    `<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:w="urn:schemas-microsoft-com:office:word" xmlns="http://www.w3.org/TR/REC-html40">` +
    `<head><meta charset="utf-8"><title>${esc(report.articleTitle)}</title>` +
    `<!--[if gte mso 9]><xml><w:WordDocument><w:View>Print</w:View><w:Zoom>100</w:Zoom></w:WordDocument></xml><![endif]-->` +
    `<style>${SHARED_STYLES}</style></head><body>${body}</body></html>`;

  const blob = new Blob([html], { type: "application/msword" });
  triggerDownload(blob, `${safeFilename(report.articleTitle)}.doc`);
}

/**
 * Renders the report into a hidden same-page iframe and triggers the
 * browser's print dialog on it -- "Save as PDF" there produces a real,
 * selectable-text PDF (not a screenshot), with no new client-side
 * PDF-rendering dependency. Deliberately not window.open(): a new-tab popup
 * is subject to popup blockers (confirmed live some browser configurations
 * block it even from a direct click), while an iframe already part of the
 * current page's DOM never triggers that check at all.
 */
export function downloadReportAsPdf(report: AiThreatSummaryReport) {
  const body = buildReportBodyHtml(report);
  const html =
    `<html><head><meta charset="utf-8"><title>${esc(report.articleTitle)}</title>` +
    `<style>${SHARED_STYLES} @page { margin: 2cm; } @media print { a { color: #1a1a1a; text-decoration: none; } }</style></head>` +
    `<body>${body}</body></html>`;

  const iframe = document.createElement("iframe");
  iframe.style.position = "fixed";
  iframe.style.right = "0";
  iframe.style.bottom = "0";
  iframe.style.width = "0";
  iframe.style.height = "0";
  iframe.style.border = "0";
  document.body.appendChild(iframe);

  let removed = false;
  const cleanup = () => {
    if (removed) return; // afterprint and the fallback timeout below can both fire -- only remove the node once
    removed = true;
    document.body.removeChild(iframe);
  };

  iframe.onload = () => {
    // Printing removes the iframe once the print dialog closes (or right
    // after print() returns on browsers that don't fire afterprint on
    // hidden frames) -- a short fallback timeout covers the latter case.
    const frameWindow = iframe.contentWindow;
    if (!frameWindow) return cleanup();
    frameWindow.addEventListener("afterprint", cleanup, { once: true });
    frameWindow.focus();
    frameWindow.print();
    setTimeout(cleanup, 2000);
  };

  const doc = iframe.contentDocument;
  if (!doc) return cleanup();
  doc.open();
  doc.write(html);
  doc.close();
}
