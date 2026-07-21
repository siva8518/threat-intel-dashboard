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

function heading(level: 1 | 2 | 3, text: string): string {
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
  return `${heading(3, title)}${rows}`;
}

function listSection(title: string, items: string[]): string {
  if (items.length === 0) return "";
  const lis = items.map((item) => `<li>${esc(item)}</li>`).join("");
  return `${heading(3, title)}<ul>${lis}</ul>`;
}

/** Groups of string[] keyed by a human label -- mirrors AiSummarization.tsx's GroupedLists/GroupedCodeLists, minus the two components' only difference (monospace styling), which doesn't matter for a printed/Word document. */
function groupedListsSection(title: string, groups: Array<[string, string[]]>): string {
  const nonEmpty = groups.filter(([, items]) => items.length > 0);
  if (nonEmpty.length === 0) return "";
  const body = nonEmpty
    .map(([label, items]) => `<p class="group-label"><strong>${esc(label)}</strong></p><ul>${items.map((item) => `<li>${esc(item)}</li>`).join("")}</ul>`)
    .join("");
  return `${heading(3, title)}${body}`;
}

function iocRow(label: string, values: string[]): string {
  if (values.length === 0) return "";
  return `<p><strong>${esc(label)} (${values.length}):</strong> ${values.map(esc).join(", ")}</p>`;
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
  const totalIocs = report.iocs.ipAddresses.length + report.iocs.domains.length + report.iocs.urls.length + report.iocs.hashes.length + report.iocs.emailAddresses.length;
  const kevCount = report.cves.filter((c) => c.knownExploited).length;
  const summary = report.aiTechnicalSummary;

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

  parts.push(
    groupedListsSection("AI Technical Summary", [
      ["Threat", summary.threat],
      ["Attack Vector", summary.attackVector],
      ["Root Cause", summary.rootCause],
      ["Exploitation Details", summary.exploitationDetails],
      ["Technical Findings", summary.technicalFindings],
      ["Security Implications", summary.securityImplications],
      ["Detection Opportunities", summary.detectionOpportunities],
      ["Hunting Opportunities", summary.huntingOpportunities],
      ["Immediate Actions", summary.immediateActions],
    ]),
  );

  parts.push(heading(2, "Executive Summary"));
  parts.push(paragraph(report.executiveSummary));

  parts.push(
    keyValueSection("Business Impact", [
      ["Business risk", report.businessImpact.businessRisk],
      ["Operational disruption", report.businessImpact.operationalDisruption],
      ["Likelihood of exploitation", report.businessImpact.likelihoodOfExploitation],
      ["Impact if unpatched", report.businessImpact.impactIfUnpatched],
    ]),
  );
  if (report.businessImpact.industriesCommonlyTargeted.length > 0) {
    parts.push(`<p><em>Industries commonly targeted: ${report.businessImpact.industriesCommonlyTargeted.map(esc).join(", ")}</em></p>`);
  }

  parts.push(
    keyValueSection("Threat Overview", [
      ["Attack chain", report.threatOverview.attackChain],
      ["Initial access", report.threatOverview.initialAccess],
      ["Privilege escalation", report.threatOverview.privilegeEscalation],
      ["Execution", report.threatOverview.execution],
      ["Persistence", report.threatOverview.persistence],
      ["Defense evasion", report.threatOverview.defenseEvasion],
      ["Lateral movement", report.threatOverview.lateralMovement],
      ["Command & control", report.threatOverview.commandAndControl],
      ["Data theft", report.threatOverview.dataTheft],
      ["Ransomware deployment", report.threatOverview.ransomwareDeployment],
    ]),
  );

  parts.push(
    groupedListsSection("Affected Products", [
      ["Products", report.affectedProducts.products],
      ["Versions", report.affectedProducts.versions],
      ["Operating systems", report.affectedProducts.operatingSystems],
      ["Cloud services", report.affectedProducts.cloudServices],
      ["Applications", report.affectedProducts.applications],
    ]),
  );

  parts.push(
    keyValueSection("Severity Assessment", [
      ["Vendor severity", report.vendorSeverityAssessment.vendorSeverity],
      ["Active exploitation", report.vendorSeverityAssessment.activeExploitation],
      ["Overall SOC priority", report.vendorSeverityAssessment.overallSocPriority],
    ]),
  );

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

  if (report.mitreAttack.length > 0) {
    const rows = report.mitreAttack
      .map((t) => `<li><strong>${esc(t.techniqueId ?? "T????")} -- ${esc(t.technique)}</strong> (${esc(t.killChainPhase)})<br/>${esc(t.reason)}</li>`)
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

  if (totalIocs > 0) {
    parts.push(
      `${heading(3, "Indicators of Compromise (verified, extracted from source text)")}` +
        iocRow("IP Addresses", report.iocs.ipAddresses) +
        iocRow("Domains", report.iocs.domains) +
        iocRow("URLs", report.iocs.urls) +
        iocRow("Hashes", report.iocs.hashes) +
        iocRow("Email Addresses", report.iocs.emailAddresses),
    );
  }

  parts.push(listSection("Detection Opportunities", report.detectionOpportunities));

  parts.push(
    groupedListsSection("Threat Hunting Opportunities", [
      ["Microsoft Defender XDR (KQL)", report.threatHuntingOpportunities.defenderXdrKql],
      ["Microsoft Sentinel (KQL)", report.threatHuntingOpportunities.sentinelKql],
      ["Splunk (SPL)", report.threatHuntingOpportunities.splunkSpl],
      ["Elastic", report.threatHuntingOpportunities.elastic],
      ["Sigma", report.threatHuntingOpportunities.sigma],
      ["YARA", report.threatHuntingOpportunities.yara],
      ["CrowdStrike Falcon", report.threatHuntingOpportunities.crowdstrikeFalcon],
      ["Carbon Black", report.threatHuntingOpportunities.carbonBlack],
    ]),
  );

  parts.push(
    groupedListsSection("Detection Engineering Opportunities", [
      ["New analytics", report.detectionEngineeringOpportunities.newAnalytics],
      ["New correlation rules", report.detectionEngineeringOpportunities.newCorrelationRules],
      ["New Sigma rules", report.detectionEngineeringOpportunities.newSigmaRules],
      ["New KQL detections", report.detectionEngineeringOpportunities.newKqlDetections],
      ["EDR behavioral detections", report.detectionEngineeringOpportunities.edrBehavioralDetections],
      ["SIEM correlation logic", report.detectionEngineeringOpportunities.siemCorrelationLogic],
      ["MITRE coverage gaps", report.detectionEngineeringOpportunities.mitreCoverageGaps],
      ["Telemetry gaps", report.detectionEngineeringOpportunities.telemetryGaps],
      ["Log source requirements", report.detectionEngineeringOpportunities.logSourceRequirements],
    ]),
  );

  parts.push(
    groupedListsSection("Incident Response Guidance", [
      ["Immediate triage steps", report.incidentResponseGuidance.immediateTriageSteps],
      ["Evidence to collect", report.incidentResponseGuidance.evidenceToCollect],
      ["Containment actions", report.incidentResponseGuidance.containmentActions],
      ["Forensic artifacts", report.incidentResponseGuidance.forensicArtifacts],
      ["Recovery actions", report.incidentResponseGuidance.recoveryActions],
      ["Validation steps", report.incidentResponseGuidance.validationSteps],
    ]),
  );

  parts.push(
    groupedListsSection("Immediate Recommendations", [
      ["Critical", report.immediateRecommendations.critical],
      ["High", report.immediateRecommendations.high],
      ["Medium", report.immediateRecommendations.medium],
      ["Low", report.immediateRecommendations.low],
    ]),
  );

  parts.push(
    groupedListsSection("Patch Information", [
      ["Fixed versions", report.patchInformationNarrative.fixedVersions],
      ["Temporary mitigations", report.patchInformationNarrative.temporaryMitigations],
      ["Known workarounds", report.patchInformationNarrative.knownWorkarounds],
    ]),
  );
  if (report.patchInformationNarrative.availability !== "Not Reported" || report.patchInformationNarrative.vendorGuidance) {
    const lines = [
      report.patchInformationNarrative.availability !== "Not Reported" ? `Availability: ${report.patchInformationNarrative.availability}` : null,
      report.patchInformationNarrative.vendorGuidance ? `Vendor guidance: ${report.patchInformationNarrative.vendorGuidance}` : null,
    ].filter((x): x is string => Boolean(x));
    parts.push(lines.map((l) => `<p>${esc(l)}</p>`).join(""));
  }

  parts.push(heading(2, "Role-Based Takeaways"));
  parts.push(heading(3, "SOC Analyst"));
  parts.push(paragraph(report.socAnalystTakeaway));
  parts.push(heading(3, "Detection Engineer"));
  parts.push(paragraph(report.detectionEngineerTakeaway));
  parts.push(heading(3, "Threat Hunter"));
  parts.push(paragraph(report.threatHunterTakeaway));
  parts.push(heading(3, "Threat Intel"));
  parts.push(paragraph(report.threatIntelTakeaway));
  parts.push(heading(3, "Executive Leadership"));
  parts.push(paragraph(report.executiveLeadershipTakeaway));

  parts.push(heading(2, "Confidence & Risk Reasoning"));
  parts.push(paragraph(`Confidence (${report.confidenceAssessment.level}): ${report.confidenceAssessment.reasoning}`));
  parts.push(paragraph(`Risk score reasoning: ${report.aiRiskScoring.reasoning}`));

  if (report.references.length > 0) {
    const rows = report.references.map((ref) => `<li><a href="${esc(ref.url)}">${esc(ref.label)}</a></li>`).join("");
    parts.push(`${heading(2, "References")}<ul>${rows}</ul>`);
  }

  return parts.filter(Boolean).join("\n");
}

const SHARED_STYLES = `
  body { font-family: Calibri, Arial, sans-serif; color: #1a1a1a; line-height: 1.5; }
  h1 { font-size: 20pt; margin-bottom: 4px; }
  h2 { font-size: 15pt; margin-top: 24px; border-bottom: 1px solid #ccc; padding-bottom: 4px; }
  h3 { font-size: 12pt; margin-top: 16px; margin-bottom: 4px; }
  p.meta { color: #555; font-size: 10pt; margin: 2px 0; }
  p.group-label { margin-bottom: 2px; }
  ul { margin-top: 4px; }
  li { margin-bottom: 4px; }
  a { color: #1a5fb4; }
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
