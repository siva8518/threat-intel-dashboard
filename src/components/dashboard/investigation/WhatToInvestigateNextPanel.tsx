// Standalone "What To Investigate Next" section -- merges the two "here's
// your next step" fields this page produces (ShouldICarePanel's removed
// "Next Action" and the correlation engine's own next-steps list, formerly
// rendered by the now-removed AI Correlation Summary panel) into ONE place
// instead of two differently-labeled boxes making the same kind of
// recommendation. The correlation summary is still fetched (see
// useInvestigationWorkspace.ts) purely to feed nextSteps here -- its other
// fields (whatIsThis/relationshipNarrative/etc.) are no longer displayed
// anywhere.
//
// Split into two explicitly labeled sections per this platform's own
// constraint: it has NO EDR/SIEM/XDR/firewall/DNS/proxy/netflow/VPN or
// other internal telemetry integration, so "what this platform can
// investigate" (external intelligence pivots -- AI-authored, grounded
// server-side) and "what the analyst must check in their own tools"
// (deterministic, never-AI-authored runbook -- see
// server/investigation/actionability.js#environmentalValidationPlan)
// must never be presented as though this platform already performed both.
import { Sparkles, Compass, ShieldQuestion, Radio, Clock3, FlaskConical, AlertTriangle } from "lucide-react";
import { Section } from "../reportPrimitives";
import { Badge } from "@/components/ui/badge";
import type { ShouldICareAssessment, CorrelationSummary, EnvironmentalValidationPlan, AnalystVerdict, CveInvestigationStep, SandboxInvestigationStep } from "@/types/threat-intel";

interface WhatToInvestigateNextPanelProps {
  shouldICare: ShouldICareAssessment | null;
  shouldICarePending: boolean;
  shouldICareError?: string | null;
  correlationSummary: CorrelationSummary | null;
  correlationSummaryPending: boolean;
  correlationSummaryError?: string | null;
  environmentalValidation: EnvironmentalValidationPlan | null;
  /** CVE searches replace the free-form AI Section 1 entirely with this deterministic, evidence-conditioned list -- see server/investigation/actionability.js#cveInvestigationSteps. null for every other entity type. */
  cveInvestigationSteps: CveInvestigationStep[] | null;
  /** Appended below Section 1 (not a replacement -- a URL/domain/hash search still has its own reputation-driven content too) only when a COMPLETED sandbox report exists -- see server/investigation/actionability.js#sandboxInvestigationSteps. */
  sandboxInvestigationSteps: SandboxInvestigationStep[] | null;
}

const SANDBOX_STEP_PRIORITY_VARIANT: Record<SandboxInvestigationStep["priority"], "critical" | "high" | "medium" | "low"> = {
  Immediate: "critical",
  High: "high",
  Normal: "medium",
  Low: "low",
};

const CVE_STEP_PRIORITY_VARIANT: Record<CveInvestigationStep["priority"], "critical" | "high" | "medium" | "low"> = {
  Immediate: "critical",
  High: "high",
  Normal: "medium",
  Low: "low",
};

/** Coarse keyword match against the free-text priority label -- these strings are authored server-side in actionability.js, not user input, so a simple substring match is enough to color the badge without needing a closed enum. */
function priorityVariant(priority: string): "critical" | "high" | "medium" | "low" {
  const p = priority.toLowerCase();
  if (p.includes("critical")) return "critical";
  if (p.includes("high")) return "high";
  if (p.includes("monitor")) return "low";
  return "medium";
}

const EXPOSURE_VARIANT: Record<AnalystVerdict["exposure"], "critical" | "medium" | "low"> = { Confirmed: "critical", Suspected: "medium", None: "low" };
const IMPACT_VARIANT: Record<AnalystVerdict["impact"], "critical" | "high" | "medium" | "low"> = { Critical: "critical", High: "high", Medium: "medium", Low: "low" };
const CONFIDENCE_VARIANT: Record<AnalystVerdict["confidence"], "cyan" | "medium" | "muted"> = { High: "cyan", Medium: "medium", Low: "muted" };

function formatDate(iso: string | null): string {
  if (!iso) return "Unknown";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "Unknown" : d.toLocaleDateString();
}

export function WhatToInvestigateNextPanel({
  shouldICare,
  shouldICarePending,
  shouldICareError = null,
  correlationSummary,
  correlationSummaryPending,
  correlationSummaryError = null,
  environmentalValidation,
  cveInvestigationSteps,
  sandboxInvestigationSteps,
}: WhatToInvestigateNextPanelProps) {
  // CVE searches never had a real intelligence graph for the free-form AI
  // nextSteps to reason over, so that path fell back to generic filler like
  // "pivot to other high-severity CVEs" -- unhelpful and ungrounded in this
  // specific CVE. cveInvestigationSteps is non-null only for CVE searches
  // and REPLACES the AI content below rather than supplementing it, so that
  // filler can never be shown again.
  const isCve = cveInvestigationSteps !== null;
  const nextAction = shouldICare?.nextAction ?? null;
  const nextSteps = correlationSummary?.nextSteps ?? [];
  // Either underlying generation may still be running -- show the content
  // that's already in as soon as it's in, rather than waiting on both, but
  // keep a quiet "still generating" note while a source that hasn't
  // resolved yet might still add more.
  const stillWaiting = !isCve && ((shouldICarePending && !shouldICare) || (correlationSummaryPending && !correlationSummary));
  const hasIntelligenceContent = isCve ? cveInvestigationSteps.length > 0 : Boolean(nextAction) || nextSteps.length > 0;
  // A source that ended in an error (never resolved to real content) is NOT
  // the same as "this platform genuinely has nothing further to add" -- the
  // direct fix for a real reported bug where an all-AI-providers-failed
  // error was silently swallowed and rendered as the misleading "No further
  // intelligence pivots identified", indistinguishable from a real empty
  // result. Only surfaced when there's no content at all to show instead.
  const generationError = !isCve && !hasIntelligenceContent ? (shouldICareError ?? correlationSummaryError ?? null) : null;

  const hasSandboxContent = Boolean(sandboxInvestigationSteps?.length);
  if (!hasIntelligenceContent && !environmentalValidation && !stillWaiting && !hasSandboxContent && !generationError) return null;

  return (
    <Section title="What To Investigate Next">
      <div className="space-y-6">
        <div>
          <p className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
            <Compass className="h-3.5 w-3.5" /> Section 1 — Intelligence Investigation (this platform)
          </p>
          <div className="space-y-2">
            {isCve ? (
              cveInvestigationSteps.length > 0 ? (
                <div className="space-y-2.5">
                  {cveInvestigationSteps.map((s, i) => (
                    <div key={i} className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3">
                      <div className="mb-1 flex flex-wrap items-center gap-2">
                        <Badge variant={CVE_STEP_PRIORITY_VARIANT[s.priority]}>{s.priority}</Badge>
                        <p className="text-sm font-semibold text-foreground">{s.title}</p>
                      </div>
                      <p className="text-sm text-foreground/90">{s.detail}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-muted">No further intelligence pivots identified.</p>
              )
            ) : (
              <>
                {nextAction && <p className="text-sm text-foreground">{nextAction}</p>}
                {nextSteps.length > 0 && (
                  <ul className="list-disc space-y-1 pl-4 text-sm text-foreground">
                    {nextSteps.map((line, i) => (
                      <li key={i}>{line}</li>
                    ))}
                  </ul>
                )}
                {!hasIntelligenceContent && !stillWaiting && !generationError && <p className="text-xs text-muted">No further intelligence pivots identified.</p>}
                {generationError && (
                  <p className="flex items-start gap-1.5 text-xs text-amber-400">
                    <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                    <span>AI-generated pivots unavailable right now ({generationError}) -- this is not the same as "nothing found"; try refreshing this search shortly.</span>
                  </p>
                )}
                {stillWaiting && (
                  <p className="flex items-center gap-1.5 text-xs text-muted">
                    <Sparkles className="h-3.5 w-3.5 animate-pulse text-primary" /> Still generating additional investigative guidance…
                  </p>
                )}
              </>
            )}
          </div>
        </div>

        {hasSandboxContent && (
          <div>
            <p className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
              <FlaskConical className="h-3.5 w-3.5" /> Sandbox-Derived Findings
            </p>
            <div className="space-y-2.5">
              {sandboxInvestigationSteps!.map((s, i) => (
                <div key={i} className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3">
                  <div className="mb-1.5 flex flex-wrap items-center gap-2">
                    <Badge variant={SANDBOX_STEP_PRIORITY_VARIANT[s.priority]}>{s.priority}</Badge>
                  </div>
                  <p className="mb-1 text-sm text-foreground">{s.observation}</p>
                  <p className="mb-1.5 text-xs text-muted">{s.whyItMatters}</p>
                  <dl className="space-y-1 text-xs">
                    <div>
                      <dt className="inline font-semibold text-foreground/90">Search: </dt>
                      <dd className="inline text-foreground/90">{s.investigation}</dd>
                    </div>
                    <div>
                      <dt className="inline font-semibold text-foreground/90">Escalate if: </dt>
                      <dd className="inline text-foreground/90">{s.escalationCondition}</dd>
                    </div>
                    <div>
                      <dt className="inline font-semibold text-foreground/90">Then: </dt>
                      <dd className="inline text-foreground/90">{s.action}</dd>
                    </div>
                  </dl>
                </div>
              ))}
            </div>
          </div>
        )}

        {environmentalValidation && (
          <div>
            <p className="mb-1.5 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
              <ShieldQuestion className="h-3.5 w-3.5" /> Section 2 — Environmental Validation (your own tools)
            </p>
            <p className="mb-1 text-sm text-foreground">{environmentalValidation.purpose}</p>
            <p className="mb-4 text-xs text-muted">{environmentalValidation.platformLimitation}</p>

            {/* Improvement 3: Analyst Verdict -- the synthesized headline read, computed from the same verdict this search already resolved. Answers what/how serious/how confident/what next in one place, before the step-by-step detail below. */}
            <div className="mb-5 rounded-xl border border-white/[0.08] bg-white/[0.03] p-4">
              <div className="mb-3 flex flex-wrap items-center gap-4">
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-wide text-muted">Exposure</p>
                  <Badge variant={EXPOSURE_VARIANT[environmentalValidation.analystVerdict.exposure]}>{environmentalValidation.analystVerdict.exposure}</Badge>
                </div>
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-wide text-muted">Impact</p>
                  <Badge variant={IMPACT_VARIANT[environmentalValidation.analystVerdict.impact]}>{environmentalValidation.analystVerdict.impact}</Badge>
                </div>
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-wide text-muted">Confidence</p>
                  <Badge variant={CONFIDENCE_VARIANT[environmentalValidation.analystVerdict.confidence]}>{environmentalValidation.analystVerdict.confidence}</Badge>
                </div>
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-wide text-muted">Priority</p>
                  <Badge variant={priorityVariant(environmentalValidation.analystVerdict.priority)}>{environmentalValidation.analystVerdict.priority}</Badge>
                </div>
              </div>
              <p className="mb-2 text-xs text-muted">{environmentalValidation.analystVerdict.exposureNote}</p>
              <dl className="space-y-1.5 text-xs">
                <div>
                  <dt className="inline font-semibold text-foreground">What happened? </dt>
                  <dd className="inline text-foreground/90">{environmentalValidation.analystVerdict.whatHappened}</dd>
                </div>
                <div>
                  <dt className="inline font-semibold text-foreground">How serious is it? </dt>
                  <dd className="inline text-foreground/90">{environmentalValidation.analystVerdict.howSerious}</dd>
                </div>
                <div>
                  <dt className="inline font-semibold text-foreground">How confident are we? </dt>
                  <dd className="inline text-foreground/90">{environmentalValidation.analystVerdict.howConfident}</dd>
                </div>
              </dl>
              {environmentalValidation.analystVerdict.recommendedActions.length > 0 && (
                <div className="mt-3 border-t border-white/[0.06] pt-2.5">
                  <p className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-muted">What should the analyst do next?</p>
                  <ul className="list-disc space-y-1 pl-4 text-xs text-foreground/90">
                    {environmentalValidation.analystVerdict.recommendedActions.map((line, i) => (
                      <li key={i}>{line}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>

            {/* Improvement 2: telemetry coverage + observation window. */}
            <div className="mb-5 grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3">
                <p className="mb-1.5 flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wide text-muted">
                  <Radio className="h-3 w-3" /> Telemetry Coverage
                </p>
                <ul className="space-y-1 text-xs">
                  {environmentalValidation.telemetryCoverage.map((entry, i) => (
                    <li key={i} className="flex items-center justify-between gap-2">
                      <span className="text-foreground/90">{entry.source}</span>
                      <Badge variant={entry.available ? "low" : "muted"}>{entry.available ? "Connected" : "Not Connected"}</Badge>
                    </li>
                  ))}
                </ul>
              </div>
              <div className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3">
                <p className="mb-1.5 flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wide text-muted">
                  <Clock3 className="h-3 w-3" /> Observation Window
                </p>
                <div className="space-y-2 text-xs">
                  <div>
                    <p className="text-foreground/90">
                      External: {formatDate(environmentalValidation.observationWindow.externalFirstSeen)} — {formatDate(environmentalValidation.observationWindow.externalLastSeen)}
                    </p>
                    <p className="text-muted">{environmentalValidation.observationWindow.externalWindowNote}</p>
                  </div>
                  {environmentalValidation.observationWindow.historicalSightingCount != null && (
                    <div>
                      <p className="text-foreground/90">
                        This platform's history: {formatDate(environmentalValidation.observationWindow.historicalFirstSeen)} — {formatDate(environmentalValidation.observationWindow.historicalLastSeen)} ({environmentalValidation.observationWindow.historicalSightingCount} sighting
                        {environmentalValidation.observationWindow.historicalSightingCount === 1 ? "" : "s"})
                      </p>
                    </div>
                  )}
                  <p className="text-muted">{environmentalValidation.observationWindow.internalWindowNote}</p>
                </div>
              </div>
            </div>

            <div className="space-y-4">
              {environmentalValidation.steps.map((step, i) => (
                <div key={i} className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3">
                  <p className="mb-1.5 text-sm font-semibold text-foreground">{step.title}</p>
                  <ul className="list-disc space-y-1 pl-4 text-sm text-foreground/90">
                    {step.items.map((item, j) => (
                      <li key={j}>{item}</li>
                    ))}
                  </ul>
                  {step.decision && step.decision.length > 0 && (
                    <div className="mt-2 border-t border-white/[0.06] pt-2">
                      <p className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-muted">Decision</p>
                      <ul className="space-y-0.5 text-xs text-muted">
                        {step.decision.map((line, j) => (
                          <li key={j}>{line}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              ))}
            </div>

            {environmentalValidation.scopeExposure.length > 0 && (
              <div className="mt-4">
                <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">Scope the Exposure — Determine</p>
                <ul className="grid list-disc grid-cols-1 gap-x-4 gap-y-1 pl-4 text-sm text-foreground/90 sm:grid-cols-2">
                  {environmentalValidation.scopeExposure.map((line, i) => (
                    <li key={i}>{line}</li>
                  ))}
                </ul>
              </div>
            )}

            {environmentalValidation.decisionMatrix.length > 0 && (
              <div className="mt-4">
                <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">Reference: Priority Guide (general findings, not specific to this search)</p>
                <div className="overflow-x-auto rounded-lg border border-white/[0.06]">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-white/[0.06] text-muted">
                        <th className="px-3 py-2 font-semibold uppercase tracking-wide">Finding</th>
                        <th className="px-3 py-2 font-semibold uppercase tracking-wide">Recommended Priority</th>
                      </tr>
                    </thead>
                    <tbody>
                      {environmentalValidation.decisionMatrix.map((row, i) => (
                        <tr key={i} className="border-b border-white/[0.04] last:border-0">
                          <td className="px-3 py-2 text-foreground/90">{row.finding}</td>
                          <td className="px-3 py-2">
                            <Badge variant={priorityVariant(row.priority)}>{row.priority}</Badge>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </Section>
  );
}
