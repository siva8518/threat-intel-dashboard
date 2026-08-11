// AI Investigation Summary -- one on-demand call (see useGenerateInvestigationAiReport
// / server/investigationAi.js), fired only by the "Generate AI Report" button,
// never automatically on search. Split into two panels: AiSummaryPanel (the
// verdict/evidence/assessment/gaps synthesis, near the top) and
// AiInvestigationActionsPanel (the three role-specific action lists, further
// down) -- both share one piece of report state from the parent.
//
// Renders the DETERMINISTIC/MODEL-AUTHORED split explicitly: confirmedFacts
// and sourceIntelligence are real, code-generated data (never AI-authored),
// shown as plain facts; assessedConclusions/potentialAttackRole/
// correlationAssessment/intelligenceGaps are the model's synthesis, each
// already run through this platform's fail-closed grounding guards before
// reaching this component -- rendered with their own confidence, never
// presented as equally certain as the confirmed facts above them.
import { BrainCircuit, Loader2, ShieldAlert, ShieldOff, ShieldQuestion } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Section, FieldList } from "../reportPrimitives";
import type { AiInvestigationReport, BlockRecommendation } from "@/types/threat-intel";

interface AiReportState {
  report: AiInvestigationReport | undefined;
  isPending: boolean;
  error: string | null;
  onGenerate: () => void;
}

const CONFIDENCE_VARIANT: Record<string, "high" | "medium" | "low" | "muted"> = {
  High: "high",
  Medium: "medium",
  Low: "low",
  Unknown: "muted",
};

const BLOCK_ICON: Record<BlockRecommendation, typeof ShieldAlert> = {
  Block: ShieldAlert,
  "Monitor — Do Not Block": ShieldQuestion,
  "Do Not Block": ShieldOff,
  "Not Applicable": ShieldOff,
};

const BLOCK_VARIANT: Record<BlockRecommendation, "critical" | "medium" | "low" | "muted"> = {
  Block: "critical",
  "Monitor — Do Not Block": "medium",
  "Do Not Block": "low",
  "Not Applicable": "muted",
};

function ConfidenceBadge({ confidence }: { confidence: string }) {
  return <Badge variant={CONFIDENCE_VARIANT[confidence] ?? "muted"}>{confidence}</Badge>;
}

const SOURCE_STATUS_LABEL: Record<string, string> = {
  data_returned: "Data returned",
  no_data: "Queried — no additional relevant intelligence returned",
  not_configured: "Not configured",
  rate_limited: "Rate limited",
  skipped: "Skipped",
};

function SourceIntelligenceList({ items }: { items: AiInvestigationReport["sourceIntelligence"] }) {
  if (items.length === 0) return null;
  return (
    <div>
      <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-muted">Source Intelligence</p>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        {items.map((s) => (
          <div key={s.source} className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-2.5 text-xs">
            <div className="mb-1 flex items-center justify-between gap-2">
              <span className="font-semibold text-foreground">{s.source}</span>
              {s.verdict && <Badge variant="muted">{s.verdict}</Badge>}
            </div>
            {s.fields.length > 0 ? (
              <ul className="space-y-0.5 text-muted">
                {s.fields.slice(0, 6).map((f) => (
                  <li key={f.key}>
                    <span className="text-foreground/80">{f.key}:</span> {Array.isArray(f.value) ? f.value.join(", ") : String(f.value)}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-muted">{SOURCE_STATUS_LABEL[s.status] ?? s.status}</p>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

export function AiSummaryPanel({ report, isPending, error, onGenerate }: AiReportState) {
  return (
    <div className="rounded-xl border border-primary/20 bg-primary/[0.04] p-4">
      <div className="mb-2 flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <BrainCircuit className="h-4 w-4 text-primary" />
          <h3 className="text-sm font-semibold text-foreground">AI Investigation Summary</h3>
        </div>
        <Button type="button" variant="outline" onClick={onGenerate} disabled={isPending}>
          {isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <BrainCircuit className="h-3.5 w-3.5" />}
          {report ? "Regenerate AI Report" : "Generate AI Report"}
        </Button>
      </div>
      {error && <p className="text-xs text-critical">{error}</p>}
      {!report && !isPending && !error && (
        <p className="text-xs text-muted">
          Not generated yet — click "Generate AI Report" for a senior Threat Intelligence Analyst-style read: verdict explanation, confirmed evidence,
          assessed conclusions with per-claim confidence, correlation across sources, intelligence gaps, and a recommended next pivot. This is a real LLM
          call and can take up to a minute.
        </p>
      )}
      {isPending && <p className="text-xs text-muted">Generating — this can take up to a minute...</p>}
      {report && (
        <div className="space-y-4 text-sm">
          <div>
            <p className="text-foreground">{report.indicatorVerdictExplanation}</p>
            <p className="mt-1.5 text-foreground">{report.executiveAssessment}</p>
          </div>

          {report.confirmedFacts.length > 0 && (
            <div>
              <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-muted">Observed Intelligence (Confirmed)</p>
              <ul className="space-y-1">
                {report.confirmedFacts.map((f, i) => (
                  <li key={i} className="flex gap-1.5 text-xs">
                    <span className="shrink-0 font-semibold text-foreground/80">{f.source}:</span>
                    <span className="text-foreground">{f.fact}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {report.assessedConclusions.length > 0 && (
            <div>
              <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-muted">Threat Assessment (Analyst Conclusions)</p>
              <div className="space-y-1.5">
                {report.assessedConclusions.map((c, i) => (
                  <div key={i} className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-2 text-xs">
                    <div className="mb-0.5 flex items-center gap-1.5">
                      <ConfidenceBadge confidence={c.confidence} />
                      <span className="font-semibold text-foreground">{c.claim}</span>
                    </div>
                    {c.reasoning && <p className="text-muted">{c.reasoning}</p>}
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-wide text-muted">Potential Attack Role</p>
              <p className="text-foreground">{report.potentialAttackRole}</p>
            </div>
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-wide text-muted">Correlation Assessment</p>
              <p className="text-foreground">{report.correlationAssessment}</p>
            </div>
          </div>

          <SourceIntelligenceList items={report.sourceIntelligence} />

          {(report.relatedIntelligence.activeCampaigns.length > 0 || report.relatedIntelligence.associatedThreatActors.length > 0 || report.relatedIntelligence.matchedMalwareFamilies.length > 0) && (
            <div>
              <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-muted">Related Intelligence</p>
              <div className="flex flex-wrap gap-1.5">
                {report.relatedIntelligence.associatedThreatActors.map((a) => (
                  <Badge key={`actor-${a}`} variant="muted">
                    Actor: {a}
                  </Badge>
                ))}
                {report.relatedIntelligence.matchedMalwareFamilies.map((m) => (
                  <Badge key={`malware-${m}`} variant="muted">
                    Malware: {m}
                  </Badge>
                ))}
                {report.relatedIntelligence.activeCampaigns.map((c) => (
                  <Badge key={`campaign-${c}`} variant="muted">
                    Campaign: {c}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {report.mitreAttackMapping.length > 0 && (
            <div>
              <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-muted">ATT&amp;CK Mapping (already correlated by this platform)</p>
              <div className="flex flex-wrap gap-1.5">
                {report.mitreAttackMapping.map((t) => (
                  <Badge key={t.id} variant="muted" title={t.tactic ?? undefined}>
                    {t.id} — {t.name}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {report.confidenceTable.length > 0 && (
            <div>
              <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-muted">Confidence Assessment</p>
              <div className="overflow-x-auto">
                <table className="w-full min-w-[420px] border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-white/10 text-left text-muted">
                      <th className="py-1 pr-3 font-semibold">Assessment</th>
                      <th className="py-1 pr-3 font-semibold">Confidence</th>
                      <th className="py-1 font-semibold">Evidence</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.confidenceTable.map((row, i) => (
                      <tr key={i} className="border-b border-white/[0.05]">
                        <td className="py-1.5 pr-3 text-foreground">{row.claim}</td>
                        <td className="py-1.5 pr-3">
                          <ConfidenceBadge confidence={row.confidence} />
                        </td>
                        <td className="py-1.5 text-muted">{row.reasoning}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          <FieldList title="Intelligence Gaps (Unknown / Unconfirmed)" items={report.intelligenceGaps} />

          <div className="rounded-lg border border-primary/30 bg-primary/[0.06] p-2.5">
            <p className="mb-0.5 text-[11px] font-semibold uppercase tracking-wide text-primary">Recommended Next Pivot</p>
            <p className="text-xs text-foreground">{report.recommendedNextPivot}</p>
          </div>

          <div className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-2.5">
            <div className="mb-1 flex items-center gap-1.5">
              {(() => {
                const Icon = BLOCK_ICON[report.blockRecommendation] ?? ShieldQuestion;
                return <Icon className="h-3.5 w-3.5" />;
              })()}
              <span className="text-[11px] font-semibold uppercase tracking-wide text-muted">Containment</span>
              <Badge variant={BLOCK_VARIANT[report.blockRecommendation] ?? "muted"}>{report.blockRecommendation}</Badge>
            </div>
            <p className="text-xs text-foreground">{report.containmentRationale}</p>
          </div>

          <p className="text-[10px] text-muted">
            Generated by {report.provider} ({report.model}) at {new Date(report.generatedAt).toLocaleString()}.
          </p>
        </div>
      )}
    </div>
  );
}

export function AiInvestigationActionsPanel({ report }: { report: AiInvestigationReport | undefined }) {
  if (!report) {
    return (
      <Section title="Investigation Actions">
        <p className="text-xs text-muted">Generate an AI Report above to see specific, indicator-named actions for Threat Intelligence, Detection Engineering, and SOC investigation.</p>
      </Section>
    );
  }
  return (
    <Section title="Investigation Actions">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <div className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3">
          <p className="mb-1.5 text-xs font-semibold text-foreground">Threat Intelligence Analyst</p>
          <ul className="list-disc space-y-1 pl-4 text-xs text-muted">
            {report.threatIntelActions.map((a, i) => (
              <li key={i}>{a}</li>
            ))}
          </ul>
        </div>
        <div className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3">
          <p className="mb-1.5 text-xs font-semibold text-foreground">Detection Engineer</p>
          <ul className="list-disc space-y-1 pl-4 text-xs text-muted">
            {report.detectionEngineerActions.map((a, i) => (
              <li key={i}>{a}</li>
            ))}
          </ul>
        </div>
        <div className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3">
          <p className="mb-1.5 text-xs font-semibold text-foreground">SOC Analyst</p>
          <ul className="list-disc space-y-1 pl-4 text-xs text-muted">
            {report.socInvestigationActions.map((a, i) => (
              <li key={i}>{a}</li>
            ))}
          </ul>
        </div>
      </div>
    </Section>
  );
}
