import { ExternalLink, Flame, ShieldAlert, Skull, Target, TrendingUp, Wrench } from "lucide-react";
import { DetailDrawer, DrawerSection } from "./DetailDrawer";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState } from "./ErrorState";
import type { IndustryBriefing, IndustryBriefingArticleRef, IndustryName } from "@/types/threat-intel";

const LEVEL_VARIANT: Record<string, "critical" | "high" | "medium" | "low"> = {
  Critical: "critical",
  High: "high",
  Medium: "medium",
  Low: "low",
};

const TREND_LABEL: Record<string, string> = {
  Increasing: "▲ Increasing",
  Stable: "▬ Stable",
  Declining: "▼ Declining",
};

function timeAgo(iso: string) {
  const days = Math.floor((Date.now() - new Date(iso).getTime()) / (24 * 60 * 60 * 1000));
  if (days < 1) return "today";
  if (days === 1) return "1d ago";
  return `${days}d ago`;
}

function SourceLinks({ articles }: { articles: IndustryBriefingArticleRef[] }) {
  if (articles.length === 0) return null;
  return (
    <ul className="mt-1.5 space-y-1">
      {articles.map((a) => (
        <li key={a.id}>
          <a
            href={a.id}
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-1.5 text-[11px] text-muted transition-colors hover:text-foreground"
          >
            <ExternalLink className="h-3 w-3 shrink-0" />
            <span className="truncate">{a.title}</span>
            <span className="shrink-0">
              ({a.source} &middot; {timeAgo(a.publishedDate)})
            </span>
          </a>
        </li>
      ))}
    </ul>
  );
}

interface IndustryBriefingDrawerProps {
  industry: IndustryName | null;
  data: IndustryBriefing | undefined;
  isPending: boolean;
  error: Error | null;
  onClose: () => void;
}

/**
 * On-demand, strictly-grounded per-industry threat briefing -- reached by
 * clicking "Generate Full Briefing" on an Industry Heatmap row (see
 * IndustryHeatmap.tsx). Every named threat/actor/technique below links back
 * to the real articles that support it (see server/industryBriefing.js);
 * firstObserved/activeExploitation/trend and the vulnerability/reference
 * lists are computed from that real data, never model-authored.
 */
export function IndustryBriefingDrawer({ industry, data, isPending, error, onClose }: IndustryBriefingDrawerProps) {
  return (
    <DetailDrawer
      open={Boolean(industry)}
      onClose={onClose}
      title={industry ?? ""}
      subtitle={data ? `${data.articleCount} source articles · last ${data.dateRangeDays} days` : "Full Industry Briefing"}
    >
      {isPending ? (
        <div className="space-y-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-16 w-full" />
          ))}
        </div>
      ) : error ? (
        <ErrorState message={error.message} />
      ) : data ? (
        <>
          <p className="whitespace-pre-line text-sm leading-relaxed text-muted">{data.executiveSummary}</p>

          <DrawerSection title="Top Emerging Threats" icon={<Flame className="h-4 w-4" />}>
            {data.topEmergingThreats.length === 0 ? (
              <p className="text-xs text-muted">No distinct emerging threats stood out in the available coverage.</p>
            ) : (
              <div className="space-y-3">
                {data.topEmergingThreats.map((t) => (
                  <div key={t.name} className="rounded-lg border border-white/10 bg-white/[0.03] p-3 text-xs">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="font-semibold text-foreground">{t.name}</span>
                      <Badge variant={LEVEL_VARIANT[t.activityLevel] ?? "medium"}>{t.activityLevel}</Badge>
                      {t.activeExploitation && (
                        <Badge variant="critical" className="gap-1">
                          <ShieldAlert className="h-3 w-3" />
                          KEV
                        </Badge>
                      )}
                      <span className="text-muted">{TREND_LABEL[t.trend]}</span>
                      {t.firstObserved && <span className="text-muted">· first seen {new Date(t.firstObserved).toISOString().slice(0, 10)}</span>}
                    </div>
                    <p className="mt-1.5 text-muted">{t.whyEmerging}</p>
                    <SourceLinks articles={t.sourceArticles} />
                  </div>
                ))}
              </div>
            )}
          </DrawerSection>

          <DrawerSection title="Active Threat Actors" icon={<Skull className="h-4 w-4" />}>
            {data.activeThreatActors.length === 0 ? (
              <p className="text-xs text-muted">No specific actor was named in the available coverage for this sector.</p>
            ) : (
              <div className="space-y-3">
                {data.activeThreatActors.map((a) => (
                  <div key={a.actor} className="rounded-lg border border-white/10 bg-white/[0.03] p-3 text-xs">
                    <span className="font-semibold text-foreground">{a.actor}</span>
                    <dl className="mt-1.5 space-y-1 text-muted">
                      <div>
                        <dt className="inline font-medium text-foreground">Motivation: </dt>
                        <dd className="inline">{a.motivation}</dd>
                      </div>
                      <div>
                        <dt className="inline font-medium text-foreground">Typical targets: </dt>
                        <dd className="inline">{a.typicalTargets}</dd>
                      </div>
                      <div>
                        <dt className="inline font-medium text-foreground">Recent campaigns: </dt>
                        <dd className="inline">{a.recentCampaigns}</dd>
                      </div>
                      <div>
                        <dt className="inline font-medium text-foreground">TTPs: </dt>
                        <dd className="inline">{a.ttps}</dd>
                      </div>
                    </dl>
                    <SourceLinks articles={a.sourceArticles} />
                  </div>
                ))}
              </div>
            )}
          </DrawerSection>

          <DrawerSection title="Emerging Attack Techniques" icon={<Wrench className="h-4 w-4" />}>
            {data.emergingAttackTechniques.length === 0 ? (
              <p className="text-xs text-muted">No specific technique trend stood out in the available coverage.</p>
            ) : (
              <div className="space-y-3">
                {data.emergingAttackTechniques.map((t) => (
                  <div key={t.technique} className="rounded-lg border border-white/10 bg-white/[0.03] p-3 text-xs">
                    <span className="font-semibold text-foreground">{t.technique}</span>
                    <p className="mt-1 text-muted">{t.whyIncreasing}</p>
                    <SourceLinks articles={t.sourceArticles} />
                  </div>
                ))}
              </div>
            )}
          </DrawerSection>

          <DrawerSection title="Common Targets" icon={<Target className="h-4 w-4" />}>
            {data.commonTargets.length === 0 ? (
              <p className="text-xs text-muted">Not enough coverage to identify commonly targeted assets.</p>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {data.commonTargets.map((t) => (
                  <Badge key={t} variant="medium">
                    {t}
                  </Badge>
                ))}
              </div>
            )}
          </DrawerSection>

          <DrawerSection title="Vulnerability Trends" icon={<ShieldAlert className="h-4 w-4" />}>
            <p className="text-xs text-muted">{data.vulnerabilityTrends.commentary}</p>
            <p className="mt-1.5 text-xs text-muted">
              {data.vulnerabilityTrends.totalUniqueCves} unique CVE{data.vulnerabilityTrends.totalUniqueCves === 1 ? "" : "s"} in this sector's coverage
              {data.vulnerabilityTrends.kevEntries.length > 0 && `, ${data.vulnerabilityTrends.kevEntries.length} actively exploited (KEV)`}.
            </p>
            {data.vulnerabilityTrends.kevEntries.length > 0 && (
              <ul className="mt-1.5 space-y-1">
                {data.vulnerabilityTrends.kevEntries.map((k) => (
                  <li key={k.cveId} className="text-[11px]">
                    <a href={k.articleId} target="_blank" rel="noreferrer" className="text-muted transition-colors hover:text-foreground">
                      <Badge variant="critical">{k.cveId}</Badge> <span className="ml-1">{k.articleTitle}</span>
                    </a>
                  </li>
                ))}
              </ul>
            )}
          </DrawerSection>

          <DrawerSection title="Industry Risk Assessment" icon={<TrendingUp className="h-4 w-4" />}>
            <div className="mb-2 flex items-center gap-1.5">
              <span className="text-xs font-medium text-foreground">Current threat level:</span>
              <Badge variant={LEVEL_VARIANT[data.industryRiskAssessment.currentThreatLevel] ?? "medium"}>{data.industryRiskAssessment.currentThreatLevel}</Badge>
            </div>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              <div>
                <p className="mb-1 text-xs font-semibold text-foreground">Likely Attack Scenarios</p>
                <ul className="list-disc space-y-0.5 pl-4 text-xs text-muted">
                  {data.industryRiskAssessment.mostLikelyAttackScenarios.map((x, i) => (
                    <li key={i}>{x}</li>
                  ))}
                </ul>
              </div>
              <div>
                <p className="mb-1 text-xs font-semibold text-foreground">Highest Business Risks</p>
                <ul className="list-disc space-y-0.5 pl-4 text-xs text-muted">
                  {data.industryRiskAssessment.highestBusinessRisks.map((x, i) => (
                    <li key={i}>{x}</li>
                  ))}
                </ul>
              </div>
              <div>
                <p className="mb-1 text-xs font-semibold text-foreground">Technologies Requiring Attention</p>
                <ul className="list-disc space-y-0.5 pl-4 text-xs text-muted">
                  {data.industryRiskAssessment.technologiesRequiringAttention.map((x, i) => (
                    <li key={i}>{x}</li>
                  ))}
                </ul>
              </div>
            </div>
          </DrawerSection>

          <DrawerSection title="Recommended Defensive Priorities" icon={<ShieldAlert className="h-4 w-4" />}>
            <ol className="list-decimal space-y-1 pl-4 text-xs text-muted">
              {data.recommendedDefensivePriorities.map((x, i) => (
                <li key={i}>{x}</li>
              ))}
            </ol>
          </DrawerSection>

          <DrawerSection title="Threat Intel Outlook (60-90 days)" icon={<TrendingUp className="h-4 w-4" />}>
            <p className="whitespace-pre-line text-xs text-muted">{data.threatIntelOutlook}</p>
          </DrawerSection>

          <DrawerSection title={`References (${data.references.length})`} icon={<ExternalLink className="h-4 w-4" />}>
            <SourceLinks articles={data.references} />
          </DrawerSection>
        </>
      ) : null}
    </DetailDrawer>
  );
}
