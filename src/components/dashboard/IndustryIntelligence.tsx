// Enterprise "pick a sector, see everything this platform knows about it"
// page -- built entirely on top of server/industryBriefing.js (on-demand,
// strictly-grounded per-industry synthesis) plus useEmergingThreatsRanking's
// own aggregate heatmap for the at-a-glance risk score. No new AI call beyond
// the one Groq generation useIndustryBriefing already makes per industry --
// the six richer sections (campaigns, CVEs, IOC feed, reports, detection,
// hunting) are all deterministic derivations already computed server-side.
import { useMemo, useState, type ReactNode } from "react";
import {
  Activity,
  Bug,
  Crosshair,
  Download,
  ExternalLink,
  Flame,
  Radar,
  ShieldAlert,
  Skull,
  Sparkles,
  Target,
  TrendingUp,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "./ErrorState";
import { INDUSTRY_EMOJI } from "./IndustryHeatmap";
import { RankedBarChart, type ChartDatum } from "./RankedBarChart";
import { useIndustryBriefing } from "@/hooks/useIndustryBriefing";
import { useEmergingThreatsRanking } from "@/hooks/useEmergingThreatsRanking";
import { downloadIocFeedAsCsv, downloadIocFeedAsJson } from "@/lib/iocExport";
import type {
  IndustryBriefingReport,
  IndustryDetectionOpportunity,
  IndustryName,
} from "@/types/threat-intel";

const INDUSTRIES = Object.keys(INDUSTRY_EMOJI) as IndustryName[];

const LEVEL_VARIANT: Record<string, "critical" | "high" | "medium" | "low"> = {
  Critical: "critical",
  High: "high",
  Medium: "medium",
  Low: "low",
};

const DETECTION_PLATFORM_LABEL: Record<string, string> = {
  sentinelKql: "Microsoft Sentinel (KQL)",
  splunkSpl: "Splunk (SPL)",
  elastic: "Elastic",
  sigma: "Sigma",
  yara: "YARA",
};

function dateOnly(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toISOString().slice(0, 10);
}

function SectionCard({
  title,
  icon,
  description,
  action,
  children,
}: {
  title: string;
  icon: ReactNode;
  description?: string;
  action?: ReactNode;
  children: ReactNode;
}) {
  return (
    <Card>
      <CardHeader className="items-start">
        <div>
          <CardTitle className="flex items-center gap-1.5 text-base font-semibold text-foreground">
            <span className="text-primary">{icon}</span>
            {title}
          </CardTitle>
          {description && <p className="mt-1 text-xs text-muted">{description}</p>}
        </div>
        {action}
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}

function RecentReportRow({ report }: { report: IndustryBriefingReport }) {
  return (
    <a
      href={report.articleLink}
      target="_blank"
      rel="noreferrer"
      className="flex items-center gap-3 rounded-lg border border-white/[0.06] bg-white/[0.02] px-3 py-2.5 transition-colors hover:border-white/20"
    >
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="truncate text-sm font-semibold text-foreground">{report.articleTitle}</span>
          <Badge variant={LEVEL_VARIANT[report.severity] ?? "medium"}>{report.severity}</Badge>
          {report.campaignName && <Badge variant="cyan">{report.campaignName}</Badge>}
        </div>
        <div className="mt-0.5 flex flex-wrap items-center gap-1.5 text-xs text-muted">
          <span>{report.articleSource}</span>
          <span>&middot;</span>
          <span>{dateOnly(report.publishedDate)}</span>
          {report.threatActors.length > 0 && (
            <>
              <span>&middot;</span>
              <span>{report.threatActors.join(", ")}</span>
            </>
          )}
        </div>
        {report.executiveSummary && <p className="mt-1 line-clamp-2 text-xs text-muted">{report.executiveSummary}</p>}
      </div>
      <ExternalLink className="h-3.5 w-3.5 shrink-0 text-muted" />
    </a>
  );
}

function DetectionQueryCard({ item }: { item: IndustryDetectionOpportunity }) {
  return (
    <div className="rounded-lg border border-white/10 bg-white/[0.03] p-3 text-xs">
      <div className="flex flex-wrap items-center gap-1.5">
        {item.malware.map((m) => (
          <span key={m} className="font-semibold text-foreground">
            {m}
          </span>
        ))}
        {item.threatActors.map((a) => (
          <Badge key={a} variant="muted">
            {a}
          </Badge>
        ))}
        <a href={item.sourceUrl} target="_blank" rel="noreferrer" className="ml-auto flex items-center gap-1 text-muted hover:text-foreground">
          {item.source}
          <ExternalLink className="h-3 w-3" />
        </a>
      </div>
      <pre className="mt-2 max-h-32 overflow-y-auto whitespace-pre-wrap rounded-lg border border-white/10 bg-black/20 p-2 font-mono text-[11px] text-foreground/90">{item.query}</pre>
    </div>
  );
}

/**
 * "Industry Intelligence" -- select one of 14 sectors, see every real signal
 * this platform has correlated for it: executive summary, active
 * actors/campaigns/malware, CVSS/EPSS/KEV-enriched critical CVEs, an
 * exportable IOC feed, ATT&CK profile, recent reports, detection/hunting
 * guidance, and an AI-generated risk assessment. Nothing here is
 * placeholder data -- every section either comes straight from a real
 * entity/CVE/cache record or (executive summary, risk assessment) from the
 * same strictly-cited Groq generation server/industryBriefing.js already
 * produces for the Emerging Threats heatmap drawer, just rendered as its own
 * full page instead of a slide-over.
 */
export function IndustryIntelligence() {
  const [selected, setSelected] = useState<IndustryName | null>(null);
  const briefing = useIndustryBriefing();
  const ranking = useEmergingThreatsRanking();

  const heatmapRow = useMemo(
    () => ranking.data?.industryHeatmap.find((r) => r.industry === selected) ?? null,
    [ranking.data, selected],
  );

  function selectIndustry(industry: IndustryName) {
    setSelected(industry);
    briefing.mutate(industry);
  }

  const data = briefing.data;

  const actorChartData: ChartDatum[] = useMemo(
    () =>
      (data?.activeThreatActors ?? [])
        .slice()
        .sort((a, b) => b.reportCount - a.reportCount)
        .slice(0, 10)
        .map((a) => ({ name: a.actor, count: a.reportCount, detail: `${a.confidence} confidence${a.country ? ` · ${a.country}` : ""}` })),
    [data],
  );

  const malwareChartData: ChartDatum[] = useMemo(
    () =>
      (data?.malwareFamilies ?? [])
        .slice()
        .sort((a, b) => b.sourceArticles.length - a.sourceArticles.length)
        .slice(0, 10)
        .map((m) => ({ name: m.name, count: m.sourceArticles.length, detail: `${m.type} · ${m.severity}` })),
    [data],
  );

  const campaignChartData: ChartDatum[] = useMemo(
    () =>
      (data?.activeCampaigns ?? [])
        .slice()
        .sort((a, b) => b.mentionCount - a.mentionCount)
        .slice(0, 10)
        .map((c) => ({ name: c.name, count: c.mentionCount, detail: c.associatedActors.join(", ") || "Unattributed" })),
    [data],
  );

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex-col items-start">
          <CardTitle className="flex items-center gap-1.5 text-base font-semibold text-foreground">
            <Radar className="h-4 w-4 text-primary" />
            Industry Intelligence
          </CardTitle>
          <p className="mt-1 text-xs text-muted">
            Select a sector to see every threat actor, campaign, malware family, CVE, IOC, and ATT&amp;CK technique this platform has correlated against it --
            plus an AI-generated risk assessment and 30-day defensive priorities. Built from real ingested reports, never placeholder data.
          </p>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-2">
            {INDUSTRIES.map((industry) => {
              const row = ranking.data?.industryHeatmap.find((r) => r.industry === industry);
              const isActive = selected === industry;
              return (
                <button
                  key={industry}
                  type="button"
                  onClick={() => selectIndustry(industry)}
                  className={`flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-semibold transition-colors ${
                    isActive ? "border-primary/50 bg-primary/15 text-[#b8adff]" : "border-white/10 bg-white/[0.03] text-muted hover:border-white/20 hover:text-foreground"
                  }`}
                >
                  <span aria-hidden="true">{INDUSTRY_EMOJI[industry]}</span>
                  {industry}
                  {row && row.activeThreatCount > 0 && (
                    <Badge variant={LEVEL_VARIANT[row.relevance] ?? "muted"} className="ml-0.5">
                      {row.activeThreatCount}
                    </Badge>
                  )}
                </button>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {!selected ? (
        <Card>
          <CardContent>
            <EmptyState message="Select a sector above to generate its intelligence briefing." />
          </CardContent>
        </Card>
      ) : briefing.isPending ? (
        <Card>
          <CardContent>
            <div className="space-y-3">
              {Array.from({ length: 6 }).map((_, i) => (
                <Skeleton key={i} className="h-16 w-full" />
              ))}
            </div>
          </CardContent>
        </Card>
      ) : briefing.isError || !data ? (
        <Card>
          <CardContent>
            <ErrorState message={(briefing.error as Error)?.message ?? "Could not generate an intelligence briefing for this sector right now."} />
          </CardContent>
        </Card>
      ) : (
        <>
          <Card>
            <CardContent>
              <div className="flex flex-wrap items-center gap-4">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-medium text-muted">Threat level</span>
                  <Badge variant={LEVEL_VARIANT[data.industryRiskAssessment.currentThreatLevel] ?? "medium"}>{data.industryRiskAssessment.currentThreatLevel}</Badge>
                </div>
                {heatmapRow && (
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-medium text-muted">Risk score</span>
                    <span className="font-mono text-sm font-semibold tabular-nums text-foreground">{heatmapRow.riskScore}/10</span>
                    <Badge variant="muted">{heatmapRow.priority} priority</Badge>
                  </div>
                )}
                <div className="flex items-center gap-2 text-xs text-muted">
                  <Activity className="h-3.5 w-3.5" />
                  {data.articleCount} source articles &middot; last {data.dateRangeDays} days
                </div>
              </div>
              <p className="mt-3 whitespace-pre-line text-sm leading-relaxed text-foreground">{data.executiveSummary}</p>
            </CardContent>
          </Card>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <SectionCard title="Most Active Threat Actors" icon={<Skull className="h-4 w-4" />}>
              {actorChartData.length === 0 ? (
                <EmptyState message="No specific actor named in the available coverage for this sector." />
              ) : (
                <RankedBarChart data={actorChartData} hue="#f43f5e" />
              )}
            </SectionCard>
            <SectionCard title="Active Campaigns" icon={<Flame className="h-4 w-4" />}>
              {campaignChartData.length === 0 ? (
                <EmptyState message="No campaign entity currently ties to this sector." />
              ) : (
                <RankedBarChart data={campaignChartData} hue="#f59e0b" />
              )}
            </SectionCard>
            <SectionCard title="Trending Malware Families" icon={<Bug className="h-4 w-4" />}>
              {malwareChartData.length === 0 ? (
                <EmptyState message="No specific malware family named in the available coverage." />
              ) : (
                <RankedBarChart data={malwareChartData} hue="#22d3ee" />
              )}
            </SectionCard>
          </div>

          <SectionCard title="Critical CVEs" icon={<ShieldAlert className="h-4 w-4" />} description="CVSS/EPSS/KEV cross-referenced from the live vulnerability caches -- never model-authored.">
            {data.criticalCves.length === 0 ? (
              <EmptyState message="No CVE appeared in this sector's current coverage." />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[640px] border-collapse text-sm">
                  <thead>
                    <tr className="border-b border-white/10 text-left text-xs uppercase tracking-wide text-muted">
                      <th className="py-2 pr-3">CVE</th>
                      <th className="py-2 pr-3">CVSS</th>
                      <th className="py-2 pr-3">EPSS</th>
                      <th className="py-2 pr-3">KEV</th>
                      <th className="py-2">Description</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.criticalCves.map((cve) => (
                      <tr key={cve.cveId} className="border-b border-white/[0.05]">
                        <td className="py-2 pr-3 font-mono font-semibold text-foreground">{cve.cveId}</td>
                        <td className="py-2 pr-3 tabular-nums text-foreground">{cve.cvssScore ?? "—"}</td>
                        <td className="py-2 pr-3 tabular-nums text-foreground">{cve.epssScore != null ? `${(cve.epssScore * 100).toFixed(1)}%` : "—"}</td>
                        <td className="py-2 pr-3">
                          {cve.knownExploited ? (
                            <Badge variant="critical" className="gap-1">
                              <ShieldAlert className="h-3 w-3" />
                              KEV
                            </Badge>
                          ) : (
                            <span className="text-muted">—</span>
                          )}
                        </td>
                        <td className="py-2 text-muted">{cve.description ?? "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </SectionCard>

          <SectionCard
            title={`Industry IOC Feed (${data.industryIocFeed.totalCount})`}
            icon={<Crosshair className="h-4 w-4" />}
            description="IPs, domains, URLs, hashes, and email addresses tied to attacks against this sector's malware families -- export to operationalize."
            action={
              data.industryIocFeed.indicators.length > 0 && (
                <div className="flex shrink-0 gap-1.5">
                  <button
                    type="button"
                    onClick={() => downloadIocFeedAsCsv(selected, data.industryIocFeed)}
                    className="flex items-center gap-1.5 rounded-lg border border-white/10 bg-white/[0.03] px-2.5 py-1.5 text-xs font-semibold text-foreground transition-colors hover:border-white/20"
                  >
                    <Download className="h-3.5 w-3.5" />
                    CSV
                  </button>
                  <button
                    type="button"
                    onClick={() => downloadIocFeedAsJson(selected, data.industryIocFeed)}
                    className="flex items-center gap-1.5 rounded-lg border border-white/10 bg-white/[0.03] px-2.5 py-1.5 text-xs font-semibold text-foreground transition-colors hover:border-white/20"
                  >
                    <Download className="h-3.5 w-3.5" />
                    JSON
                  </button>
                </div>
              )
            }
          >
            {data.industryIocFeed.indicators.length === 0 ? (
              <EmptyState message="No IOC currently traces to this sector's malware families." />
            ) : (
              <div className="max-h-96 overflow-auto">
                <table className="w-full min-w-[560px] border-collapse text-sm">
                  <thead className="sticky top-0 bg-surface">
                    <tr className="border-b border-white/10 text-left text-xs uppercase tracking-wide text-muted">
                      <th className="py-2 pr-3">Indicator</th>
                      <th className="py-2 pr-3">Type</th>
                      <th className="py-2 pr-3">Malware Family</th>
                      <th className="py-2">First Seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.industryIocFeed.indicators.map((ioc, i) => (
                      <tr key={`${ioc.indicatorType}:${ioc.indicator}:${i}`} className="border-b border-white/[0.05]">
                        <td className="py-1.5 pr-3 font-mono text-xs text-foreground">{ioc.indicator}</td>
                        <td className="py-1.5 pr-3">
                          <Badge variant="muted">{ioc.indicatorType}</Badge>
                        </td>
                        <td className="py-1.5 pr-3 text-muted">{ioc.malwareFamily ?? "—"}</td>
                        <td className="py-1.5 text-muted">{dateOnly(ioc.firstSeen)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </SectionCard>

          <SectionCard title="MITRE ATT&CK Profile" icon={<Target className="h-4 w-4" />}>
            {data.tacticsSummary.length > 0 && (
              <div className="mb-3 flex flex-wrap gap-1.5">
                {data.tacticsSummary.map((s) => (
                  <Badge key={s.tactic} variant="muted">
                    {s.tactic} <span className="ml-1 tabular-nums text-foreground">{s.techniqueCount}</span>
                  </Badge>
                ))}
              </div>
            )}
            {data.topAttackTechniques.length === 0 ? (
              <EmptyState message="No specific ATT&CK technique could be grounded against this sector's coverage." />
            ) : (
              <div className="space-y-2.5">
                {data.topAttackTechniques.map((t, i) => (
                  <div key={t.techniqueId ?? `${t.techniqueName}-${i}`} className="rounded-lg border border-white/10 bg-white/[0.03] p-3 text-xs">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="font-semibold text-foreground">{t.techniqueName}</span>
                      {t.techniqueId && <span className="font-mono text-muted">{t.techniqueId}</span>}
                      {t.tactic && (
                        <Badge variant="muted" className="normal-case">
                          {t.tactic}
                        </Badge>
                      )}
                      <Badge variant={LEVEL_VARIANT[t.detectionPriority] ?? "medium"}>{t.detectionPriority} priority</Badge>
                    </div>
                    <p className="mt-1.5 text-muted">{t.whyUsed}</p>
                  </div>
                ))}
              </div>
            )}
          </SectionCard>

          <SectionCard title={`Recent Intelligence Reports (${data.recentReports.length})`} icon={<Activity className="h-4 w-4" />}>
            {data.recentReports.length === 0 ? (
              <EmptyState message="No stored AI Summarization report is currently backing this sector's coverage." />
            ) : (
              <div className="space-y-2">
                {data.recentReports.map((r) => (
                  <RecentReportRow key={r.id} report={r} />
                ))}
              </div>
            )}
          </SectionCard>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <SectionCard title="Detection Opportunities" icon={<ShieldAlert className="h-4 w-4" />} description="Real Sentinel/Splunk/Elastic/Sigma/YARA queries built from this sector's own malware IOCs.">
              {Object.values(data.detectionOpportunities).every((arr) => arr.length === 0) ? (
                <EmptyState message="No detection query could be built from this sector's malware entities yet." />
              ) : (
                <div className="space-y-4">
                  {(Object.entries(data.detectionOpportunities) as [string, IndustryDetectionOpportunity[]][])
                    .filter(([, items]) => items.length > 0)
                    .map(([platform, items]) => (
                      <div key={platform}>
                        <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">{DETECTION_PLATFORM_LABEL[platform] ?? platform}</p>
                        <div className="space-y-2">
                          {items.map((item, i) => (
                            <DetectionQueryCard key={i} item={item} />
                          ))}
                        </div>
                      </div>
                    ))}
                </div>
              )}
            </SectionCard>

            <SectionCard title="Threat Hunting Opportunities" icon={<Radar className="h-4 w-4" />} description="Hunting hypotheses tailored to this sector's active malware and actors.">
              {data.huntingOpportunities.length === 0 ? (
                <EmptyState message="No hunting query could be built from this sector's malware/actor entities yet." />
              ) : (
                <div className="space-y-2">
                  {data.huntingOpportunities.map((item, i) => (
                    <DetectionQueryCard key={i} item={item} />
                  ))}
                </div>
              )}
            </SectionCard>
          </div>

          <SectionCard title="AI Industry Risk Assessment" icon={<Sparkles className="h-4 w-4" />}>
            <div className="space-y-4">
              <div>
                <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">Why This Sector Is Currently Targeted</p>
                <p className="text-sm text-foreground">{data.industryRiskAssessment.whyTargeted}</p>
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
              <div className="rounded-xl border border-primary/20 bg-primary/[0.04] p-3">
                <p className="mb-1.5 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-primary">
                  <TrendingUp className="h-3.5 w-3.5" /> Prioritize Over the Next 30 Days
                </p>
                <ol className="list-decimal space-y-1 pl-4 text-sm text-foreground">
                  {data.recommendedDefensivePriorities.map((x, i) => (
                    <li key={i}>{x}</li>
                  ))}
                </ol>
              </div>
              <div>
                <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">Threat Intel Outlook (60-90 days)</p>
                <p className="whitespace-pre-line text-xs text-muted">{data.threatIntelOutlook}</p>
              </div>
              <Badge variant="muted">AI-generated briefing &middot; {data.references.length} source articles cited</Badge>
            </div>
          </SectionCard>
        </>
      )}
    </div>
  );
}
