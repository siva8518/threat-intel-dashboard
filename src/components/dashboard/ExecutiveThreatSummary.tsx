import { useEffect, useRef, useState } from "react";
import { animate } from "framer-motion";
import { motion } from "framer-motion";
import { AlertTriangle, Bug, Flame, Globe2, ShieldAlert, Skull, TrendingUp } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState } from "./ErrorState";
import { TopSecurityEventsToday, type TodayEventKey } from "./TopSecurityEventsToday";
import { useExecutiveSummary } from "@/hooks/useExecutiveSummary";
import { useSelection } from "@/context/SelectionContext";
import { fetchCveById } from "@/api/dashboardApi";
import type { ThreatLevel } from "@/types/threat-intel";
import { cn } from "@/lib/utils";

const LEVEL_STYLE: Record<ThreatLevel, { text: string; ring: string; glow: string; badge: "low" | "medium" | "high" | "critical" }> = {
  Low: { text: "text-low", ring: "#2fd97c", glow: "shadow-[0_0_40px_-8px_rgba(47,217,124,0.5)]", badge: "low" },
  Elevated: { text: "text-medium", ring: "#f2c94c", glow: "shadow-[0_0_40px_-8px_rgba(242,201,76,0.5)]", badge: "medium" },
  High: { text: "text-high", ring: "#f7913d", glow: "shadow-[0_0_40px_-8px_rgba(247,145,61,0.5)]", badge: "high" },
  Critical: { text: "text-critical", ring: "#fb3f5e", glow: "shadow-[0_0_40px_-8px_rgba(251,63,94,0.6)]", badge: "critical" },
};

function useCountUp(value: number) {
  const [display, setDisplay] = useState(value);
  const prev = useRef(value);

  useEffect(() => {
    const controls = animate(prev.current, value, {
      duration: 0.8,
      ease: [0.16, 1, 0.3, 1],
      onUpdate: (v) => setDisplay(v),
    });
    prev.current = value;
    return () => controls.stop();
  }, [value]);

  return display;
}

function ScoreGauge({ score, level }: { score: number; level: ThreatLevel }) {
  const animatedScore = useCountUp(score);
  const style = LEVEL_STYLE[level];
  const radius = 50;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference * (1 - animatedScore / 100);

  return (
    <div className={cn("relative flex h-28 w-28 shrink-0 items-center justify-center rounded-full", style.glow)}>
      <svg viewBox="0 0 120 120" className="h-full w-full -rotate-90">
        <circle cx="60" cy="60" r={radius} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="10" />
        <circle
          cx="60"
          cy="60"
          r={radius}
          fill="none"
          stroke={style.ring}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: "stroke 0.4s ease" }}
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className="text-3xl font-bold tabular-nums">{Math.round(animatedScore)}</span>
        <span className="text-[10px] uppercase tracking-wider text-muted">/ 100</span>
      </div>
    </div>
  );
}

interface FactCardProps {
  icon: React.ReactNode;
  label: string;
  onClick?: () => void;
  loading?: boolean;
  title?: string;
  children: React.ReactNode;
}

function FactCard({ icon, label, onClick, loading, title, children }: FactCardProps) {
  // A plain div, not a <button> -- "Industries Targeted"/"Countries Under
  // Attack" nest their own per-item <button>s inside this (see below), and
  // a <button> can't validly contain another <button>. Confirmed live: with
  // this as a <button>, the browser's HTML parser breaks the nested
  // buttons' clicks entirely (React's validateDOMNesting warning matched
  // exactly this component). role="button" + keyboard handling keeps it
  // accessible for the FactCards that click as a single unit.
  const clickable = Boolean(onClick) && !loading;
  return (
    <div
      role={onClick ? "button" : undefined}
      tabIndex={clickable ? 0 : undefined}
      onClick={clickable ? onClick : undefined}
      title={title}
      onKeyDown={
        clickable
          ? (e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                onClick!();
              }
            }
          : undefined
      }
      className={cn(
        "flex w-full flex-col gap-1 rounded-xl border border-white/[0.06] bg-white/[0.02] p-3 text-left transition-all duration-200",
        clickable && "cursor-pointer hover:-translate-y-0.5 hover:border-primary/30 hover:bg-white/[0.05]",
      )}
    >
      <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted">
        {icon}
        {label}
      </div>
      {loading ? <Skeleton className="h-5 w-2/3" /> : <div className="text-sm font-medium text-foreground">{children}</div>}
    </div>
  );
}

interface ExecutiveThreatSummaryProps {
  onNavigateToActors: () => void;
  onNavigateToCampaigns: () => void;
  onNavigateToCountry: (countryCode: string) => void;
  onNavigateToIndustry: (industry: string) => void;
  onNavigateTodayEvent: (key: TodayEventKey) => void;
}

export function ExecutiveThreatSummary({
  onNavigateToActors,
  onNavigateToCampaigns,
  onNavigateToCountry,
  onNavigateToIndustry,
  onNavigateTodayEvent,
}: ExecutiveThreatSummaryProps) {
  const { data, isLoading, isError, error } = useExecutiveSummary();
  const { selectMalware, selectCve } = useSelection();
  const [loadingCve, setLoadingCve] = useState(false);

  async function openMostExploitedCve() {
    if (!data?.mostExploitedCve) return;
    setLoadingCve(true);
    try {
      const record = await fetchCveById(data.mostExploitedCve.cveId);
      selectCve(record);
    } catch {
      // best-effort -- if the live NVD lookup fails, just don't open the drawer
    } finally {
      setLoadingCve(false);
    }
  }

  if (isLoading) {
    return (
      <Card>
        <CardContent className="flex flex-col items-center gap-5 p-5 md:flex-row">
          <Skeleton className="h-28 w-28 shrink-0 rounded-full" />
          <div className="grid w-full flex-1 grid-cols-2 gap-2.5 md:grid-cols-3">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-16 w-full" />
            ))}
          </div>
        </CardContent>
      </Card>
    );
  }

  if (isError || !data) {
    return (
      <Card>
        <CardContent>
          <ErrorState message={(error as Error)?.message ?? "Executive Threat Summary is unavailable right now."} />
        </CardContent>
      </Card>
    );
  }

  const style = LEVEL_STYLE[data.level];

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
      <Card className="overflow-visible">
        <CardContent className="p-5">
          <div className="flex flex-col items-center gap-5 lg:flex-row lg:items-start">
            <div className="flex flex-col items-center gap-1.5">
              <ScoreGauge score={data.score} level={data.level} />
              <Badge variant={style.badge} className="text-sm">
                {data.level} Threat Level
              </Badge>
              <span className="text-[11px] text-muted">
                Updated {new Date(data.generatedAt).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}
              </span>
            </div>

            <div className="grid w-full flex-1 grid-cols-1 gap-2.5 sm:grid-cols-2 lg:grid-cols-3">
              <FactCard icon={<Skull className="h-3.5 w-3.5" />} label="Most Active Threat Actor" onClick={onNavigateToActors}>
                {data.mostActiveActor ? (
                  <>
                    {data.mostActiveActor.name}{" "}
                    <span className="font-normal text-muted">({data.mostActiveActor.campaignCount} campaigns)</span>
                  </>
                ) : (
                  <span className="text-muted">No active actor identified</span>
                )}
              </FactCard>

              <FactCard
                icon={<Bug className="h-3.5 w-3.5" />}
                label="Most Active Malware Family"
                onClick={data.mostActiveMalware ? () => selectMalware(data.mostActiveMalware!) : undefined}
              >
                {data.mostActiveMalware ? (
                  <>
                    {data.mostActiveMalware.family}{" "}
                    <span className="font-normal text-muted">({data.mostActiveMalware.count} sightings)</span>
                  </>
                ) : (
                  <span className="text-muted">No trending family identified</span>
                )}
              </FactCard>

              <FactCard
                icon={<ShieldAlert className="h-3.5 w-3.5" />}
                label="Most Exploited CVE"
                onClick={data.mostExploitedCve ? openMostExploitedCve : undefined}
                loading={loadingCve}
              >
                {data.mostExploitedCve ? (
                  <span className="flex items-center gap-1.5 font-mono">
                    {data.mostExploitedCve.cveId}
                    {data.mostExploitedCve.knownExploited && <Badge variant="danger">KEV</Badge>}
                  </span>
                ) : (
                  <span className="text-muted">None identified</span>
                )}
              </FactCard>

              <FactCard
                icon={<Flame className="h-3.5 w-3.5" />}
                label="Total Active Campaigns"
                onClick={onNavigateToCampaigns}
                title="Ransomware victim disclosures (ransomware.live, RansomWatch & RansomLook) + named MITRE ATT&CK threat-actor campaigns + OTX adversary-tagged pulses + named campaigns identified from security-news-vendor coverage -- click to view Campaign Intelligence"
              >
                <AnimatedCount value={data.totalActiveCampaigns} />
                <div className="mt-0.5 text-xs font-normal text-muted">
                  {data.campaignsBreakdown.ransomware} ransomware · {data.campaignsBreakdown.attackCampaigns} ATT&amp;CK ·{" "}
                  {data.campaignsBreakdown.otxPulses} OTX · {data.campaignsBreakdown.newsVendors} news-vendor
                </div>
              </FactCard>

              <FactCard icon={<TrendingUp className="h-3.5 w-3.5" />} label="Industries Targeted">
                <div className="flex flex-wrap gap-1">
                  {data.industriesTargeted.slice(0, 4).map((i) => (
                    <button
                      key={i.industry}
                      onClick={(e) => {
                        e.stopPropagation();
                        onNavigateToIndustry(i.industry);
                      }}
                      title={`View ${i.industry} campaigns`}
                      className="rounded-full border border-white/10 bg-white/[0.03] px-2 py-0.5 text-xs transition-colors hover:border-primary/40"
                    >
                      {i.industry} <span className="text-muted">({i.count})</span>
                    </button>
                  ))}
                </div>
              </FactCard>

              <FactCard icon={<Globe2 className="h-3.5 w-3.5" />} label="Countries Under Attack">
                <div className="flex flex-wrap gap-1">
                  {data.countriesUnderAttack.slice(0, 4).map((c) => (
                    <button
                      key={c.countryCode}
                      onClick={(e) => {
                        e.stopPropagation();
                        onNavigateToCountry(c.countryCode);
                      }}
                      className="rounded-full border border-white/10 bg-white/[0.03] px-2 py-0.5 text-xs transition-colors hover:border-primary/40"
                    >
                      {c.countryCode} <span className="text-muted">({c.count})</span>
                    </button>
                  ))}
                </div>
              </FactCard>
            </div>
          </div>

          <div className="mt-4 border-t border-white/[0.06] pt-4">
            <TopSecurityEventsToday onNavigate={onNavigateTodayEvent} />
          </div>

          <details className="mt-4 border-t border-white/[0.06] pt-3 text-xs text-muted">
            <summary className="flex w-fit cursor-pointer items-center gap-1.5 select-none hover:text-foreground">
              <AlertTriangle className="h-3.5 w-3.5" />
              How is this score calculated?
            </summary>
            <div className="mt-2 space-y-1">
              <p>
                A transparent weighted heuristic across five live signals -- not an industry-standard metric.
                Every input is the same data shown elsewhere in this dashboard.
              </p>
              <ul className="grid grid-cols-1 gap-x-4 gap-y-0.5 sm:grid-cols-2">
                {data.breakdown.map((b) => (
                  <li key={b.signal} className="flex items-center justify-between gap-2">
                    <span className="capitalize">{b.signal.replace(/([A-Z])/g, " $1")}</span>
                    <span className="font-mono">
                      {Math.round(b.normalized * 100)}% × {Math.round(b.weight * 100)}w = {b.contribution.toFixed(1)}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          </details>
        </CardContent>
      </Card>
    </motion.div>
  );
}

function AnimatedCount({ value }: { value: number }) {
  const animated = useCountUp(value);
  return <span className="text-lg font-semibold tabular-nums">{Math.round(animated)}</span>;
}
