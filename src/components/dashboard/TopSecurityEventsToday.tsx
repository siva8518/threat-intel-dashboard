import { useEffect, useRef, useState } from "react";
import { animate } from "framer-motion";
import { Bug, Flame, Github, Link2, ShieldAlert, Skull } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState } from "./ErrorState";
import { useTodaySecurityEvents } from "@/hooks/useTodaySecurityEvents";
import type { TodaySecurityEvents } from "@/types/threat-intel";

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

export type TodayEventsTargetTab = "correlation-engine" | "threat-actors" | "threat-feed" | "github-intel";

// "Critical KEV" and "Major Vendor Advisories" were dropped from this grid --
// the KEV count and a real vendor/source line now live once, in prose, in
// the AI Daily Brief below (see server/aiDailyBrief.js) instead of being
// shown twice across the merged tile.
const STATS: Array<{ key: keyof Omit<TodaySecurityEvents, "generatedAt" | "criticalKev">; label: string; icon: typeof ShieldAlert; color: string; tab: TodayEventsTargetTab }> = [
  { key: "activeExploitCampaigns", label: "Active Exploit Campaigns", icon: Flame, color: "text-high", tab: "correlation-engine" },
  { key: "newRansomwareVictims", label: "New Ransomware Victims", icon: Skull, color: "text-critical", tab: "threat-actors" },
  { key: "newMalwareSamples", label: "New Malware Samples", icon: Bug, color: "text-medium", tab: "threat-feed" },
  { key: "githubExploits", label: "GitHub Exploits", icon: Github, color: "text-medium", tab: "github-intel" },
  { key: "newIocs", label: "New IOCs", icon: Link2, color: "text-accent-cyan", tab: "threat-feed" },
];

function StatTile({
  label,
  icon: Icon,
  color,
  value,
  onClick,
}: {
  label: string;
  icon: typeof ShieldAlert;
  color: string;
  value: number;
  onClick: () => void;
}) {
  const animated = useCountUp(value);
  return (
    <button
      type="button"
      onClick={onClick}
      title={`View ${label}`}
      className="flex cursor-pointer flex-col gap-1.5 rounded-xl border border-white/[0.06] bg-white/[0.02] p-3.5 text-left transition-all duration-200 hover:-translate-y-0.5 hover:border-primary/30 hover:bg-white/[0.05]"
    >
      <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted">
        <Icon className={`h-3.5 w-3.5 ${color}`} />
        {label}
      </div>
      <span className="text-2xl font-bold tabular-nums text-foreground">{Math.round(animated)}</span>
    </button>
  );
}

interface TopSecurityEventsTodayProps {
  onNavigate: (tab: TodayEventsTargetTab) => void;
}

/** Same-calendar-day rollup of new activity across every source -- see server/todaySecurityEvents.js. Rendered without its own Card -- lives inside the merged Executive Threat Summary tile. */
export function TopSecurityEventsToday({ onNavigate }: TopSecurityEventsTodayProps) {
  const { data, isLoading, isError, error } = useTodaySecurityEvents();

  return (
    <div>
      <h3 className="mb-3 text-base font-semibold text-foreground">Top Security Events Today</h3>
      {isLoading ? (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-[72px] w-full" />
          ))}
        </div>
      ) : isError || !data ? (
        <ErrorState message={error?.message ?? "Top Security Events Today is unavailable right now."} />
      ) : (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
          {STATS.map((stat) => (
            <StatTile
              key={stat.key}
              label={stat.label}
              icon={stat.icon}
              color={stat.color}
              value={data[stat.key]}
              onClick={() => onNavigate(stat.tab)}
            />
          ))}
        </div>
      )}
    </div>
  );
}
