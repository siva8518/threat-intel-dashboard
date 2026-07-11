import { useMemo, useState } from "react";
import { Bug, ExternalLink, Github, Newspaper, ShieldAlert, Skull } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "./ErrorState";
import { useThreatTimeline } from "@/hooks/useThreatTimeline";
import { useSelection } from "@/context/SelectionContext";
import { fetchCveById } from "@/api/dashboardApi";
import type { ThreatTimelineEvent, ThreatTimelineEventType } from "@/types/threat-intel";
import { cn } from "@/lib/utils";

const DAY_OPTIONS = [
  { value: 1, label: "Today" },
  { value: 3, label: "3 Days" },
  { value: 7, label: "7 Days" },
  { value: 30, label: "30 Days" },
];

const TYPE_OPTIONS: Array<{ value: ThreatTimelineEventType; label: string; icon: typeof Skull }> = [
  { value: "kev", label: "KEV", icon: ShieldAlert },
  { value: "ransomware", label: "Ransomware", icon: Skull },
  { value: "malware", label: "Malware", icon: Bug },
  { value: "github", label: "GitHub", icon: Github },
  { value: "news", label: "News", icon: Newspaper },
];

const TYPE_ICON: Record<ThreatTimelineEventType, typeof Skull> = {
  kev: ShieldAlert,
  ransomware: Skull,
  malware: Bug,
  github: Github,
  news: Newspaper,
};

function dayLabel(iso: string) {
  const date = new Date(iso);
  const today = new Date();
  const yesterday = new Date();
  yesterday.setDate(today.getDate() - 1);
  const sameDay = (a: Date, b: Date) => a.toDateString() === b.toDateString();
  if (sameDay(date, today)) return "Today";
  if (sameDay(date, yesterday)) return "Yesterday";
  return date.toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" });
}

function timeLabel(iso: string) {
  return new Date(iso).toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" });
}

function EventRow({ event }: { event: ThreatTimelineEvent }) {
  const { selectMalware, selectCve } = useSelection();
  const [loading, setLoading] = useState(false);
  const Icon = TYPE_ICON[event.type];

  async function handleClick() {
    if (event.type === "kev" && event.cveId) {
      setLoading(true);
      try {
        selectCve(await fetchCveById(event.cveId));
      } catch {
        // best-effort -- if the live NVD lookup fails, just don't open the drawer
      } finally {
        setLoading(false);
      }
      return;
    }
    if (event.type === "malware" && event.malwareFamily) {
      selectMalware({ family: event.malwareFamily, count: 0, sources: [], techniques: [], detectionRules: [] });
      return;
    }
    if (event.url) window.open(event.url, "_blank", "noreferrer");
  }

  const clickable = (event.type === "kev" && event.cveId) || (event.type === "malware" && event.malwareFamily) || event.url;

  return (
    <li className="relative pl-8">
      <span className="absolute left-[7px] top-1.5 h-2.5 w-2.5 rounded-full border-2 border-background bg-primary" />
      <button
        type="button"
        onClick={handleClick}
        disabled={!clickable || loading}
        className={cn(
          "flex w-full flex-col gap-1 rounded-lg border border-white/10 bg-white/[0.02] p-3 text-left transition-colors",
          clickable && "hover:border-primary/40 hover:bg-white/[0.05]",
        )}
      >
        <div className="flex items-start justify-between gap-2">
          <span className="flex items-center gap-1.5 text-sm font-medium text-foreground">
            <Icon className="h-3.5 w-3.5 shrink-0 text-muted" />
            {event.title}
            {event.type !== "kev" && event.type !== "malware" && event.url && <ExternalLink className="h-3 w-3 shrink-0 text-muted" />}
          </span>
          <Badge variant={event.severity} className="shrink-0">
            {event.severity}
          </Badge>
        </div>
        {event.detail && <p className="pl-5 text-xs text-muted">{event.detail}</p>}
        <p className="pl-5 text-[11px] text-muted">{timeLabel(event.date)}</p>
      </button>
    </li>
  );
}

/** Interactive Threat Timeline -- see server/threatTimeline.js. */
export function ThreatTimeline() {
  const [days, setDays] = useState(7);
  const [activeTypes, setActiveTypes] = useState<Set<ThreatTimelineEventType>>(new Set(TYPE_OPTIONS.map((t) => t.value)));
  const { events, isLoading, isError, error } = useThreatTimeline(days);

  function toggleType(type: ThreatTimelineEventType) {
    setActiveTypes((prev) => {
      const next = new Set(prev);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });
  }

  const filtered = useMemo(() => events.filter((e) => activeTypes.has(e.type)), [events, activeTypes]);

  const groups = useMemo(() => {
    const byDay = new Map<string, ThreatTimelineEvent[]>();
    for (const event of filtered) {
      const key = dayLabel(event.date);
      const list = byDay.get(key) ?? [];
      list.push(event);
      byDay.set(key, list);
    }
    return Array.from(byDay.entries());
  }, [filtered]);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base font-semibold text-foreground">
          Interactive Threat Timeline{" "}
          <span className="text-muted">(KEV additions, ransomware victims, malware sightings, GitHub PoCs &amp; notable news)</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap gap-1.5">
            {DAY_OPTIONS.map((opt) => (
              <button
                key={opt.value}
                onClick={() => setDays(opt.value)}
                className={cn(
                  "rounded-lg px-3 py-1.5 text-xs font-medium transition-colors",
                  days === opt.value ? "bg-gradient-primary text-white shadow-glow-primary" : "border border-white/10 bg-white/[0.03] text-muted hover:text-foreground",
                )}
              >
                {opt.label}
              </button>
            ))}
          </div>
          <div className="flex flex-wrap gap-1.5">
            {TYPE_OPTIONS.map(({ value, label, icon: Icon }) => (
              <button
                key={value}
                onClick={() => toggleType(value)}
                className={cn(
                  "flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-medium transition-colors",
                  activeTypes.has(value) ? "border border-primary/40 bg-primary/10 text-foreground" : "border border-white/10 bg-white/[0.02] text-muted hover:text-foreground",
                )}
              >
                <Icon className="h-3.5 w-3.5" />
                {label}
              </button>
            ))}
          </div>
        </div>

        {isLoading ? (
          <div className="space-y-2">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-16 w-full" />
            ))}
          </div>
        ) : isError ? (
          <ErrorState message={error?.message ?? "The threat timeline is unavailable right now."} />
        ) : groups.length === 0 ? (
          <EmptyState message="No events match the current filters in this window." />
        ) : (
          <div className="space-y-6">
            {groups.map(([day, dayEvents]) => (
              <div key={day}>
                <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">{day}</p>
                <ul className="space-y-2 border-l border-white/10">
                  {dayEvents.map((event) => (
                    <EventRow key={event.id} event={event} />
                  ))}
                </ul>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
