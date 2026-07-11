import { useEffect, useMemo, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { ExternalLink, Flame, Globe2, ShieldAlert, Skull, TrendingUp, Bug } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Select } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "./ErrorState";
import { useSecurityNews } from "@/hooks/useSecurityNews";
import { useSelection } from "@/context/SelectionContext";
import { fetchCveById } from "@/api/dashboardApi";
import type { NewsItem, NewsSeverity } from "@/types/threat-intel";
import { cn } from "@/lib/utils";

const DISPLAY_LIMIT = 60;

type GroupBy = "none" | "actors" | "malware" | "cveIds" | "industries" | "countries";

const GROUP_OPTIONS: Array<{ value: GroupBy; label: string; icon: typeof Skull }> = [
  { value: "none", label: "Latest", icon: TrendingUp },
  { value: "actors", label: "Threat Actor", icon: Skull },
  { value: "malware", label: "Malware", icon: Bug },
  { value: "cveIds", label: "CVE", icon: ShieldAlert },
  { value: "industries", label: "Industry", icon: TrendingUp },
  { value: "countries", label: "Country", icon: Globe2 },
];

// Confirmed commercial security-vendor threat-research feeds among this
// app's 31 news sources (see server/connectors/newsFeeds.js) -- as opposed
// to security journalism/aggregator outlets (BleepingComputer, The Hacker
// News, Krebs, etc.) or government/CERT advisories (CISA, UK NCSC). A
// selectable grouping in the source filter below, and the landing spot for
// the AI Daily Brief's "published N articles today" bullet.
const MAJOR_VENDOR_SOURCES = new Set([
  "Cisco Talos",
  "CrowdStrike",
  "Unit 42",
  "Recorded Future",
  "Google Threat Intelligence",
  "Microsoft Security",
  "SentinelLabs",
  "Rapid7",
  "Check Point Research",
  "ESET Research",
  "Kaspersky Securelist",
  "Elastic Security Labs",
  "FortiGuard Labs",
]);
const MAJOR_VENDORS_FILTER = "__major-vendors__";

const SEVERITY_STYLE: Record<NewsSeverity, { variant: "critical" | "high" | "medium" | "low"; label: string }> = {
  critical: { variant: "critical", label: "Critical" },
  high: { variant: "high", label: "High" },
  medium: { variant: "medium", label: "Medium" },
  low: { variant: "low", label: "Low" },
};

function timeAgo(iso: string) {
  const ms = Date.now() - new Date(iso).getTime();
  const hours = Math.floor(ms / (60 * 60 * 1000));
  if (hours < 1) return "just now";
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function TagChips({ item }: { item: NewsItem }) {
  const { selectMalware, selectCve } = useSelection();
  const [loadingCve, setLoadingCve] = useState<string | null>(null);

  async function openCve(cveId: string) {
    setLoadingCve(cveId);
    try {
      selectCve(await fetchCveById(cveId));
    } catch {
      // best-effort -- if the live NVD lookup fails, just don't open the drawer
    } finally {
      setLoadingCve(null);
    }
  }

  const hasTags =
    item.tags.cveIds.length ||
    item.tags.malware.length ||
    item.tags.actors.length ||
    item.tags.industries.length ||
    item.tags.countries.length;
  if (!hasTags) return null;

  return (
    <div className="mt-1.5 flex flex-wrap gap-1">
      {item.tags.cveIds.map((id) => (
        <button
          key={id}
          onClick={() => openCve(id)}
          disabled={loadingCve === id}
          className="rounded-full border border-critical/25 bg-critical/10 px-2 py-0.5 font-mono text-[11px] text-critical transition-colors hover:bg-critical/20 disabled:opacity-50"
        >
          {id}
        </button>
      ))}
      {item.tags.malware.map((m) => (
        <button
          key={m}
          onClick={() => selectMalware({ family: m, count: 0, sources: [], techniques: [], detectionRules: [] })}
          className="rounded-full border border-white/10 bg-white/[0.03] px-2 py-0.5 text-[11px] transition-colors hover:border-primary/40"
        >
          {m}
        </button>
      ))}
      {item.tags.actors.map((a) => (
        <Badge key={a} variant="danger" className="text-[11px]">
          {a}
        </Badge>
      ))}
      {item.tags.industries.map((i) => (
        <Badge key={i} variant="muted" className="text-[11px]">
          {i}
        </Badge>
      ))}
      {item.tags.countries.map((c) => (
        <Badge key={c} variant="cyan" className="text-[11px]">
          {c}
        </Badge>
      ))}
    </div>
  );
}

function ArticleRow({ item }: { item: NewsItem }) {
  const severity = SEVERITY_STYLE[item.severity];
  return (
    <li className="py-2.5">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <a
            href={item.link}
            target="_blank"
            rel="noreferrer"
            className="flex items-start gap-1 text-sm text-foreground hover:text-primary hover:underline"
          >
            <span>{item.title}</span>
            <ExternalLink className="mt-0.5 h-3 w-3 shrink-0" />
          </a>
          <TagChips item={item} />
        </div>
        <div className="flex shrink-0 flex-col items-end gap-1">
          <Badge variant={severity.variant}>{severity.label}</Badge>
          <span className="text-[11px] text-muted">{timeAgo(item.publishedDate)}</span>
          <Badge variant="muted" className="text-[11px]">
            {item.source}
          </Badge>
        </div>
      </div>
    </li>
  );
}

function BreakingNewsStrip({ items }: { items: NewsItem[] }) {
  if (items.length === 0) return null;
  return (
    <motion.div
      initial={{ opacity: 0, y: -8 }}
      animate={{ opacity: 1, y: 0 }}
      className="mb-4 overflow-hidden rounded-xl border border-critical/30 bg-critical/[0.06]"
    >
      <div className="flex items-center gap-2 border-b border-critical/20 px-4 py-2">
        <span className="relative flex h-2 w-2">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-critical opacity-75" />
          <span className="relative inline-flex h-2 w-2 rounded-full bg-critical" />
        </span>
        <Flame className="h-3.5 w-3.5 text-critical" />
        <span className="text-xs font-bold uppercase tracking-wider text-critical">Breaking · Last 6 Hours</span>
      </div>
      <ul className="divide-y divide-critical/10 px-4">
        <AnimatePresence initial={false}>
          {items.slice(0, 6).map((item) => (
            <motion.li
              key={item.id}
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0 }}
              className="py-2"
            >
              <div className="flex items-center justify-between gap-3">
                <a
                  href={item.link}
                  target="_blank"
                  rel="noreferrer"
                  className="flex min-w-0 items-center gap-1.5 text-sm font-medium text-foreground hover:text-primary hover:underline"
                >
                  <span className="truncate">{item.title}</span>
                  <ExternalLink className="h-3 w-3 shrink-0" />
                </a>
                <Badge variant={SEVERITY_STYLE[item.severity].variant} className="shrink-0">
                  {SEVERITY_STYLE[item.severity].label}
                </Badge>
              </div>
            </motion.li>
          ))}
        </AnimatePresence>
      </ul>
    </motion.div>
  );
}

interface SecurityNewsProps {
  /** Deep-link target set by clicking a source in the AI Daily Brief ("{source} published N articles today"). */
  initialSourceFilter?: string | null;
}

export function SecurityNews({ initialSourceFilter }: SecurityNewsProps = {}) {
  const { items, isLoading, isError, error } = useSecurityNews();
  const [sourceFilter, setSourceFilter] = useState(initialSourceFilter ?? "ALL");
  const [groupBy, setGroupBy] = useState<GroupBy>("none");

  // Re-syncs whenever a fresh navigation sets a new source (e.g. clicking a
  // different AI Daily Brief bullet on a later visit) rather than only on
  // first mount.
  useEffect(() => {
    if (initialSourceFilter) setSourceFilter(initialSourceFilter);
  }, [initialSourceFilter]);

  const availableSources = useMemo(() => Array.from(new Set(items.map((i) => i.source))).sort(), [items]);

  const sourceFiltered = useMemo(() => {
    if (sourceFilter === "ALL") return items;
    if (sourceFilter === MAJOR_VENDORS_FILTER) return items.filter((i) => MAJOR_VENDOR_SOURCES.has(i.source));
    return items.filter((i) => i.source === sourceFilter);
  }, [items, sourceFilter]);

  // "Latest" is a recency-capped flat feed regardless of tags. Grouped views
  // are the opposite: tags are rare (most headlines don't mention a specific
  // CVE/actor/etc.), so capping to the most-recent N *first* would leave
  // almost every group empty -- confirmed live, grouping by CVE against just
  // the newest 60 items surfaced zero CVE groups. Grouped views instead pull
  // from the full tagged pool and simply don't show an "Uncategorized"
  // bucket, since the point of picking a dimension is "what's the news said
  // about each X currently in the news," not every unrelated headline too.
  const filtered = useMemo(() => sourceFiltered.slice(0, DISPLAY_LIMIT), [sourceFiltered]);

  const breaking = useMemo(
    () => items.filter((i) => i.isBreaking && (i.severity === "critical" || i.severity === "high")),
    [items],
  );

  const groups = useMemo(() => {
    if (groupBy === "none") return null;
    const map = new Map<string, NewsItem[]>();
    for (const item of sourceFiltered) {
      for (const value of item.tags[groupBy]) {
        const bucket = map.get(value) ?? [];
        bucket.push(item);
        map.set(value, bucket);
      }
    }
    return Array.from(map.entries())
      .sort((a, b) => b[1].length - a[1].length)
      .slice(0, 15);
  }, [sourceFiltered, groupBy]);

  return (
    <div className="space-y-4">
      <BreakingNewsStrip items={breaking} />
      <Card>
        <CardHeader className="flex-col items-start gap-3 md:flex-row md:items-center">
          <CardTitle className="text-base font-semibold text-foreground">
            Security Newsroom <span className="text-muted">({availableSources.length || 31} sources merged, newest first)</span>
          </CardTitle>
          <div className="flex w-full flex-wrap gap-2 md:w-auto">
            <Select value={sourceFilter} onChange={(e) => setSourceFilter(e.target.value)} className="w-full sm:w-auto">
              <option value="ALL">All sources</option>
              <option value={MAJOR_VENDORS_FILTER}>Major Vendors (grouped)</option>
              {availableSources.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </Select>
          </div>
        </CardHeader>
        <CardContent>
          <div className="mb-4 flex flex-wrap gap-1.5">
            {GROUP_OPTIONS.map(({ value, label, icon: Icon }) => (
              <button
                key={value}
                onClick={() => setGroupBy(value)}
                className={cn(
                  "flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition-colors",
                  groupBy === value ? "bg-gradient-primary text-white shadow-glow-primary" : "border border-white/10 bg-white/[0.03] text-muted hover:text-foreground",
                )}
              >
                <Icon className="h-3.5 w-3.5" />
                {label}
              </button>
            ))}
          </div>

          {isLoading ? (
            <div className="space-y-3">
              {Array.from({ length: 6 }).map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : isError ? (
            <ErrorState message={error?.message ?? "Security news sources are currently unreachable."} />
          ) : groups === null && filtered.length === 0 ? (
            <EmptyState message="No headlines available." />
          ) : groups?.length === 0 ? (
            <EmptyState message="No current headlines are tagged with this dimension yet -- try again after the next refresh, or pick another grouping." />
          ) : groups === null ? (
            <ul className="divide-y divide-white/[0.06]">
              {filtered.map((item) => (
                <ArticleRow key={item.id} item={item} />
              ))}
            </ul>
          ) : (
            <div className="space-y-5">
              {groups.map(([groupName, groupItems]) => (
                <div key={groupName}>
                  <h3 className="mb-1 flex items-center gap-2 text-sm font-semibold text-foreground">
                    {groupName}
                    <span className="text-xs font-normal text-muted">
                      ({groupItems.length} article{groupItems.length === 1 ? "" : "s"})
                    </span>
                  </h3>
                  <ul className="divide-y divide-white/[0.06] rounded-lg border border-white/[0.06] bg-white/[0.01] px-3">
                    {groupItems.map((item) => (
                      <ArticleRow key={`${groupName}-${item.id}`} item={item} />
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
