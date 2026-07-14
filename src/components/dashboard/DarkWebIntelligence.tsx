import { useMemo, useState } from "react";
import { Ghost, ChevronDown, ChevronRight, ExternalLink, ShieldCheck } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "./ErrorState";
import { DateRangeFilter, EMPTY_DATE_RANGE, isWithinDateRange, type DateRange } from "./DateRangeFilter";
import { useDarkWebIntelligence } from "@/hooks/useDarkWebIntelligence";
import type { DarkWebIntelligenceEntity, DarkWebFindingType } from "@/types/threat-intel";
import { cn } from "@/lib/utils";

const TYPE_FILTERS: Array<DarkWebFindingType | "All"> = [
  "All",
  "Data Leak",
  "Credential Dump",
  "Initial Access Listing",
  "Marketplace Listing",
  "Forum Discussion",
  "Extortion Threat",
  "Other",
];

const TYPE_VARIANT: Record<DarkWebFindingType, "critical" | "high" | "medium" | "cyan" | "default" | "low" | "muted"> = {
  "Data Leak": "critical",
  "Credential Dump": "high",
  "Initial Access Listing": "high",
  "Extortion Threat": "critical",
  "Marketplace Listing": "medium",
  "Forum Discussion": "cyan",
  Other: "muted",
};

function timeAgo(iso: string) {
  const ms = Date.now() - new Date(iso).getTime();
  const days = Math.floor(ms / (24 * 60 * 60 * 1000));
  if (days < 1) return "today";
  if (days === 1) return "1 day ago";
  return `${days} days ago`;
}

function EntityRow({ entity, expanded, onToggle }: { entity: DarkWebIntelligenceEntity; expanded: boolean; onToggle: () => void }) {
  return (
    <div className="rounded-xl border border-white/[0.06] bg-white/[0.02]">
      <button type="button" onClick={onToggle} className="flex w-full items-start justify-between gap-3 p-3 text-left">
        <div className="flex min-w-0 items-start gap-2">
          {expanded ? <ChevronDown className="mt-0.5 h-4 w-4 shrink-0 text-muted" /> : <ChevronRight className="mt-0.5 h-4 w-4 shrink-0 text-muted" />}
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm font-semibold text-foreground">{entity.name}</span>
              <Badge variant={TYPE_VARIANT[entity.type]}>{entity.type}</Badge>
              {entity.verified ? (
                <Badge variant="low" className="gap-1">
                  <ShieldCheck className="h-3 w-3" />
                  Corroborated
                </Badge>
              ) : (
                <Badge variant="muted">Single source</Badge>
              )}
            </div>
            <div className="mt-1 flex flex-wrap gap-x-3 text-xs text-muted">
              {entity.platform && <span>Platform: {entity.platform}</span>}
              {entity.victimOrg && <span>Victim: {entity.victimOrg}</span>}
            </div>
          </div>
        </div>
        <div className="flex shrink-0 flex-col items-end gap-1 text-xs text-muted">
          <span>{entity.mentionCount} article{entity.mentionCount === 1 ? "" : "s"}</span>
          <span>last seen {timeAgo(entity.lastSeen)}</span>
        </div>
      </button>

      {expanded && (
        <div className="border-t border-white/[0.06] px-3 pb-3 pt-2 text-xs">
          <div className="mb-3 grid grid-cols-1 gap-2 sm:grid-cols-2">
            {entity.associatedActors.length > 0 && (
              <div>
                <span className="text-muted">Associated actors: </span>
                {entity.associatedActors.join(", ")}
              </div>
            )}
            {entity.associatedMalware.length > 0 && (
              <div>
                <span className="text-muted">Associated malware/tools: </span>
                {entity.associatedMalware.join(", ")}
              </div>
            )}
            {entity.targetedIndustries.length > 0 && (
              <div>
                <span className="text-muted">Targets industries: </span>
                {entity.targetedIndustries.join(", ")}
              </div>
            )}
            {entity.targetedCountries.length > 0 && (
              <div>
                <span className="text-muted">Targets countries: </span>
                {entity.targetedCountries.join(", ")}
              </div>
            )}
            {entity.cveExploited.length > 0 && (
              <div className="sm:col-span-2">
                <span className="text-muted">Exploits: </span>
                <span className="font-mono">{entity.cveExploited.join(", ")}</span>
              </div>
            )}
          </div>

          {entity.articles.length === 0 ? (
            <p className="text-muted">No linked articles.</p>
          ) : (
            <ul className="space-y-1.5">
              {entity.articles.map((a) => (
                <li key={a.link} className="flex items-start justify-between gap-3">
                  <a href={a.link} target="_blank" rel="noreferrer" className="flex min-w-0 items-start gap-1 text-foreground hover:text-primary hover:underline">
                    <span className="truncate">{a.title}</span>
                    <ExternalLink className="mt-0.5 h-3 w-3 shrink-0" />
                  </a>
                  <span className="shrink-0 text-muted">
                    {a.source} · {a.publishedDate?.slice(0, 10)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}

/**
 * Canonical, deduped dark-web-finding catalog -- one record per finding
 * (data leak, credential dump, initial-access listing, marketplace listing,
 * forum chatter, extortion threat), built by automatically extracting
 * findings from OSINT vendor/researcher news coverage of underground
 * forums/marketplaces/Telegram channels (server/darkWebExtraction.js). No
 * direct dark-web-forum scraping -- every linked article below is a public
 * news/vendor RSS feed already tracked in server/connectors/newsFeeds.js
 * (KELA, Cyble, SOCRadar, Constella Intelligence, Silobreaker, Recorded
 * Future, Intel 471, ransomware leak-site trackers, etc.). This is also
 * exactly what the RAG chatbot's dark-web chunks are built from -- anything
 * shown here is answerable by the AI Assistant tab.
 */
export function DarkWebIntelligence() {
  const { data, isLoading, isError, error } = useDarkWebIntelligence();
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState<DarkWebFindingType | "All">("All");
  const [dateRange, setDateRange] = useState<DateRange>(EMPTY_DATE_RANGE);
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());

  const entities = data?.entities ?? [];
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return entities.filter((e) => {
      if (typeFilter !== "All" && e.type !== typeFilter) return false;
      if (!isWithinDateRange(e.lastSeen, dateRange)) return false;
      if (!q) return true;
      return e.name.toLowerCase().includes(q) || (e.victimOrg ?? "").toLowerCase().includes(q) || (e.platform ?? "").toLowerCase().includes(q);
    });
  }, [entities, search, typeFilter, dateRange]);

  function toggle(id: string) {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  const verifiedCount = entities.filter((e) => e.verified).length;

  return (
    <Card>
      <CardHeader className="flex-col items-start gap-3">
        <div>
          <CardTitle className="flex items-center gap-1.5 text-base font-semibold text-foreground">
            <Ghost className="h-4 w-4 text-primary" />
            Dark Web Intelligence{" "}
            <span className="font-normal text-muted">
              ({entities.length} finding{entities.length === 1 ? "" : "s"}, {verifiedCount} corroborated)
            </span>
          </CardTitle>
          <p className="mt-1 text-xs text-muted">
            Data leaks, credential dumps, and underground-forum activity surfaced from OSINT vendor/researcher coverage of the dark web -- not direct dark-web scraping.
          </p>
        </div>
        <div className="flex w-full flex-wrap items-center gap-2">
          <Input placeholder="Search by finding, victim, or platform…" value={search} onChange={(e) => setSearch(e.target.value)} className="w-full sm:w-64" />
          <DateRangeFilter value={dateRange} onChange={setDateRange} />
          <div className="flex flex-wrap gap-1.5">
            {TYPE_FILTERS.map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => setTypeFilter(t)}
                className={cn(
                  "rounded-lg px-2.5 py-1 text-xs font-medium transition-colors",
                  typeFilter === t ? "bg-gradient-primary text-white shadow-glow-primary" : "border border-white/10 bg-white/[0.03] text-muted hover:text-foreground",
                )}
              >
                {t}
              </button>
            ))}
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="space-y-2">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-16 w-full" />
            ))}
          </div>
        ) : isError ? (
          <ErrorState message={error?.message ?? "Dark Web Intelligence is unavailable right now."} />
        ) : filtered.length === 0 ? (
          <EmptyState
            message={
              entities.length === 0
                ? "No dark-web findings identified yet -- extraction runs a few articles at a time in the background; check back shortly."
                : "No findings match this search/date/filter combination."
            }
          />
        ) : (
          <div className={cn("space-y-2")}>
            {filtered.map((entity) => (
              <EntityRow key={entity.id} entity={entity} expanded={expandedIds.has(entity.id)} onToggle={() => toggle(entity.id)} />
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
