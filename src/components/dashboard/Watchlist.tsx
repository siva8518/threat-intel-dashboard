import { useState } from "react";
import { Eye, ExternalLink, ChevronRight, Plus, X } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "./ErrorState";
import { useWatchlist } from "@/hooks/useWatchlist";
import { useFlashReports } from "@/hooks/useFlashReports";
import type { FlashReport, FlashReportSourceType } from "@/types/threat-intel";
import { cn } from "@/lib/utils";

const SOURCE_TYPE_LABEL: Record<FlashReportSourceType, string> = {
  news: "Security News",
  malware: "Malware Intelligence",
  actor: "Threat Actor Intelligence",
  campaign: "Campaign Intelligence",
  darkweb: "Dark Web Intelligence",
  ransomware: "Ransomware Leak Site",
  github: "GitHub Intel",
};

function timeAgo(iso: string) {
  const ms = Date.now() - new Date(iso).getTime();
  const hours = Math.floor(ms / (60 * 60 * 1000));
  if (hours < 1) return "just now";
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function KeywordManager() {
  const { keywords, isLoading, addKeyword, removeKeyword, isAdding } = useWatchlist();
  const [draft, setDraft] = useState("");

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    const label = draft.trim();
    if (!label) return;
    await addKeyword(label);
    setDraft("");
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-1.5 text-base font-semibold text-foreground">
          <Eye className="h-4 w-4 text-primary" />
          Tracked Names{" "}
          <span className="font-normal text-muted">
            ({keywords.length} name{keywords.length === 1 ? "" : "s"})
          </span>
        </CardTitle>
        <p className="mt-1 text-xs text-muted">
          Client and organization names under continuous monitoring -- any mention across news, malware/actor/campaign/dark-web intelligence, ransomware leak
          sites, or GitHub Intel is reported here as a flash alert the moment it's found.
        </p>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} className="mb-4 flex gap-2">
          <Input
            placeholder='Add a name to track, e.g. "Acme Corp" or "Acme Corp (ACME)"…'
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            className="flex-1"
          />
          <Button type="submit" disabled={!draft.trim() || isAdding}>
            <Plus className="h-3.5 w-3.5" />
            Add
          </Button>
        </form>

        {isLoading ? (
          <div className="flex flex-wrap gap-2">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-7 w-24" />
            ))}
          </div>
        ) : keywords.length === 0 ? (
          <EmptyState message="No names tracked yet -- add one above. Every source this platform monitors (news, malware/actor/campaign/dark-web intelligence, ransomware leak sites) gets scanned for it automatically." />
        ) : (
          <div className="flex flex-wrap gap-2">
            {keywords.map((k) => (
              <span
                key={k.id}
                className="flex items-center gap-1.5 rounded-full border border-white/10 bg-white/[0.03] py-1 pl-3 pr-1.5 text-xs font-medium text-foreground"
              >
                {k.label}
                <button
                  type="button"
                  onClick={() => removeKeyword(k.id)}
                  aria-label={`Stop tracking ${k.label}`}
                  className="rounded-full p-0.5 text-muted transition-colors hover:bg-critical/15 hover:text-critical"
                >
                  <X className="h-3 w-3" />
                </button>
              </span>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function FlashReportRow({ report, onOpen }: { report: FlashReport; onOpen: (r: FlashReport) => void }) {
  return (
    <li className={cn("py-2.5", !report.read && "bg-critical/[0.04]")}>
      <button type="button" onClick={() => onOpen(report)} className="flex w-full items-start justify-between gap-3 px-3 text-left">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            {!report.read && <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-critical" />}
            <Badge variant="danger" className="shrink-0">
              {report.keywordLabel}
            </Badge>
            <span className="truncate text-sm text-foreground">{report.title}</span>
            {report.url && <ExternalLink className="h-3 w-3 shrink-0 text-muted" />}
          </div>
          <p className="mt-0.5 text-xs text-muted">
            {SOURCE_TYPE_LABEL[report.sourceType]} · {report.sourceLabel}
          </p>
        </div>
        <span className="shrink-0 text-xs text-muted">{timeAgo(report.foundAt)}</span>
      </button>
    </li>
  );
}

/**
 * User-curated watchlist: names being continuously monitored across every
 * intelligence source this platform tracks (news, malware/actor/campaign/
 * dark-web intelligence, ransomware leak-site victim posts), plus the full
 * history of matches found -- see server/watchlist.js + server/watchlistScanner.js.
 * The most-recent unread match also surfaces as a dashboard-wide banner
 * (FlashReportBanner.tsx) until opened or dismissed from here.
 */
export function Watchlist() {
  const { reports, unreadCount, isLoading, isError, markRead, markAllRead } = useFlashReports();
  const [showEarlier, setShowEarlier] = useState(false);

  const recentReports = reports.filter((r) => r.recent);
  const earlierReports = reports.filter((r) => !r.recent);

  function openReport(report: FlashReport) {
    markRead(report.id);
    if (report.url) window.open(report.url, "_blank", "noopener,noreferrer");
  }

  return (
    <div className="space-y-4">
      <KeywordManager />
      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <CardTitle className="flex items-center gap-1.5 text-base font-semibold text-foreground">
            Flash Reports{" "}
            <span className="font-normal text-muted">
              ({reports.length} total, {unreadCount} unread)
            </span>
          </CardTitle>
          {unreadCount > 0 && (
            <Button variant="outline" size="sm" onClick={() => markAllRead()}>
              Mark all read
            </Button>
          )}
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="space-y-2">
              {Array.from({ length: 5 }).map((_, i) => (
                <Skeleton key={i} className="h-12 w-full" />
              ))}
            </div>
          ) : isError ? (
            <ErrorState message="Flash reports are unavailable right now." />
          ) : reports.length === 0 ? (
            <EmptyState message="No matches yet -- as soon as a tracked name shows up anywhere this platform monitors, it'll appear here." />
          ) : (
            <>
              <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-muted">New in the last 48h ({recentReports.length})</p>
              {recentReports.length === 0 ? (
                <p className="mb-4 text-xs text-muted">No fresh mentions in the last 48 hours.</p>
              ) : (
                <ul className="mb-4 divide-y divide-white/[0.06]">
                  {recentReports.map((r) => (
                    <FlashReportRow key={r.id} report={r} onOpen={openReport} />
                  ))}
                </ul>
              )}

              {earlierReports.length > 0 && (
                <div className="border-t border-white/[0.06] pt-3">
                  <button
                    type="button"
                    onClick={() => setShowEarlier((v) => !v)}
                    className="flex items-center gap-1 text-xs font-medium text-muted transition-colors hover:text-foreground"
                  >
                    <ChevronRight className={cn("h-3.5 w-3.5 transition-transform", showEarlier && "rotate-90")} />
                    {showEarlier ? "Hide" : "Show"} {earlierReports.length} earlier mention{earlierReports.length === 1 ? "" : "s"}
                  </button>
                  {showEarlier && (
                    <ul className="mt-2 divide-y divide-white/[0.06] opacity-80">
                      {earlierReports.map((r) => (
                        <FlashReportRow key={r.id} report={r} onOpen={openReport} />
                      ))}
                    </ul>
                  )}
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
