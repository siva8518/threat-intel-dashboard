import { useState } from "react";
import { ShieldAlert } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "./ErrorState";
import { RankedBarChart } from "./RankedBarChart";
import { TimeframeSelector } from "./TimeframeSelector";
import { useGithubIntelStats } from "@/hooks/useGithubIntel";
import { useSelection } from "@/context/SelectionContext";
import { fetchCveById } from "@/api/dashboardApi";

const TOP_N = 8;

/**
 * Ranked by how many tracked GitHub repos reference each CVE (PoC exploits,
 * write-ups, detection rules) plus how many news headlines across every
 * configured source name it -- see server/githubIntel/index.js#computeTopCves,
 * which merges both signals the same way server/correlate.js merges IOC- and
 * news-derived ATT&CK technique counts. Scoped by the timeframe selector
 * below (default 30d, repos re-dated by lastEnrichedAt/discoveredAt and news
 * items by publishedDate server-side -- see server/lib/dateWindow.js), with
 * an "All" option for full activity-to-date.
 */
export function TopCves() {
  const [days, setDays] = useState<number | null>(30);
  const { data, isLoading, isError } = useGithubIntelStats(days);
  const { selectCve } = useSelection();
  const [loadingCveId, setLoadingCveId] = useState<string | null>(null);

  const topCves = (data?.topCves ?? []).slice(0, TOP_N);

  async function openCve(cveId: string) {
    setLoadingCveId(cveId);
    try {
      selectCve(await fetchCveById(cveId));
    } catch {
      // best-effort -- if the live NVD lookup fails, just don't open the drawer
    } finally {
      setLoadingCveId(null);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-1.5 text-base font-semibold text-foreground">
          <ShieldAlert className="h-4 w-4 text-primary" />
          Top CVEs
        </CardTitle>
        <TimeframeSelector value={days} onChange={setDays} />
      </CardHeader>
      <CardContent>
        {isLoading || loadingCveId ? (
          <Skeleton className="h-48 w-full" />
        ) : isError ? (
          <ErrorState message="Top CVEs is unavailable right now." />
        ) : topCves.length === 0 ? (
          <EmptyState message={days ? `No GitHub-tracked or news-mentioned CVE activity in the last ${days} days.` : "No GitHub-tracked or news-mentioned CVE activity yet."} />
        ) : (
          <RankedBarChart
            hue="#f7913d"
            data={topCves.map((c) => ({
              name: c.cveId,
              count: c.repoCount + c.newsMentionCount,
              detail: [
                c.repoCount > 0 ? `${c.repoCount} GitHub PoC/repo mention${c.repoCount === 1 ? "" : "s"}` : null,
                c.newsMentionCount > 0 ? `${c.newsMentionCount} news mention${c.newsMentionCount === 1 ? "" : "s"}` : null,
              ]
                .filter(Boolean)
                .join(" · "),
              onOpen: () => openCve(c.cveId),
            }))}
          />
        )}
      </CardContent>
    </Card>
  );
}
