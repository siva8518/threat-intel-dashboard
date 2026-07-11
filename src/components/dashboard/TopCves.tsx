import { useState } from "react";
import { ShieldAlert } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "./ErrorState";
import { RankedBarChart } from "./RankedBarChart";
import { useGithubIntelStats } from "@/hooks/useGithubIntel";
import { useSelection } from "@/context/SelectionContext";
import { fetchCveById } from "@/api/dashboardApi";

const TOP_N = 8;

/**
 * Ranked by how many tracked GitHub repos reference each CVE (PoC exploits,
 * write-ups, detection rules -- see server/githubIntel/index.js#computeTopCves),
 * not by "actor-attributed KEV entries added in exactly the last 7 days" --
 * that narrower cut is frequently empty; GitHub PoC activity accumulates
 * continuously and is almost never zero.
 */
export function TopCves() {
  const { data, isLoading, isError } = useGithubIntelStats();
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
      </CardHeader>
      <CardContent>
        {isLoading || loadingCveId ? (
          <Skeleton className="h-48 w-full" />
        ) : isError ? (
          <ErrorState message="Top CVEs is unavailable right now." />
        ) : topCves.length === 0 ? (
          <EmptyState message="No GitHub-tracked CVE activity yet." />
        ) : (
          <RankedBarChart
            hue="#f7913d"
            data={topCves.map((c) => ({
              name: c.cveId,
              count: c.repoCount,
              detail: `${c.repoCount} GitHub PoC/repo mention${c.repoCount === 1 ? "" : "s"}`,
              onOpen: () => openCve(c.cveId),
            }))}
          />
        )}
      </CardContent>
    </Card>
  );
}
