import { useMemo, useState } from "react";
import { ArrowDown, ArrowUp, ExternalLink } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeaderCell, TableRow } from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { SeverityBadge } from "./SeverityBadge";
import { ErrorState, EmptyState } from "./ErrorState";
import { useCves } from "@/hooks/useCves";
import { useDebouncedValue } from "@/hooks/useDebouncedValue";
import { CVSS_SEVERITIES } from "@/config/constants";
import type { Severity } from "@/types/threat-intel";
import { useSelection } from "@/context/SelectionContext";

const PAGE_SIZE = 20;
const SEARCH_DEBOUNCE_MS = 400;
type SortKey = "cvssScore" | "publishedDate";

export function CveTable() {
  const [severity, setSeverity] = useState<Severity | "ALL">("ALL");
  const [keyword, setKeyword] = useState("");
  const debouncedKeyword = useDebouncedValue(keyword, SEARCH_DEBOUNCE_MS);
  const [page, setPage] = useState(0);
  const [sortKey, setSortKey] = useState<SortKey>("publishedDate");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const { selectCve } = useSelection();

  const cves = useCves({
    severity: severity === "ALL" ? undefined : severity,
    keyword: debouncedKeyword,
    page,
    pageSize: PAGE_SIZE,
  });
  const rows = useMemo(() => {
    const records = cves.data?.records ?? [];
    // Sorting only applies within the current page: each page is fetched
    // server-side from NVD, and re-sorting across all pages would require
    // pulling the entire 30-day result set client-side.
    return [...records].sort((a, b) => {
      const dir = sortDir === "asc" ? 1 : -1;
      if (sortKey === "cvssScore") return ((a.cvssScore ?? -1) - (b.cvssScore ?? -1)) * dir;
      return (new Date(a.publishedDate).getTime() - new Date(b.publishedDate).getTime()) * dir;
    });
  }, [cves.data, sortKey, sortDir]);

  function toggleSort(key: SortKey) {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("desc");
    }
  }

  const totalResults = cves.data?.totalResults ?? 0;
  const totalPages = Math.max(1, Math.ceil(totalResults / PAGE_SIZE));

  return (
    <Card>
      <CardHeader className="flex-col items-start gap-3 md:flex-row md:items-center">
        <CardTitle className="text-base font-semibold text-foreground">
          Latest CVEs <span className="text-muted">(last 30 days)</span>
        </CardTitle>
        <div className="flex w-full flex-wrap gap-2 md:w-auto">
          <Input
            placeholder="Search CVE ID or keyword…"
            value={keyword}
            onChange={(e) => {
              setKeyword(e.target.value);
              setPage(0);
            }}
            className="w-full sm:w-56"
          />
          <Select
            value={severity}
            onChange={(e) => {
              setSeverity(e.target.value as Severity | "ALL");
              setPage(0);
            }}
          >
            <option value="ALL">All severities</option>
            {CVSS_SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </Select>
        </div>
      </CardHeader>
      <CardContent>
        {cves.isLoading ? (
          <div className="space-y-2">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-9 w-full" />
            ))}
          </div>
        ) : cves.isError ? (
          <ErrorState message={(cves.error as Error).message} />
        ) : rows.length === 0 ? (
          <EmptyState message="No CVEs matched the current filters." />
        ) : (
          <>
            <Table>
              <TableHead>
                <TableRow>
                  <TableHeaderCell>CVE ID</TableHeaderCell>
                  <TableHeaderCell>Severity</TableHeaderCell>
                  <TableHeaderCell>
                    <button className="flex items-center gap-1" onClick={() => toggleSort("cvssScore")}>
                      CVSS {sortKey === "cvssScore" && (sortDir === "asc" ? <ArrowUp className="h-3 w-3" /> : <ArrowDown className="h-3 w-3" />)}
                    </button>
                  </TableHeaderCell>
                  <TableHeaderCell>Vendor</TableHeaderCell>
                  <TableHeaderCell title="FIRST EPSS: probability of exploitation in the next 30 days">EPSS</TableHeaderCell>
                  <TableHeaderCell>
                    <button className="flex items-center gap-1" onClick={() => toggleSort("publishedDate")}>
                      Published {sortKey === "publishedDate" && (sortDir === "asc" ? <ArrowUp className="h-3 w-3" /> : <ArrowDown className="h-3 w-3" />)}
                    </button>
                  </TableHeaderCell>
                  <TableHeaderCell>Description</TableHeaderCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {rows.map((cve) => (
                  <TableRow key={cve.id} interactive onClick={() => selectCve(cve)} title="View correlated actors, campaigns, IOCs, GitHub PoCs & news">
                    <TableCell className="font-mono text-xs">
                      <a
                        href={cve.sourceUrl}
                        target="_blank"
                        rel="noreferrer"
                        onClick={(e) => e.stopPropagation()}
                        className="flex items-center gap-1 text-primary hover:underline"
                      >
                        {cve.id}
                        <ExternalLink className="h-3 w-3" />
                      </a>
                      {cve.knownExploited && (
                        <Badge variant="danger" className="mt-1">
                          Known Exploited
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell>
                      <SeverityBadge severity={cve.severity} />
                    </TableCell>
                    <TableCell>{cve.cvssScore?.toFixed(1) ?? "—"}</TableCell>
                    <TableCell>{cve.vendor}</TableCell>
                    <TableCell title={cve.epssPercentile !== null ? `${(cve.epssPercentile * 100).toFixed(0)}th percentile` : undefined}>
                      {cve.epssScore !== null ? `${(cve.epssScore * 100).toFixed(1)}%` : "—"}
                    </TableCell>
                    <TableCell className="whitespace-nowrap">
                      {new Date(cve.publishedDate).toLocaleDateString()}
                    </TableCell>
                    <TableCell className="max-w-md text-muted">
                      <span className="line-clamp-2">{cve.description}</span>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            <div className="mt-3 flex items-center justify-between text-xs text-muted">
              <span>
                Page {page + 1} of {totalPages} · {totalResults} results
              </span>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
                  Previous
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={page + 1 >= totalPages}
                  onClick={() => setPage((p) => p + 1)}
                >
                  Next
                </Button>
              </div>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}
