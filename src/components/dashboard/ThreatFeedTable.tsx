import { useMemo, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeaderCell, TableRow } from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "./ErrorState";
import { useThreatFeed } from "@/hooks/useThreatFeed";
import type { IocType } from "@/types/threat-intel";

const TYPE_LABEL: Record<IocType, string> = {
  ip: "IP Address",
  domain: "Domain",
  url: "URL",
  hash: "File Hash",
  unknown: "Unknown",
};

export function ThreatFeedTable() {
  const { iocs, isLoading, isError, error } = useThreatFeed();
  const [sourceFilter, setSourceFilter] = useState("ALL");
  const [familyFilter, setFamilyFilter] = useState("");

  const availableSources = useMemo(() => Array.from(new Set(iocs.flatMap((i) => i.sources))).sort(), [iocs]);

  const filtered = useMemo(() => {
    return iocs.filter((ioc) => {
      if (sourceFilter !== "ALL" && !ioc.sources.includes(sourceFilter)) return false;
      if (familyFilter && !ioc.malwareFamily.toLowerCase().includes(familyFilter.toLowerCase())) return false;
      return true;
    });
  }, [iocs, sourceFilter, familyFilter]);

  return (
    <Card>
      <CardHeader className="flex-col items-start gap-3 md:flex-row md:items-center">
        <CardTitle className="text-base font-semibold text-foreground">
          Threat Feed{" "}
          <span className="text-muted">
            (deduped IOCs from ThreatFox, URLHaus, MalwareBazaar, Feodo Tracker, OpenPhish, OTX &amp; AbuseIPDB)
          </span>
        </CardTitle>
        <div className="flex w-full flex-wrap gap-2 md:w-auto">
          <Input
            placeholder="Filter by malware family…"
            value={familyFilter}
            onChange={(e) => setFamilyFilter(e.target.value)}
            className="w-full sm:w-48"
          />
          <Select value={sourceFilter} onChange={(e) => setSourceFilter(e.target.value)}>
            <option value="ALL">All sources</option>
            {availableSources.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </Select>
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="space-y-2">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-9 w-full" />
            ))}
          </div>
        ) : isError ? (
          <ErrorState message={error?.message ?? "Threat feed is currently unreachable."} />
        ) : filtered.length === 0 ? (
          <EmptyState message="No indicators matched the current filters." />
        ) : (
          <Table>
            <TableHead>
              <TableRow>
                <TableHeaderCell>Indicator</TableHeaderCell>
                <TableHeaderCell>Type</TableHeaderCell>
                <TableHeaderCell>Malware Family</TableHeaderCell>
                <TableHeaderCell>Threat Type</TableHeaderCell>
                <TableHeaderCell>First Seen</TableHeaderCell>
                <TableHeaderCell>Sources</TableHeaderCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {filtered.map((ioc) => (
                <TableRow key={ioc.id}>
                  <TableCell className="max-w-xs truncate font-mono text-xs">{ioc.indicator}</TableCell>
                  <TableCell>{TYPE_LABEL[ioc.indicatorType]}</TableCell>
                  <TableCell>{ioc.malwareFamily}</TableCell>
                  <TableCell>{ioc.threatType}</TableCell>
                  <TableCell className="whitespace-nowrap">
                    {new Date(ioc.firstSeen).toLocaleString(undefined, {
                      month: "short",
                      day: "numeric",
                      hour: "2-digit",
                      minute: "2-digit",
                    })}
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {ioc.sources.map((s) => (
                        <Badge key={s} variant="muted">
                          {s}
                        </Badge>
                      ))}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}
