import { useEffect, useMemo, useState } from "react";
import { X } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeaderCell, TableRow } from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "./ErrorState";
import { DateRangeFilter, EMPTY_DATE_RANGE, isWithinDateRange, type DateRange } from "./DateRangeFilter";
import { useRansomwareCampaigns, useThreatActors } from "@/hooks/useRansomware";

interface RansomwareCampaignsProps {
  /** Country alpha-2 code to filter the campaign table to, set by clicking a country fact in the Executive Threat Summary. */
  countryFilter?: string | null;
  onClearCountryFilter?: () => void;
  /** Industry bucket (e.g. "LSHC") to filter to, set by clicking an industry fact in the Executive Threat Summary. */
  industryFilter?: string | null;
  onClearIndustryFilter?: () => void;
  /** Deep-link target set by clicking "New Ransomware Victims" on the Overview tab -- see DashboardPage.tsx#goToTodayEvent. */
  initialDateRange?: DateRange;
}

export function RansomwareCampaigns({ countryFilter, onClearCountryFilter, industryFilter, onClearIndustryFilter, initialDateRange }: RansomwareCampaignsProps) {
  const { campaigns, isLoading, isError } = useRansomwareCampaigns();
  const actors = useThreatActors();
  const [dateRange, setDateRange] = useState<DateRange>(initialDateRange ?? EMPTY_DATE_RANGE);

  useEffect(() => {
    if (initialDateRange) setDateRange(initialDateRange);
  }, [initialDateRange]);

  const filtered = useMemo(() => {
    let result = campaigns;
    if (countryFilter) result = result.filter((c) => c.country === countryFilter);
    if (industryFilter) result = result.filter((c) => c.industry === industryFilter);
    result = result.filter((c) => isWithinDateRange(c.discoveredDate, dateRange));
    return result;
  }, [campaigns, countryFilter, industryFilter, dateRange]);

  return (
    <Card>
      <CardHeader className="flex-col items-start gap-3 md:flex-row md:items-center">
        <CardTitle className="text-base font-semibold text-foreground">
          Active Ransomware Campaigns &amp; Threat Actor Activity{" "}
          <span className="text-muted" title="ransomware.live leak-site posts + OTX pulse adversary tags. Ransomware groups only -- no free bulk source covers APT/nation-state attribution.">
            (ransomware.live + OTX)
          </span>
        </CardTitle>
        <DateRangeFilter value={dateRange} onChange={setDateRange} />
        {countryFilter && (
          <Button variant="outline" size="sm" onClick={onClearCountryFilter}>
            Filtered by country: {countryFilter}
            <X className="h-3 w-3" />
          </Button>
        )}
        {industryFilter && (
          <Button variant="outline" size="sm" onClick={onClearIndustryFilter}>
            Filtered by industry: {industryFilter}
            <X className="h-3 w-3" />
          </Button>
        )}
      </CardHeader>
      <CardContent className="space-y-4">
        {actors.data && actors.data.length > 0 && (
          <div className="flex flex-wrap gap-2">
            {actors.data.slice(0, 12).map((actor) => (
              <Badge key={actor.name} variant={actor.type === "ransomware" ? "danger" : "muted"} title={`${actor.campaignCount} activity ${actor.campaignCount === 1 ? "entry" : "entries"}`}>
                {actor.name} ({actor.campaignCount})
              </Badge>
            ))}
          </div>
        )}

        {isLoading ? (
          <div className="space-y-2">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className="h-8 w-full" />
            ))}
          </div>
        ) : isError ? (
          <ErrorState message="ransomware.live is currently unreachable." />
        ) : filtered.length === 0 ? (
          <EmptyState
            message={
              countryFilter && industryFilter
                ? `No recent campaigns reported for ${countryFilter} in ${industryFilter}.`
                : countryFilter
                  ? `No recent campaigns reported for ${countryFilter}.`
                  : industryFilter
                    ? `No recent campaigns reported in ${industryFilter}.`
                    : "No recent ransomware campaigns reported."
            }
          />
        ) : (
          <Table>
            <TableHead>
              <TableRow>
                <TableHeaderCell>Group</TableHeaderCell>
                <TableHeaderCell>Victim</TableHeaderCell>
                <TableHeaderCell>Sector</TableHeaderCell>
                <TableHeaderCell>Country</TableHeaderCell>
                <TableHeaderCell>Discovered</TableHeaderCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {filtered.map((c) => (
                <TableRow key={c.id}>
                  <TableCell>
                    <Badge variant="danger">{c.group}</Badge>
                  </TableCell>
                  <TableCell className="max-w-xs truncate">
                    {c.sourceUrl ? (
                      <a href={c.sourceUrl} target="_blank" rel="noreferrer" className="text-primary hover:underline">
                        {c.victim}
                      </a>
                    ) : (
                      c.victim
                    )}
                  </TableCell>
                  <TableCell>{c.sector}</TableCell>
                  <TableCell>{c.country}</TableCell>
                  <TableCell className="whitespace-nowrap">{new Date(c.discoveredDate).toLocaleDateString()}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}
