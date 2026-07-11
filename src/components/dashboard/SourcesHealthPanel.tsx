import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeaderCell, TableRow } from "@/components/ui/table";
import { useSourcesHealth } from "@/hooks/useSourcesHealth";
import type { SourceReliability } from "@/types/threat-intel";

function ReliabilityCell({ reliability }: { reliability: SourceReliability | null }) {
  if (!reliability) return <span className="text-xs text-muted">—</span>;
  if (reliability.score === null) {
    return (
      <span className="text-xs text-muted" title={`Only ${reliability.trackedDays} day(s) of history recorded so far`}>
        Building history…
      </span>
    );
  }

  const variant = reliability.score >= 95 ? "low" : reliability.score >= 80 ? "medium" : "critical";
  return (
    <span className="flex items-center gap-1.5">
      <Badge variant={variant}>{reliability.score}%</Badge>
      <span className="text-[11px] text-muted">/ {reliability.trackedDays}d</span>
    </span>
  );
}

export function SourcesHealthPanel() {
  const { sources, onlineCount, totalCount } = useSourcesHealth();

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base font-semibold text-foreground">
          Feed Health{" "}
          <span className="text-muted" title="Reliability = % of tracked days a source's scheduled sync came back online, recorded once per calendar day">
            ({onlineCount}/{totalCount} sources online)
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHead>
            <TableRow>
              <TableHeaderCell>Source</TableHeaderCell>
              <TableHeaderCell>Status</TableHeaderCell>
              <TableHeaderCell>Reliability</TableHeaderCell>
              <TableHeaderCell>Last Synchronized</TableHeaderCell>
              <TableHeaderCell>Detail</TableHeaderCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {sources.map((s) => (
              <TableRow key={s.key}>
                <TableCell className="font-medium">{s.label}</TableCell>
                <TableCell>
                  <Badge variant={s.online ? "success" : "danger"}>{s.online ? "Online" : "Offline"}</Badge>
                </TableCell>
                <TableCell>
                  <ReliabilityCell reliability={s.reliability} />
                </TableCell>
                <TableCell className="whitespace-nowrap text-muted">
                  {s.lastSynchronized ? new Date(s.lastSynchronized).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" }) : "—"}
                </TableCell>
                <TableCell className="max-w-md text-xs text-muted">{s.error ?? "—"}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}
