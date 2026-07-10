import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeaderCell, TableRow } from "@/components/ui/table";
import { useSourcesHealth } from "@/hooks/useSourcesHealth";

export function SourcesHealthPanel() {
  const { sources, onlineCount, totalCount } = useSourcesHealth();

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base font-semibold text-foreground">
          Feed Health <span className="text-muted">({onlineCount}/{totalCount} sources online)</span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHead>
            <TableRow>
              <TableHeaderCell>Source</TableHeaderCell>
              <TableHeaderCell>Status</TableHeaderCell>
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
