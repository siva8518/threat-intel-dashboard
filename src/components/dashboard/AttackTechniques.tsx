import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeaderCell, TableRow } from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "./ErrorState";
import { useAttackTechniques } from "@/hooks/useAttackTechniques";

export function AttackTechniques() {
  const { data, isLoading, isError, error } = useAttackTechniques();

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base font-semibold text-foreground">
          MITRE ATT&amp;CK Techniques Observed{" "}
          <span
            className="text-muted"
            title="Derived from a curated malware-to-technique map plus techniques automatically extracted from news article text -- not a live telemetry feed"
          >
            (best-effort, see tooltip)
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="space-y-2">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className="h-8 w-full" />
            ))}
          </div>
        ) : isError ? (
          <ErrorState message={(error as Error).message} />
        ) : !data || data.length === 0 ? (
          <EmptyState message="No techniques could be associated with the current threat feed." />
        ) : (
          <Table>
            <TableHead>
              <TableRow>
                <TableHeaderCell>Technique</TableHeaderCell>
                <TableHeaderCell>Tactic</TableHeaderCell>
                <TableHeaderCell>Observed</TableHeaderCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {data.map((technique) => (
                <TableRow key={technique.id}>
                  <TableCell>
                    <a href={technique.url} target="_blank" rel="noreferrer" className="text-primary hover:underline">
                      {technique.id} {technique.name}
                    </a>
                  </TableCell>
                  <TableCell className="capitalize">{technique.tactic}</TableCell>
                  <TableCell>
                    <Badge variant="default">{technique.observedCount}</Badge>
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
