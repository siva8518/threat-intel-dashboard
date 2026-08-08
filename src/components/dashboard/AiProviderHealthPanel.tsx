import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeaderCell, TableRow } from "@/components/ui/table";
import { useAiProviderHealth } from "@/hooks/useAiProviderHealth";
import type { AiProviderHealth } from "@/types/threat-intel";

const STATUS_VARIANT: Record<AiProviderHealth["status"], "success" | "medium" | "danger" | "muted"> = {
  healthy: "success",
  cooldown: "medium",
  misconfigured: "danger",
  unconfigured: "muted",
};

export function AiProviderHealthPanel() {
  const { providers, usage } = useAiProviderHealth();
  const configuredCount = providers.filter((p) => p.configured).length;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base font-semibold text-foreground">
          AI Provider Health{" "}
          <span className="text-muted" title="The fallback chain this platform walks for every AI-assisted narrative -- deterministic evidence/correlation/verdicts never depend on any of this">
            ({configuredCount}/{providers.length} providers configured)
          </span>
        </CardTitle>
        {usage && (
          <p className="mt-1 text-xs text-muted">
            {usage.totalRequests} request(s) this session -- {usage.totalSuccess} succeeded, {usage.totalFailure} failed, {usage.cacheHits} served from cache, {usage.totalTokens.toLocaleString()} token(s) total.
          </p>
        )}
      </CardHeader>
      <CardContent>
        <Table>
          <TableHead>
            <TableRow>
              <TableHeaderCell>Provider</TableHeaderCell>
              <TableHeaderCell>Model</TableHeaderCell>
              <TableHeaderCell>Status</TableHeaderCell>
              <TableHeaderCell>Success Rate</TableHeaderCell>
              <TableHeaderCell>Avg Latency</TableHeaderCell>
              <TableHeaderCell>Requests</TableHeaderCell>
              <TableHeaderCell>Last Failure</TableHeaderCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {providers.map((p) => (
              <TableRow key={p.label}>
                <TableCell className="font-medium">{p.label}</TableCell>
                <TableCell className="max-w-[220px] truncate font-mono text-xs text-muted" title={p.model}>
                  {p.model}
                </TableCell>
                <TableCell>
                  <Badge variant={STATUS_VARIANT[p.status]}>{p.statusLabel}</Badge>
                </TableCell>
                <TableCell className="text-muted">{p.successRate === null ? "—" : `${p.successRate}%`}</TableCell>
                <TableCell className="text-muted">{p.avgLatencyMs === null ? "—" : `${(p.avgLatencyMs / 1000).toFixed(1)}s`}</TableCell>
                <TableCell className="text-muted">
                  {p.totalSuccess + p.totalFailure > 0 ? `${p.totalSuccess}✓ / ${p.totalFailure}✗` : "—"}
                </TableCell>
                <TableCell className="max-w-xs text-xs text-muted">{p.lastFailureReason ?? "—"}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}
