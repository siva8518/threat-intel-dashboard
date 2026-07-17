import { useMemo, useState } from "react";
import { ExternalLink, Pencil } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeaderCell, TableRow } from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { SeverityBadge } from "./SeverityBadge";
import { ErrorState, EmptyState } from "./ErrorState";
import { useRemediationQueue } from "@/hooks/useRemediationQueue";
import { useSelection } from "@/context/SelectionContext";
import type { RemediationQueueItem, RemediationStatus } from "@/types/threat-intel";
import { cn } from "@/lib/utils";

const STATUS_FILTERS: Array<RemediationStatus | "all"> = ["all", "pending", "patched", "mitigated", "risk_accepted"];

const STATUS_LABEL: Record<RemediationStatus, string> = {
  pending: "Pending",
  patched: "Patched",
  mitigated: "Mitigated",
  risk_accepted: "Risk Accepted",
};

const STATUS_BADGE: Record<RemediationStatus, "muted" | "success" | "medium" | "cyan"> = {
  pending: "muted",
  patched: "success",
  mitigated: "medium",
  risk_accepted: "cyan",
};

function urgencyColor(score: number) {
  if (score >= 70) return "text-critical";
  if (score >= 45) return "text-high";
  if (score >= 20) return "text-medium";
  return "text-low";
}

function PatchInfoCell({ item }: { item: RemediationQueueItem }) {
  if (!item.patchInfo) {
    return <span className="text-xs text-muted">Not yet analyzed</span>;
  }
  const { availability, fixedVersions, temporaryMitigations } = item.patchInfo;
  return (
    <div className="max-w-xs text-xs">
      <p className="font-medium text-foreground">{availability === "Not Reported" ? "Availability not reported" : availability}</p>
      {fixedVersions.length > 0 && <p className="mt-0.5 text-muted">Fixed in: {fixedVersions.slice(0, 2).join(", ")}</p>}
      {fixedVersions.length === 0 && temporaryMitigations.length > 0 && (
        <p className="mt-0.5 text-muted">Mitigation: {temporaryMitigations[0].slice(0, 80)}</p>
      )}
    </div>
  );
}

/**
 * The one workflow this app couldn't previously support end-to-end for a VM
 * team: not just "here's a CVE list" (Latest CVEs already does that) but
 * "here's what to patch first, and here's whether we already have." Reuses
 * the exact CVE records Latest CVEs shows, re-ranked by a deterministic
 * urgency score (server/remediationQueue.js), enriched with patch guidance
 * from AI Summarization when available, and paired with a status this app
 * has no other way to know -- an org's own remediation state -- tracked
 * here rather than in a spreadsheet next to this dashboard.
 */
export function RemediationTracker() {
  const { items, ready, isLoading, isError, error, setStatus, clearStatus, isUpdating } = useRemediationQueue();
  const [statusFilter, setStatusFilter] = useState<RemediationStatus | "all">("all");
  const [editingId, setEditingId] = useState<string | null>(null);
  const [noteDraft, setNoteDraft] = useState("");
  const { selectCve } = useSelection();

  const counts = useMemo(() => {
    const c: Record<RemediationStatus, number> = { pending: 0, patched: 0, mitigated: 0, risk_accepted: 0 };
    for (const item of items) c[item.status] += 1;
    return c;
  }, [items]);

  const filtered = useMemo(() => (statusFilter === "all" ? items : items.filter((i) => i.status === statusFilter)), [items, statusFilter]);

  function startEditingNote(item: RemediationQueueItem) {
    setEditingId(item.id);
    setNoteDraft(item.note ?? "");
  }

  async function saveNote(item: RemediationQueueItem) {
    await setStatus({ cveId: item.id, status: item.status, note: noteDraft });
    setEditingId(null);
  }

  async function changeStatus(item: RemediationQueueItem, status: RemediationStatus) {
    if (status === "pending" && item.note === null) {
      await clearStatus(item.id);
    } else {
      await setStatus({ cveId: item.id, status, note: item.note });
    }
  }

  return (
    <Card>
      <CardHeader className="flex-col items-start gap-3 md:flex-row md:items-center">
        <div>
          <CardTitle className="text-base font-semibold text-foreground">Vulnerabilities Remediation Tracker</CardTitle>
          <p className="mt-1 text-xs text-muted">
            The same CVEs Latest CVEs shows, ranked by a transparent urgency score (KEV + EPSS + CVSS) instead of publish date -- so Vulnerability
            Management gets a prioritized patch queue, not a flat list, and can track what's actually been remediated.
          </p>
        </div>
      </CardHeader>
      <CardContent>
        <div className="mb-3 flex flex-wrap gap-1.5">
          {STATUS_FILTERS.map((s) => (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              className={cn(
                "rounded-lg px-2.5 py-1 text-xs font-medium transition-colors",
                statusFilter === s ? "bg-gradient-primary text-white shadow-glow-primary" : "border border-white/10 bg-white/[0.03] text-muted hover:text-foreground",
              )}
            >
              {s === "all" ? `All (${items.length})` : `${STATUS_LABEL[s]} (${counts[s]})`}
            </button>
          ))}
        </div>

        {isLoading ? (
          <div className="space-y-2">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        ) : isError ? (
          <ErrorState message={(error as Error)?.message ?? "The Vulnerabilities Remediation Tracker is unavailable right now."} />
        ) : !ready ? (
          <EmptyState message="NVD data is still syncing -- check back shortly." />
        ) : filtered.length === 0 ? (
          <EmptyState message={items.length === 0 ? "No CVEs available yet." : "No CVEs match this status filter."} />
        ) : (
          <Table>
            <TableHead>
              <TableRow>
                <TableHeaderCell>CVE ID</TableHeaderCell>
                <TableHeaderCell title="0-100, weighted from KEV status (40pts), EPSS exploitation probability (40pts), and CVSS severity (20pts)">
                  Urgency
                </TableHeaderCell>
                <TableHeaderCell>Severity</TableHeaderCell>
                <TableHeaderCell>Vendor / Product</TableHeaderCell>
                <TableHeaderCell>Patch Info</TableHeaderCell>
                <TableHeaderCell>Status</TableHeaderCell>
                <TableHeaderCell>Note</TableHeaderCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {filtered.map((item) => (
                <TableRow key={item.id}>
                  <TableCell className="font-mono text-xs">
                    <button onClick={() => selectCve(item)} className="flex items-center gap-1 text-primary hover:underline" title="View correlated profile">
                      {item.id}
                    </button>
                    {item.knownExploited && (
                      <Badge variant="danger" className="mt-1">
                        KEV
                      </Badge>
                    )}
                    <a
                      href={item.sourceUrl}
                      target="_blank"
                      rel="noreferrer"
                      className="mt-1 flex items-center gap-1 text-[11px] text-muted hover:text-foreground"
                    >
                      NVD <ExternalLink className="h-2.5 w-2.5" />
                    </a>
                  </TableCell>
                  <TableCell>
                    <span className={cn("font-mono text-sm font-semibold", urgencyColor(item.urgencyScore))}>{item.urgencyScore}</span>
                  </TableCell>
                  <TableCell>
                    <SeverityBadge severity={item.severity} />
                    <div className="mt-1 text-[11px] text-muted">
                      CVSS {item.cvssScore?.toFixed(1) ?? "—"} · EPSS {item.epssScore !== null ? `${(item.epssScore * 100).toFixed(0)}%` : "—"}
                    </div>
                  </TableCell>
                  <TableCell className="max-w-[10rem] truncate text-xs">
                    {item.vendor} / {item.product}
                  </TableCell>
                  <TableCell>
                    <PatchInfoCell item={item} />
                  </TableCell>
                  <TableCell>
                    <Select value={item.status} onChange={(e) => changeStatus(item, e.target.value as RemediationStatus)} className="text-xs">
                      {(Object.keys(STATUS_LABEL) as RemediationStatus[]).map((s) => (
                        <option key={s} value={s}>
                          {STATUS_LABEL[s]}
                        </option>
                      ))}
                    </Select>
                    <Badge variant={STATUS_BADGE[item.status]} className="mt-1">
                      {STATUS_LABEL[item.status]}
                    </Badge>
                  </TableCell>
                  <TableCell className="max-w-[12rem]">
                    {editingId === item.id ? (
                      <div className="flex flex-col gap-1.5">
                        <Input
                          autoFocus
                          value={noteDraft}
                          onChange={(e) => setNoteDraft(e.target.value)}
                          placeholder="e.g. Patched via KB5041 rollout, ticket VM-4821"
                          className="text-xs"
                        />
                        <div className="flex gap-1.5">
                          <Button type="button" size="sm" onClick={() => saveNote(item)} disabled={isUpdating}>
                            Save
                          </Button>
                          <Button type="button" size="sm" variant="outline" onClick={() => setEditingId(null)}>
                            Cancel
                          </Button>
                        </div>
                      </div>
                    ) : (
                      <button
                        type="button"
                        onClick={() => startEditingNote(item)}
                        className="flex items-start gap-1 text-left text-xs text-muted hover:text-foreground"
                      >
                        <Pencil className="mt-0.5 h-3 w-3 shrink-0" />
                        <span className="line-clamp-2">{item.note ?? "Add note"}</span>
                      </button>
                    )}
                    {item.statusUpdatedAt && <p className="mt-1 text-[10px] text-muted">Updated {new Date(item.statusUpdatedAt).toLocaleDateString()}</p>}
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
