import { Badge } from "@/components/ui/badge";
import type { Severity } from "@/types/threat-intel";

const VARIANT_BY_SEVERITY: Record<Severity, "critical" | "high" | "medium" | "low" | "muted"> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  UNKNOWN: "muted",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <Badge variant={VARIANT_BY_SEVERITY[severity]}>{severity}</Badge>;
}
