import { AnimatePresence, motion } from "framer-motion";
import { ExternalLink, Flame } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { useSecurityNews } from "@/hooks/useSecurityNews";
import type { NewsItem, NewsSeverity } from "@/types/threat-intel";

export const SEVERITY_STYLE: Record<NewsSeverity, { variant: "critical" | "high" | "medium" | "low"; label: string }> = {
  critical: { variant: "critical", label: "Critical" },
  high: { variant: "high", label: "High" },
  medium: { variant: "medium", label: "Medium" },
  low: { variant: "low", label: "Low" },
};

/** Critical/high severity headlines from the last 6 hours across all merged news sources -- shared by DailySummary.tsx (Overview) and SecurityNews.tsx, so both surfaces agree on exactly what counts as "breaking." */
export function useBreakingNews() {
  const { items } = useSecurityNews();
  return items.filter((i) => i.isBreaking && (i.severity === "critical" || i.severity === "high"));
}

/** Same-shape strip used standalone at the top of Security News and, folded into DailySummary's card, on the Overview tab. */
export function BreakingNewsStrip({ items }: { items: NewsItem[] }) {
  if (items.length === 0) return null;
  return (
    <motion.div
      initial={{ opacity: 0, y: -8 }}
      animate={{ opacity: 1, y: 0 }}
      className="mb-4 overflow-hidden rounded-xl border border-critical/30 bg-critical/[0.06]"
    >
      <div className="flex items-center gap-2 border-b border-critical/20 px-4 py-2">
        <span className="relative flex h-2 w-2">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-critical opacity-75" />
          <span className="relative inline-flex h-2 w-2 rounded-full bg-critical" />
        </span>
        <Flame className="h-3.5 w-3.5 text-critical" />
        <span className="text-xs font-bold uppercase tracking-wider text-critical">Breaking · Last 6 Hours</span>
      </div>
      <ul className="divide-y divide-critical/10 px-4">
        <AnimatePresence initial={false}>
          {items.slice(0, 6).map((item) => (
            <motion.li key={item.id} initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0 }} className="py-2">
              <div className="flex items-center justify-between gap-3">
                <a
                  href={item.link}
                  target="_blank"
                  rel="noreferrer"
                  className="flex min-w-0 items-center gap-1.5 text-sm font-medium text-foreground hover:text-primary hover:underline"
                >
                  <span className="truncate">{item.title}</span>
                  <ExternalLink className="h-3 w-3 shrink-0" />
                </a>
                <Badge variant={SEVERITY_STYLE[item.severity].variant} className="shrink-0">
                  {SEVERITY_STYLE[item.severity].label}
                </Badge>
              </div>
            </motion.li>
          ))}
        </AnimatePresence>
      </ul>
    </motion.div>
  );
}
