import { motion } from "framer-motion";
import { ExternalLink, Siren, X } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { useFlashReports } from "@/hooks/useFlashReports";
import type { FlashReport, FlashReportSourceType } from "@/types/threat-intel";

const SOURCE_TYPE_LABEL: Record<FlashReportSourceType, string> = {
  news: "Security News",
  malware: "Malware Intelligence",
  actor: "Threat Actor Intelligence",
  campaign: "Campaign Intelligence",
  darkweb: "Dark Web Intelligence",
  ransomware: "Ransomware Leak Site",
};

interface FlashReportBannerProps {
  onOpenWatchlist: () => void;
}

/**
 * Dashboard-wide alert for watchlist matches (see server/watchlist.js +
 * server/watchlistScanner.js) -- mounted once in DashboardLayout so it's
 * visible no matter which tab is active, and stays up until each report is
 * explicitly opened or dismissed (not on a timer, not on tab navigation).
 * Shows the single most-recent unread match; "View all" opens the full
 * Watchlist tab for the rest.
 */
export function FlashReportBanner({ onOpenWatchlist }: FlashReportBannerProps) {
  const { reports, unreadCount, markRead } = useFlashReports();
  const unread = reports.filter((r) => !r.read);

  if (unread.length === 0) return null;

  const latest = unread[0];

  function openReport(report: FlashReport) {
    markRead(report.id);
    if (report.url) window.open(report.url, "_blank", "noopener,noreferrer");
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: -8 }}
      animate={{ opacity: 1, y: 0 }}
      className="mx-4 mt-3 overflow-hidden rounded-xl border border-critical/30 bg-critical/[0.08] md:mx-6"
    >
      <div className="flex flex-wrap items-center gap-3 px-4 py-2.5">
        <span className="relative flex h-2 w-2 shrink-0">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-critical opacity-75" />
          <span className="relative inline-flex h-2 w-2 rounded-full bg-critical" />
        </span>
        <Siren className="h-4 w-4 shrink-0 text-critical" />
        <span className="shrink-0 text-xs font-bold uppercase tracking-wider text-critical">
          Flash Report{unreadCount === 1 ? "" : "s"} ({unreadCount})
        </span>
        <button
          type="button"
          onClick={() => openReport(latest)}
          className="flex min-w-0 flex-1 items-center gap-1.5 text-left text-sm text-foreground hover:text-primary hover:underline"
        >
          <Badge variant="danger" className="shrink-0">
            {latest.keywordLabel}
          </Badge>
          <span className="truncate">
            mentioned in {SOURCE_TYPE_LABEL[latest.sourceType]} · {latest.title}
          </span>
          {latest.url && <ExternalLink className="h-3 w-3 shrink-0" />}
        </button>
        <div className="ml-auto flex shrink-0 items-center gap-3">
          {unreadCount > 1 && (
            <button type="button" onClick={onOpenWatchlist} className="text-xs font-medium text-critical hover:underline">
              View all {unreadCount}
            </button>
          )}
          <button
            type="button"
            onClick={() => markRead(latest.id)}
            aria-label="Dismiss this flash report"
            className="rounded-full p-1 text-critical/70 transition-colors hover:bg-critical/10 hover:text-critical"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>
    </motion.div>
  );
}
