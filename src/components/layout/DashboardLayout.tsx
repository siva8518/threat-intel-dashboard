import { useEffect, useState, type ReactNode } from "react";
import { motion } from "framer-motion";
import { Topbar } from "./Topbar";
import { TopTabs, type TabItem } from "./TopTabs";
import { CommandPalette } from "./CommandPalette";
import { FlashReportBanner } from "../dashboard/FlashReportBanner";

interface DashboardLayoutProps {
  tabs: readonly TabItem[];
  activeTab: string;
  onTabChange: (id: string) => void;
  /** Called when the platform search palette's user picks a threat-actor result -- see CommandPalette.tsx. */
  onSelectActor: (name: string) => void;
  children: ReactNode;
}

export function DashboardLayout({ tabs, activeTab, onTabChange, onSelectActor, children }: DashboardLayoutProps) {
  const [paletteOpen, setPaletteOpen] = useState(false);

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if ((e.key === "k" || e.key === "K") && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);

  return (
    <div className="flex min-h-screen flex-col">
      <Topbar onOpenPalette={() => setPaletteOpen(true)} />
      <TopTabs tabs={tabs} activeTab={activeTab} onChange={onTabChange} />
      <FlashReportBanner onOpenWatchlist={() => onTabChange("watchlist")} />
      <main className="flex-1 p-4 md:p-6">
        {/*
          Deliberately no AnimatePresence here -- with mode="wait" it never
          completed the exit phase for this tree in testing (confirmed live:
          the active tab pill updated correctly but the rendered content
          stayed frozen on the previous tab indefinitely), so tab switching
          silently broke. A keyed enter-only fade still gives each tab switch
          a smooth transition without that failure mode.
        */}
        <motion.div
          key={activeTab}
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
          className="space-y-6"
        >
          {children}
        </motion.div>
      </main>
      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} tabs={tabs} onNavigate={onTabChange} onSelectActor={onSelectActor} />
    </div>
  );
}
