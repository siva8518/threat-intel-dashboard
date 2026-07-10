import type { LucideIcon } from "lucide-react";
import { motion } from "framer-motion";
import { cn } from "@/lib/utils";

export interface TabItem {
  id: string;
  label: string;
  icon: LucideIcon;
}

interface TopTabsProps {
  tabs: readonly TabItem[];
  activeTab: string;
  onChange: (id: string) => void;
}

/**
 * Horizontal, click-to-switch section navigation. Only the active tab's
 * content is rendered by the parent (DashboardPage) -- this replaced a
 * vertical sidebar that just scrolled the page to an anchor, which meant
 * every section was always stacked on one long page.
 */
export function TopTabs({ tabs, activeTab, onChange }: TopTabsProps) {
  return (
    <nav className="sticky top-[57px] z-30 flex flex-wrap gap-1 border-b border-white/[0.06] bg-background/70 px-4 py-2.5 backdrop-blur-xl">
      {tabs.map(({ id, label, icon: Icon }) => {
        const isActive = id === activeTab;
        return (
          <button
            key={id}
            type="button"
            onClick={() => onChange(id)}
            aria-current={isActive ? "page" : undefined}
            className={cn(
              "relative flex items-center gap-1.5 whitespace-nowrap rounded-lg px-3 py-1.5 text-sm font-medium transition-colors",
              isActive ? "text-white" : "text-muted hover:text-foreground",
            )}
          >
            {isActive && (
              <motion.span
                layoutId="active-tab-pill"
                transition={{ type: "spring", stiffness: 500, damping: 40 }}
                className="absolute inset-0 rounded-lg bg-gradient-primary shadow-glow-primary"
              />
            )}
            <Icon className="relative h-4 w-4" />
            <span className="relative">{label}</span>
          </button>
        );
      })}
    </nav>
  );
}
