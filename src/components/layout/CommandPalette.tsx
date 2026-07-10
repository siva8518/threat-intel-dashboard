import { Search } from "lucide-react";
import { AnimatePresence, motion } from "framer-motion";
import { Command } from "cmdk";
import type { TabItem } from "./TopTabs";

interface CommandPaletteProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  tabs: readonly TabItem[];
  onNavigate: (id: string) => void;
}

/**
 * Floating Cmd/Ctrl+K palette for jumping straight to a section without
 * hunting through the tab bar. Built on cmdk (fuzzy list/keyboard nav) inside
 * a hand-rolled Framer Motion overlay rather than cmdk's own <Command.Dialog>
 * (a Radix Dialog under the hood) -- that unmounts instantly on close, which
 * would skip the exit animation entirely.
 */
export function CommandPalette({ open, onOpenChange, tabs, onNavigate }: CommandPaletteProps) {
  function go(id: string) {
    onNavigate(id);
    onOpenChange(false);
  }

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.15 }}
          className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 pt-[14vh] backdrop-blur-sm"
          onClick={() => onOpenChange(false)}
        >
          <motion.div
            initial={{ opacity: 0, y: -12, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -8, scale: 0.98 }}
            transition={{ duration: 0.18, ease: [0.16, 1, 0.3, 1] }}
            onClick={(e) => e.stopPropagation()}
            className="glass-panel w-full max-w-lg overflow-hidden shadow-popover"
          >
            <Command filter={(value, search) => (value.toLowerCase().includes(search.toLowerCase()) ? 1 : 0)}>
              <div className="flex items-center gap-2 border-b border-white/[0.06] px-4">
                <Search className="h-4 w-4 shrink-0 text-muted" />
                <Command.Input
                  autoFocus
                  placeholder="Jump to a section…"
                  className="h-12 w-full bg-transparent text-sm text-foreground outline-none placeholder:text-muted/60"
                />
                <kbd className="shrink-0 rounded border border-white/10 bg-white/5 px-1.5 py-0.5 text-[10px] text-muted">
                  ESC
                </kbd>
              </div>
              <Command.List className="max-h-80 overflow-y-auto p-2">
                <Command.Empty className="py-8 text-center text-sm text-muted">No matching section.</Command.Empty>
                <Command.Group
                  heading="Navigate"
                  className="px-2 py-1 text-[11px] font-semibold uppercase tracking-wider text-muted/60 [&_[cmdk-group-items]]:mt-1"
                >
                  {tabs.map(({ id, label, icon: Icon }) => (
                    <Command.Item
                      key={id}
                      value={label}
                      onSelect={() => go(id)}
                      className="flex cursor-pointer items-center gap-2.5 rounded-lg px-3 py-2.5 text-sm text-foreground transition-colors data-[selected=true]:bg-white/[0.08]"
                    >
                      <Icon className="h-4 w-4 text-primary" />
                      {label}
                    </Command.Item>
                  ))}
                </Command.Group>
              </Command.List>
            </Command>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
