import { createContext, useContext, useMemo, useState, type ReactNode } from "react";
import type { CveRecord, TrendingMalwareEntry } from "@/types/threat-intel";

interface SelectionContextValue {
  selectedCve: CveRecord | null;
  selectedMalware: TrendingMalwareEntry | null;
  selectCve: (cve: CveRecord) => void;
  selectMalware: (entry: TrendingMalwareEntry) => void;
  clearSelection: () => void;
}

const SelectionContext = createContext<SelectionContextValue | null>(null);

/**
 * Shared "what's currently selected" state so clicking a CVE or malware
 * family anywhere in the dashboard opens the same detail drawer, instead of
 * each widget owning its own local selection state. Only one drawer is ever
 * open at a time -- selecting one kind clears the other. Stores the already-
 * fetched row object (not just an id) so the drawer can render its summary
 * instantly while it separately fetches the deeper cross-reference profile.
 */
export function SelectionProvider({ children }: { children: ReactNode }) {
  const [selectedCve, setSelectedCve] = useState<CveRecord | null>(null);
  const [selectedMalware, setSelectedMalware] = useState<TrendingMalwareEntry | null>(null);

  const value = useMemo<SelectionContextValue>(
    () => ({
      selectedCve,
      selectedMalware,
      selectCve: (cve) => {
        setSelectedMalware(null);
        setSelectedCve(cve);
      },
      selectMalware: (entry) => {
        setSelectedCve(null);
        setSelectedMalware(entry);
      },
      clearSelection: () => {
        setSelectedCve(null);
        setSelectedMalware(null);
      },
    }),
    [selectedCve, selectedMalware],
  );

  return <SelectionContext.Provider value={value}>{children}</SelectionContext.Provider>;
}

export function useSelection() {
  const ctx = useContext(SelectionContext);
  if (!ctx) throw new Error("useSelection must be used within a SelectionProvider");
  return ctx;
}
