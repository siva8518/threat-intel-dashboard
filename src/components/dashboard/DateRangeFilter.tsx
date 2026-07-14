import { CalendarDays, X } from "lucide-react";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

/** "" on either end means unbounded in that direction -- native date input value format (yyyy-mm-dd), which sorts/compares correctly as a plain string. */
export interface DateRange {
  from: string;
  to: string;
}

export const EMPTY_DATE_RANGE: DateRange = { from: "", to: "" };

/** True if `iso` (any ISO datetime/date string) falls within `range`, inclusive on both ends. An empty `from`/`to` leaves that side unbounded. */
export function isWithinDateRange(iso: string | null | undefined, range: DateRange) {
  if (!iso) return false;
  if (!range.from && !range.to) return true;
  const day = iso.slice(0, 10);
  if (range.from && day < range.from) return false;
  if (range.to && day > range.to) return false;
  return true;
}

interface DateRangeFilterProps {
  value: DateRange;
  onChange: (next: DateRange) => void;
  className?: string;
}

/**
 * A real calendar (native browser date picker, so "go back a month" or "go
 * back a year" is a few clicks, not a dropdown capped at a handful of
 * presets) for filtering anything with a date -- shared across the news feed
 * and every intelligence tab so "when was this active" is answered the same
 * way everywhere.
 */
export function DateRangeFilter({ value, onChange, className }: DateRangeFilterProps) {
  const isActive = Boolean(value.from || value.to);
  return (
    <div className={cn("flex flex-wrap items-center gap-1.5", className)}>
      <CalendarDays className="h-3.5 w-3.5 shrink-0 text-muted" />
      <Input
        type="date"
        aria-label="From date"
        value={value.from}
        max={value.to || undefined}
        onChange={(e) => onChange({ ...value, from: e.target.value })}
        style={{ colorScheme: "dark" }}
        className="w-[9.5rem]"
      />
      <span className="text-xs text-muted">to</span>
      <Input
        type="date"
        aria-label="To date"
        value={value.to}
        min={value.from || undefined}
        onChange={(e) => onChange({ ...value, to: e.target.value })}
        style={{ colorScheme: "dark" }}
        className="w-[9.5rem]"
      />
      {isActive && (
        <button
          type="button"
          onClick={() => onChange(EMPTY_DATE_RANGE)}
          aria-label="Clear date filter"
          className="flex items-center gap-1 rounded-lg border border-white/10 bg-white/[0.03] px-2 py-1.5 text-xs text-muted transition-colors hover:text-foreground"
        >
          <X className="h-3 w-3" />
          Clear
        </button>
      )}
    </div>
  );
}
