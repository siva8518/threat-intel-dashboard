import { Children, useEffect, useMemo, useRef, useState, type ReactElement, type ReactNode } from "react";
import { ChevronDown } from "lucide-react";
import { cn } from "@/lib/utils";

interface OptionProps {
  value: string | number;
  children: ReactNode;
}

interface SelectProps {
  value: string | number;
  onChange: (e: { target: { value: string } }) => void;
  className?: string;
  children: ReactNode;
}

/**
 * Custom dropdown, not a native <select>. A native <select>'s open popup is
 * drawn by the OS, not the page -- confirmed live that on Windows, Chrome
 * themes that popup off the system light/dark setting, not this page's CSS
 * (`color-scheme: dark` and solid option colors both had no effect). Building
 * the popup as regular DOM content sidesteps that entirely, at the cost of
 * reimplementing basic listbox behavior (click-outside/Escape to close, no
 * native keyboard type-ahead). Kept API-compatible with the native version
 * (`value`/`onChange(e.target.value)`/`<option>` children) so no call site
 * that used the old native <select> needed to change.
 */
export function Select({ value, onChange, className, children }: SelectProps) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);

  const options = useMemo(
    () =>
      Children.toArray(children)
        .filter((child): child is ReactElement<OptionProps> => typeof child === "object" && "props" in child)
        .map((child) => ({ value: String(child.props.value), label: child.props.children })),
    [children],
  );

  const selectedLabel = options.find((o) => o.value === String(value))?.label ?? options[0]?.label;

  useEffect(() => {
    if (!open) return;
    function onPointerDown(e: PointerEvent) {
      if (!rootRef.current?.contains(e.target as Node)) setOpen(false);
    }
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);

  return (
    <div ref={rootRef} className={cn("relative", className)}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex h-9 w-full items-center justify-between gap-2 rounded-lg border border-white/10 bg-surface px-2.5 text-sm text-foreground transition-colors focus-visible:outline-none focus-visible:border-primary/50 focus-visible:ring-2 focus-visible:ring-primary/20"
      >
        <span className="truncate">{selectedLabel}</span>
        <ChevronDown className={cn("h-3.5 w-3.5 shrink-0 text-muted transition-transform", open && "rotate-180")} />
      </button>
      {open && (
        <div className="glass-panel absolute left-0 top-[calc(100%+6px)] z-50 max-h-64 w-full min-w-max overflow-y-auto bg-surface p-1 shadow-popover">
          {options.map((o) => (
            <button
              key={o.value}
              type="button"
              onClick={() => {
                onChange({ target: { value: o.value } });
                setOpen(false);
              }}
              className={cn(
                "flex w-full items-center rounded-lg px-3 py-2 text-left text-sm transition-colors hover:bg-white/[0.08]",
                String(value) === o.value ? "bg-primary/15 text-[#b8adff]" : "text-foreground",
              )}
            >
              {o.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
