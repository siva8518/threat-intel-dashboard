// Shared presentational primitives for rendering structured report data --
// extracted from AiSummarization.tsx (where these first shipped) so the
// Intelligence Investigation Console can reuse the exact same look instead
// of growing its own second copy.
import type { ReactNode } from "react";

export function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div>
      {title && <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-muted">{title}</h4>}
      {children}
    </div>
  );
}

export function FieldList({ title, items }: { title: string; items: string[] }) {
  if (items.length === 0) return null;
  return (
    <Section title={title}>
      <ul className="list-disc space-y-1 pl-4 text-sm text-foreground">
        {items.map((item, i) => (
          <li key={i}>{item}</li>
        ))}
      </ul>
    </Section>
  );
}

/** label: value pairs where value is a plain string, skipping "Not Reported" entries so the card isn't padded with filler. */
export function KeyValueBlock({ title, pairs }: { title: string; pairs: Array<[string, string | null]> }) {
  const shown = pairs.filter(([, v]) => v && v !== "Not Reported");
  if (shown.length === 0) return null;
  return (
    <Section title={title}>
      <dl className="space-y-1.5 text-sm">
        {shown.map(([label, value]) => (
          <div key={label}>
            <dt className="inline font-semibold text-foreground">{label}: </dt>
            <dd className="inline text-foreground">{value}</dd>
          </div>
        ))}
      </dl>
    </Section>
  );
}

export function GroupedLists({ title, groups }: { title: string; groups: Array<[string, string[]]> }) {
  const nonEmpty = groups.filter(([, items]) => items.length > 0);
  if (nonEmpty.length === 0) return null;
  return (
    <Section title={title}>
      <div className="space-y-2.5">
        {nonEmpty.map(([label, items]) => (
          <div key={label}>
            <div className="mb-1 text-xs font-semibold text-foreground">{label}</div>
            <ul className="list-disc space-y-1 pl-4 text-sm text-foreground">
              {items.map((item, i) => (
                <li key={i}>{item}</li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </Section>
  );
}
