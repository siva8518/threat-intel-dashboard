import { Bar, BarChart, CartesianGrid, LabelList, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

export interface ChartDatum {
  name: string;
  count: number;
  detail: string;
  onOpen?: () => void;
}

// Single tooltip shared by every ranked bar chart in the dashboard -- one
// series per chart (a plain count), so no legend/color-key is needed per the
// dataviz sequential-form rule; the tooltip is the only place the fuller
// (technique name / sources / vendor) detail shows up.
function ChartTooltip({ active, payload }: { active?: boolean; payload?: Array<{ payload: ChartDatum }> }) {
  if (!active || !payload || payload.length === 0) return null;
  const item = payload[0].payload;
  return (
    <div className="rounded-lg border border-white/10 bg-surface px-2.5 py-1.5 text-xs shadow-glass">
      <p className="font-mono font-semibold text-foreground">{item.name}</p>
      <p className="text-muted">{item.detail}</p>
      <p className="text-foreground">{item.count} observed</p>
    </div>
  );
}

// A label that won't fit doesn't get clipped -- measure first (see the
// dataviz skill's label guidance). A fixed axis width worked for short
// technique IDs (T1071.001) but silently truncated longer names from the
// left (CVE-2026-34486 rendered as "-2026-34486", or worse) once this
// component started getting reused for CVE IDs and actor names too. JetBrains
// Mono at 11px runs ~6.6px/char; sized off the longest label actually in
// this chart's data, clamped so a single long outlier can't blow out the
// whole axis.
function yAxisWidth(data: ChartDatum[]) {
  const longest = data.reduce((max, d) => Math.max(max, d.name.length), 0);
  return Math.min(140, Math.max(60, Math.ceil(longest * 6.6) + 16));
}

const AXIS_STYLE = { fill: "#8d93ac", fontSize: 11 };
const CATEGORY_AXIS_STYLE = { fill: "#eef0fa", fontSize: 11, fontFamily: "JetBrains Mono, monospace" };

/**
 * Ranked magnitude chart, single sequential hue, value direct-labeled at the
 * bar's end (see the dataviz skill: a magnitude ranking of one series never
 * needs more than one hue or a legend). Bars with an `onOpen` handler are
 * clickable through to the underlying record's detail view.
 *
 * `orientation="horizontal"` (default): bars ≤24px thick, 4px rounded at the
 * tip. `orientation="vertical"`: columns, 4px rounded at the top -- used
 * where the category names are short enough to sit under a column (e.g.
 * malware family names) rather than needing room to read beside a bar.
 */
export function RankedBarChart({ data, hue, orientation = "horizontal" }: { data: ChartDatum[]; hue: string; orientation?: "horizontal" | "vertical" }) {
  const clickable = data.some((d) => d.onOpen);

  if (orientation === "vertical") {
    return (
      <ResponsiveContainer width="100%" height={240}>
        <BarChart data={data} margin={{ top: 20, right: 8, bottom: 24, left: 8 }}>
          <CartesianGrid vertical={false} stroke="#232841" />
          <XAxis
            dataKey="name"
            stroke="#8d93ac"
            tick={CATEGORY_AXIS_STYLE}
            axisLine={false}
            tickLine={false}
            interval={0}
            angle={-30}
            textAnchor="end"
            height={44}
          />
          <YAxis type="number" allowDecimals={false} stroke="#8d93ac" tick={AXIS_STYLE} axisLine={false} tickLine={false} width={32} />
          <Tooltip content={<ChartTooltip />} cursor={{ fill: "rgba(255,255,255,0.03)" }} />
          <Bar dataKey="count" fill={hue} radius={[4, 4, 0, 0]} maxBarSize={36} onClick={(entry: ChartDatum) => entry.onOpen?.()} className={clickable ? "cursor-pointer" : undefined}>
            <LabelList dataKey="count" position="top" fill="#eef0fa" fontSize={11} />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={Math.max(160, data.length * 30)}>
      <BarChart data={data} layout="vertical" margin={{ top: 4, right: 32, bottom: 4, left: 4 }}>
        <CartesianGrid horizontal={false} stroke="#232841" />
        <XAxis type="number" allowDecimals={false} stroke="#8d93ac" tick={AXIS_STYLE} axisLine={false} tickLine={false} />
        <YAxis type="category" dataKey="name" stroke="#8d93ac" tick={CATEGORY_AXIS_STYLE} axisLine={false} tickLine={false} width={yAxisWidth(data)} />
        <Tooltip content={<ChartTooltip />} cursor={{ fill: "rgba(255,255,255,0.03)" }} />
        <Bar dataKey="count" fill={hue} radius={[0, 4, 4, 0]} maxBarSize={18} onClick={(entry: ChartDatum) => entry.onOpen?.()} className={clickable ? "cursor-pointer" : undefined}>
          <LabelList dataKey="count" position="right" fill="#eef0fa" fontSize={11} />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
