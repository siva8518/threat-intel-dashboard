import type { CorrelationCard } from "@/types/threat-intel";

// Radial node-link view of one correlation cluster -- same underlying data
// as the card list in CorrelationEngine.tsx, just visualized as a graph
// instead of grouped text lists. Capped per category (not the full arrays
// the text view shows) so the layout stays readable: a cluster can carry up
// to a dozen+ IOCs/techniques, which would turn a radial diagram into an
// unreadable hairball well before it added any insight over the list view.
const SIZE = 240;
const CENTER = SIZE / 2;
const HUB_RADIUS = 10;
const NODE_RADIUS = 7;
const SPOKE_RADIUS = 92;
const MAX_PER_CATEGORY = { actors: 4, malware: 4, cves: 5, iocs: 4 };

type NodeCategory = "actor" | "malware" | "cve" | "ioc";

interface GraphNode {
  id: string;
  label: string;
  category: NodeCategory;
  highlighted?: boolean; // KEV-flagged CVE
  onClick?: () => void;
}

const CATEGORY_COLOR: Record<NodeCategory, string> = {
  actor: "#fb3f5e", // critical
  malware: "#f7913d", // high
  cve: "#b8adff", // primary
  ioc: "#22d3ee", // accent-cyan
};

function truncate(label: string, max = 14) {
  return label.length > max ? `${label.slice(0, max - 1)}…` : label;
}

function buildNodes(card: CorrelationCard, onSelectMalware: (family: string) => void, onSelectCve: (cveId: string) => void): GraphNode[] {
  const nodes: GraphNode[] = [];

  for (const actor of card.actors.slice(0, MAX_PER_CATEGORY.actors)) {
    nodes.push({ id: `actor:${actor}`, label: actor, category: "actor" });
  }
  for (const family of card.malware.slice(0, MAX_PER_CATEGORY.malware)) {
    nodes.push({ id: `malware:${family}`, label: family, category: "malware", onClick: () => onSelectMalware(family) });
  }
  // KEV-flagged CVEs first -- correlateCves/buildCorrelationClusters already
  // sorts card.cves this way, so slicing here keeps the most notable ones.
  for (const cve of card.cves.slice(0, MAX_PER_CATEGORY.cves)) {
    nodes.push({ id: `cve:${cve.id}`, label: cve.id, category: "cve", highlighted: cve.knownExploited, onClick: () => onSelectCve(cve.id) });
  }
  for (const ioc of card.iocs.slice(0, MAX_PER_CATEGORY.iocs)) {
    nodes.push({ id: `ioc:${ioc.indicator}`, label: ioc.indicator, category: "ioc" });
  }

  return nodes;
}

export function CorrelationGraph({
  card,
  onSelectMalware,
  onSelectCve,
}: {
  card: CorrelationCard;
  onSelectMalware: (family: string) => void;
  onSelectCve: (cveId: string) => void;
}) {
  const nodes = buildNodes(card, onSelectMalware, onSelectCve);
  const hiddenCount =
    Math.max(0, card.actors.length - MAX_PER_CATEGORY.actors) +
    Math.max(0, card.malware.length - MAX_PER_CATEGORY.malware) +
    Math.max(0, card.cves.length - MAX_PER_CATEGORY.cves) +
    Math.max(0, card.iocs.length - MAX_PER_CATEGORY.iocs);

  if (nodes.length === 0) {
    return <p className="p-4 text-center text-xs text-muted">Not enough linked entities to graph.</p>;
  }

  return (
    <div className="flex flex-col items-center gap-2 p-2">
      <svg viewBox={`0 0 ${SIZE} ${SIZE}`} className="h-56 w-56">
        {nodes.map((node, i) => {
          const angle = (i / nodes.length) * 2 * Math.PI - Math.PI / 2;
          const x = CENTER + SPOKE_RADIUS * Math.cos(angle);
          const y = CENTER + SPOKE_RADIUS * Math.sin(angle);
          const color = CATEGORY_COLOR[node.category];
          return (
            <g key={node.id}>
              <line x1={CENTER} y1={CENTER} x2={x} y2={y} stroke={color} strokeOpacity={0.3} strokeWidth={1.5} />
              <g
                onClick={node.onClick}
                className={node.onClick ? "cursor-pointer" : undefined}
                style={{ transform: `translate(${x}px, ${y}px)` }}
              >
                {/* Invisible, larger hit-area -- SVG <g> only captures clicks on
                    painted shapes, not empty space, so the visible dot alone
                    (7-10px radius) is too small a target to click reliably. */}
                <circle r={NODE_RADIUS + 8} fill="transparent" />
                <circle
                  r={node.highlighted ? NODE_RADIUS + 3 : NODE_RADIUS}
                  fill={color}
                  fillOpacity={0.85}
                  stroke={node.highlighted ? "#fb3f5e" : "none"}
                  strokeWidth={node.highlighted ? 2 : 0}
                />
                <text y={NODE_RADIUS + 12} textAnchor="middle" fontSize={8} fill="currentColor" className="fill-foreground">
                  {truncate(node.label)}
                </text>
              </g>
            </g>
          );
        })}
        <circle cx={CENTER} cy={CENTER} r={HUB_RADIUS} className="fill-white/10 stroke-white/20" strokeWidth={1} />
      </svg>
      {hiddenCount > 0 && <p className="text-[11px] text-muted">+{hiddenCount} more in the list view below</p>}
    </div>
  );
}
