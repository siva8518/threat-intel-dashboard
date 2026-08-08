// Canonical MITRE ATT&CK Enterprise tactic order + display labels -- mirrors
// server/correlate.js's own ATTACK_TACTICS_ORDER/TACTIC_DISPLAY convention
// (that file's comment documents why "defense evasion" is split into
// "defense impairment"/"stealth" in the live bundle this app ingests, a
// 15-tactic list rather than the classic 14). One shared source so the
// Investigation Graph's node detail panel and the entity dossier's own
// ATT&CK section group techniques under the exact same tactic headers.
export const ATTACK_TACTICS_ORDER = [
  "reconnaissance", "resource development", "initial access", "execution", "persistence",
  "privilege escalation", "defense impairment", "stealth", "credential access", "discovery",
  "lateral movement", "collection", "command and control", "exfiltration", "impact",
];

export const TACTIC_DISPLAY_LABEL: Record<string, string> = {
  reconnaissance: "Reconnaissance",
  "resource development": "Resource Development",
  "initial access": "Initial Access",
  execution: "Execution",
  persistence: "Persistence",
  "privilege escalation": "Privilege Escalation",
  "defense impairment": "Defense Impairment",
  stealth: "Stealth",
  "credential access": "Credential Access",
  discovery: "Discovery",
  "lateral movement": "Lateral Movement",
  collection: "Collection",
  "command and control": "Command & Control",
  exfiltration: "Exfiltration",
  impact: "Impact",
};

export interface AttackTechniqueSummary {
  id: string;
  name: string;
  tactic: string | null;
}

/** Groups a flat technique list under its tactic, in kill-chain order; anything with an unrecognized/missing tactic collects under "Other". */
export function groupByTactic<T extends AttackTechniqueSummary>(techniques: T[]): Array<{ tactic: string; label: string; items: T[] }> {
  const byTactic = new Map<string, T[]>();
  for (const t of techniques) {
    const key = t.tactic && TACTIC_DISPLAY_LABEL[t.tactic] ? t.tactic : "other";
    if (!byTactic.has(key)) byTactic.set(key, []);
    byTactic.get(key)!.push(t);
  }
  const order = [...ATTACK_TACTICS_ORDER, "other"];
  return order
    .filter((tactic) => byTactic.has(tactic))
    .map((tactic) => ({ tactic, label: tactic === "other" ? "Other" : TACTIC_DISPLAY_LABEL[tactic], items: byTactic.get(tactic)! }));
}
