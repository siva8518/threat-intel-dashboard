// Shared DNS helpers for the Intelligence Investigation Console -- all free,
// keyless, built on Node's own `dns` module (dns.resolve*/dns.reverse), no
// third-party dependency. Every function resolves to `null`/[] on failure
// (NXDOMAIN, no records of that type, timeout) rather than throwing --
// "this record type doesn't exist for this domain" is a normal, common
// outcome here, not an error worth surfacing as one.
import dns from "node:dns/promises";

async function safeResolve(fn) {
  try {
    return await fn();
  } catch {
    return [];
  }
}

/** A/AAAA/MX/NS/CNAME/TXT records for a domain -- the "DNS Records" sub-panel. */
export async function resolveDnsRecords(domain) {
  const [a, aaaa, mx, ns, cname, txt] = await Promise.all([
    safeResolve(() => dns.resolve4(domain)),
    safeResolve(() => dns.resolve6(domain)),
    safeResolve(() => dns.resolveMx(domain)),
    safeResolve(() => dns.resolveNs(domain)),
    safeResolve(() => dns.resolveCname(domain)),
    safeResolve(() => dns.resolveTxt(domain)),
  ]);
  return {
    a,
    aaaa,
    mx: mx.map((m) => `${m.exchange} (priority ${m.priority})`),
    ns,
    cname,
    txt: txt.map((chunks) => chunks.join("")),
  };
}

/** PTR reverse-DNS lookup for an IP -- "Network Intelligence" sub-panel. */
export async function reverseDns(ip) {
  const hostnames = await safeResolve(() => dns.reverse(ip));
  return hostnames[0] ?? null;
}

function parseSpf(txtRecords) {
  const record = txtRecords.find((t) => t.startsWith("v=spf1"));
  return record ?? null;
}

function parseDmarc(txtRecords) {
  const record = txtRecords.find((t) => t.startsWith("v=DMARC1"));
  if (!record) return null;
  const policyMatch = record.match(/p=(\w+)/);
  return { raw: record, policy: policyMatch ? policyMatch[1] : null };
}

/**
 * SPF/DKIM/DMARC posture for a domain -- real DNS TXT data, no third-party
 * "email security score" service involved. DKIM has no fixed record name
 * (selectors are org-specific), so this checks the common `default`/`google`/
 * `selector1` selectors and reports what it found; a miss here means "not
 * found under the common selector names," not "definitively no DKIM."
 */
export async function resolveEmailSecurity(domain) {
  const [rootTxt, dmarcTxt, ...dkimResults] = await Promise.all([
    safeResolve(() => dns.resolveTxt(domain)),
    safeResolve(() => dns.resolveTxt(`_dmarc.${domain}`)),
    ...["default", "google", "selector1", "selector2"].map((sel) => safeResolve(() => dns.resolveTxt(`${sel}._domainkey.${domain}`))),
  ]);

  const spf = parseSpf(rootTxt.map((c) => c.join("")));
  const dmarc = parseDmarc(dmarcTxt.map((c) => c.join("")));
  const dkimSelectors = ["default", "google", "selector1", "selector2"];
  const dkimFound = dkimResults
    .map((chunks, i) => (chunks.length > 0 ? { selector: dkimSelectors[i], record: chunks.map((c) => c.join("")).join("") } : null))
    .filter(Boolean);

  return {
    spf,
    dmarc,
    dkim: dkimFound.length > 0 ? dkimFound : null,
    dkimNote: dkimFound.length === 0 ? "No DKIM record found under common selector names (default/google/selector1/selector2) -- the domain may use a custom selector not checked here." : null,
  };
}
