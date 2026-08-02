// RDAP (Registration Data Access Protocol) -- IANA's free, keyless,
// standardized JSON successor to WHOIS. Bootstrapped through rdap.org, which
// redirects to the correct registry RDAP server for the domain's TLD, so
// this doesn't need a per-TLD server map. This is the WHOIS-equivalent
// sub-panel for the Domain investigation module -- no paid WHOIS API needed.
import { ApiError, fetchJson } from "../lib/http.js";
import { withRetry } from "../lib/retry.js";

function findEvent(events, action) {
  return (events ?? []).find((e) => e.eventAction === action)?.eventDate ?? null;
}

function findEntityName(entities, role) {
  const entity = (entities ?? []).find((e) => (e.roles ?? []).includes(role));
  const vcard = entity?.vcardArray?.[1];
  const fnEntry = Array.isArray(vcard) ? vcard.find((row) => row[0] === "fn") : null;
  return fnEntry ? fnEntry[3] : (entity?.handle ?? null);
}

export async function checkIndicator(type, value) {
  if (type !== "domain") throw new ApiError("RDAP only supports domain lookups", "RDAP");

  let data;
  try {
    data = await withRetry(() => fetchJson(`https://rdap.org/domain/${encodeURIComponent(value)}`, { source: "RDAP", timeoutMs: 8_000 }), {
      retries: 1,
      baseDelayMs: 500,
    });
  } catch (error) {
    if (error.status === 404) {
      return { source: "RDAP", verdict: "unknown", registered: false, registrar: null, createdDate: null, updatedDate: null, expiresDate: null, nameservers: [], registrant: null, status: [] };
    }
    throw error;
  }

  return {
    source: "RDAP",
    verdict: "unknown", // registration data alone says nothing about maliciousness
    registered: true,
    registrar: findEntityName(data.entities, "registrar"),
    createdDate: findEvent(data.events, "registration"),
    updatedDate: findEvent(data.events, "last changed"),
    expiresDate: findEvent(data.events, "expiration"),
    nameservers: (data.nameservers ?? []).map((ns) => ns.ldhName).filter(Boolean),
    registrant: findEntityName(data.entities, "registrant"),
    status: data.status ?? [],
  };
}
