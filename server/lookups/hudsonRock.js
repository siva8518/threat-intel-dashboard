import { ApiError, fetchJson } from "../lib/http.js";

const CAVALIER_URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain";

/**
 * Hudson Rock's Cavalier infostealer-intelligence API -- free, keyless, no
 * registration (confirmed live). Domain lookups only here: reports how many
 * devices with credentials/sessions tied to that domain have shown up in
 * infostealer malware logs (Redline/Raccoon/Vidar/etc), the closest free,
 * legal, publicly-documented signal to "dark web exposure" this app has --
 * the paid dark-web platforms (SOCRadar, Searchlight Cyber, Flare) all
 * require an account/subscription for API access, this doesn't.
 */
export async function checkIndicator(type, value) {
  if (type !== "domain") throw new ApiError("Hudson Rock only supports domain lookups", "Hudson Rock");

  const data = await fetchJson(`${CAVALIER_URL}?domain=${encodeURIComponent(value)}`, { source: "Hudson Rock" });

  const total = data.total ?? 0;
  return {
    source: "Hudson Rock",
    verdict: total > 0 ? "suspicious" : "clean", // presence of infostealer-exposed credentials is a real risk signal, not proof of active compromise
    infostealerInfections: total,
    employeesExposed: data.employees ?? 0,
    usersExposed: data.users ?? 0,
    thirdPartiesExposed: data.third_parties ?? 0,
  };
}
