import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

// Thin HTTP client against the already-running backend (server/index.js) --
// NOT a direct import of cache.js/scheduler.js. Only the main process's
// startScheduler() call ever populates the cache, so a separate process
// importing cache.js directly would just see its own empty, never-synced
// copy. Requires `npm run dev` (or the prod server) to already be running.
const API_BASE = `http://localhost:${process.env.PORT || 8080}/api`;

async function apiGet(path) {
  const res = await fetch(`${API_BASE}${path}`);
  const body = await res.json().catch(() => null);
  if (!res.ok) {
    throw new Error(body?.error || `${API_BASE}${path} responded ${res.status}`);
  }
  return body;
}

function textResult(data) {
  return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
}

function errorResult(error) {
  return { content: [{ type: "text", text: `Error: ${error.message}` }], isError: true };
}

const server = new McpServer({ name: "threat-intel-dashboard", version: "1.0.0" });

server.registerTool(
  "lookup_cve",
  {
    title: "Look up a CVE by ID",
    description:
      "Fetch a single CVE record (any age, not just the last 30 days) enriched with CISA KEV status and EPSS exploit-probability score.",
    inputSchema: { cveId: z.string().describe('CVE identifier, e.g. "CVE-2021-44228"') },
  },
  async ({ cveId }) => {
    try {
      return textResult(await apiGet(`/dashboard/cve/${encodeURIComponent(cveId)}`));
    } catch (error) {
      return errorResult(error);
    }
  },
);

server.registerTool(
  "search_cves",
  {
    title: "Search recent CVEs",
    description:
      "Search CVEs published in the last 30 days, optionally filtered by CVSS v3 severity and/or keyword, enriched with CISA KEV status and EPSS score. For a specific CVE of any age, use lookup_cve instead.",
    inputSchema: {
      severity: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]).optional().describe("Filter by CVSS v3 severity"),
      keyword: z.string().optional().describe("Keyword to search in the CVE description (e.g. a vendor or product name)"),
      pageSize: z.number().int().min(1).max(100).optional().describe("Max results to return (default 20)"),
    },
  },
  async ({ severity, keyword, pageSize }) => {
    try {
      const params = new URLSearchParams();
      if (severity) params.set("severity", severity);
      if (keyword) params.set("keyword", keyword);
      if (pageSize) params.set("pageSize", String(pageSize));
      return textResult(await apiGet(`/dashboard/cves?${params.toString()}`));
    } catch (error) {
      return errorResult(error);
    }
  },
);

server.registerTool(
  "search_threat_actor",
  {
    title: "Search threat actor groups",
    description: "Search known threat actor / APT groups by name or alias.",
    inputSchema: { query: z.string().describe("Name or alias fragment to search for") },
  },
  async ({ query }) => {
    try {
      return textResult(await apiGet(`/dashboard/threat-actor-profiles/search?q=${encodeURIComponent(query)}`));
    } catch (error) {
      return errorResult(error);
    }
  },
);

server.registerTool(
  "get_threat_actor_profile",
  {
    title: "Get full threat actor profile",
    description:
      "Get a full profile for a threat actor group by its MITRE ATT&CK group ID (e.g. G0007), including techniques, malware/tools, Malpedia families, ransomware campaigns and recent news.",
    inputSchema: { attackId: z.string().describe('MITRE ATT&CK group ID, e.g. "G0007"') },
  },
  async ({ attackId }) => {
    try {
      return textResult(await apiGet(`/dashboard/threat-actor-profiles/${encodeURIComponent(attackId)}`));
    } catch (error) {
      return errorResult(error);
    }
  },
);

server.registerTool(
  "search_ioc",
  {
    title: "Search an indicator of compromise",
    description:
      "Look up an IP, domain, URL, or file hash live across all configured sources (OTX, AbuseIPDB, Pulsedive, VirusTotal, GreyNoise, Shodan, Hybrid Analysis, LeakIX) and return a correlated verdict.",
    inputSchema: {
      type: z.enum(["ip", "domain", "url", "hash"]).describe("Indicator type"),
      value: z.string().describe("The indicator value to look up"),
    },
  },
  async ({ type, value }) => {
    try {
      return textResult(await apiGet(`/ioc-search?type=${encodeURIComponent(type)}&value=${encodeURIComponent(value)}`));
    } catch (error) {
      return errorResult(error);
    }
  },
);

server.registerTool(
  "get_threat_feed",
  {
    title: "Get the live threat feed",
    description: "Get the aggregated live threat feed (malicious IPs, URLs, hashes, phishing domains) from all bulk sources.",
    inputSchema: {},
  },
  async () => {
    try {
      return textResult(await apiGet("/dashboard/threat-feed"));
    } catch (error) {
      return errorResult(error);
    }
  },
);

server.registerTool(
  "get_ransomware_campaigns",
  {
    title: "Get active ransomware campaigns",
    description: "Get recent ransomware campaign/victim disclosures merged from ransomware.live, RansomWatch and RansomLook.",
    inputSchema: {},
  },
  async () => {
    try {
      return textResult(await apiGet("/dashboard/ransomware"));
    } catch (error) {
      return errorResult(error);
    }
  },
);

server.registerTool(
  "get_github_repo_intel",
  {
    title: "Get GitHub threat intel repo stats",
    description: "Get aggregate stats and repo list from the GitHub Threat Intel collector (IOC/CVE/ATT&CK extraction with threat scoring across security-relevant GitHub repos).",
    inputSchema: {},
  },
  async () => {
    try {
      return textResult(await apiGet("/dashboard/github-intel/stats"));
    } catch (error) {
      return errorResult(error);
    }
  },
);

server.registerTool(
  "get_source_health",
  {
    title: "Get data source health",
    description: "Get the sync status, last-updated timestamp, and error state of every connected data source.",
    inputSchema: {},
  },
  async () => {
    try {
      return textResult(await apiGet("/dashboard/health"));
    } catch (error) {
      return errorResult(error);
    }
  },
);

server.registerTool(
  "get_malware_trending",
  {
    title: "Get trending malware families",
    description: "Get malware families trending right now, ranked by frequency across the live threat feed (MalwareBazaar, ThreatFox, URLHaus, etc.), each mapped to known ATT&CK techniques where available.",
    inputSchema: {},
  },
  async () => {
    try {
      return textResult(await apiGet("/dashboard/malware-trending"));
    } catch (error) {
      return errorResult(error);
    }
  },
);

server.registerTool(
  "get_attack_techniques",
  {
    title: "Get trending ATT&CK techniques",
    description: "Get MITRE ATT&CK techniques currently observed, derived from malware families seen in the live threat feed cross-referenced against a curated malware-to-technique map.",
    inputSchema: {},
  },
  async () => {
    try {
      return textResult(await apiGet("/dashboard/attack-techniques"));
    } catch (error) {
      return errorResult(error);
    }
  },
);

server.registerTool(
  "get_kev_catalog",
  {
    title: "Get CISA Known Exploited Vulnerabilities",
    description: "Get the CISA KEV catalog of vulnerabilities confirmed to be actively exploited in the wild.",
    inputSchema: {},
  },
  async () => {
    try {
      return textResult(await apiGet("/dashboard/kev"));
    } catch (error) {
      return errorResult(error);
    }
  },
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  console.error("MCP server failed to start:", error);
  process.exit(1);
});
