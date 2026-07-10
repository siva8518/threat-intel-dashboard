import { useState } from "react";
import { Copy, Check } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

// Kept in sync manually with the tool registrations in server/mcpServer.js --
// there's no live endpoint listing them since the MCP server is a separate
// stdio process the dashboard backend has no visibility into.
const TOOLS = [
  { name: "lookup_cve", description: "Look up a single CVE by ID, enriched with KEV + EPSS." },
  { name: "search_threat_actor", description: "Search threat actor groups by name or alias." },
  { name: "get_threat_actor_profile", description: "Full actor profile by ATT&CK group ID (techniques, malware, campaigns, news)." },
  { name: "search_ioc", description: "Look up an IP, domain, URL or hash across all configured IOC sources." },
  { name: "get_threat_feed", description: "Aggregated live threat feed (malicious IPs, URLs, hashes, phishing domains)." },
  { name: "get_ransomware_campaigns", description: "Recent ransomware victim disclosures, merged across trackers." },
  { name: "get_github_repo_intel", description: "Stats from the GitHub threat-intel repo collector." },
  { name: "get_source_health", description: "Sync status and errors for every connected data source." },
  { name: "get_malware_trending", description: "Malware families trending right now, mapped to ATT&CK where known." },
  { name: "get_attack_techniques", description: "MITRE ATT&CK techniques currently observed in the live feed." },
  { name: "get_kev_catalog", description: "CISA's catalog of vulnerabilities confirmed actively exploited." },
] as const;

const DESKTOP_CONFIG = `{
  "mcpServers": {
    "threat-intel-dashboard": {
      "command": "node",
      "args": ["<path-to-project>/server/mcpServer.js"]
    }
  }
}`;

const CODE_CLI_CMD = "claude mcp add threat-intel-dashboard -- node server/mcpServer.js";
const INSPECTOR_CMD = "npx @modelcontextprotocol/inspector node server/mcpServer.js";

function CopyBlock({ code }: { code: string }) {
  const [copied, setCopied] = useState(false);

  async function onCopy() {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <div className="relative">
      <pre className="overflow-x-auto rounded-md border border-border bg-background p-3 pr-10 text-xs">
        <code>{code}</code>
      </pre>
      <Button
        type="button"
        variant="ghost"
        size="sm"
        onClick={onCopy}
        className="absolute right-1.5 top-1.5 h-7 px-2"
        aria-label="Copy to clipboard"
      >
        {copied ? <Check className="h-3.5 w-3.5 text-low" /> : <Copy className="h-3.5 w-3.5" />}
      </Button>
    </div>
  );
}

/**
 * MCP isn't something this web dashboard talks to itself -- it's a separate
 * stdio protocol for AI clients (Claude Desktop/Code, MCP Inspector). This
 * panel can't "launch" it from a browser click: having the backend able to
 * exec arbitrary local processes on request from an HTTP call is a real
 * security anti-pattern (this app can also run as a public-facing Docker
 * container), so this only surfaces the tool list and the exact commands to
 * run yourself in a terminal.
 */
export function McpServerPanel() {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base font-semibold text-foreground">
          MCP Server <span className="text-muted">(for AI assistants, not this browser tab)</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        <p className="text-sm text-muted">
          <code className="rounded bg-background px-1 py-0.5 text-xs">server/mcpServer.js</code> exposes this
          dashboard's aggregated data to MCP-capable AI clients over stdio. It calls this same backend's own
          <code className="mx-1 rounded bg-background px-1 py-0.5 text-xs">/api/dashboard/*</code>
          routes, so <strong>the backend you're looking at right now must stay running</strong> for tool
          calls to return data. It can't be started from this page for security reasons — run one of the
          commands below in a terminal instead.
        </p>

        <div>
          <h3 className="mb-2 text-sm font-semibold text-foreground">Tools ({TOOLS.length})</h3>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {TOOLS.map((tool) => (
              <div key={tool.name} className={cn("rounded-md border border-border p-2.5 text-xs")}>
                <div className="mb-0.5 font-mono font-semibold text-primary">{tool.name}</div>
                <div className="text-muted">{tool.description}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="space-y-3">
          <div>
            <h3 className="mb-1.5 text-sm font-semibold text-foreground">Test it (MCP Inspector)</h3>
            <p className="mb-1.5 text-xs text-muted">Opens a local web UI to try each tool by hand.</p>
            <CopyBlock code={INSPECTOR_CMD} />
          </div>

          <div>
            <h3 className="mb-1.5 text-sm font-semibold text-foreground">Register with Claude Code</h3>
            <CopyBlock code={CODE_CLI_CMD} />
          </div>

          <div>
            <h3 className="mb-1.5 text-sm font-semibold text-foreground">Register with Claude Desktop</h3>
            <p className="mb-1.5 text-xs text-muted">
              Add to <code className="rounded bg-background px-1 py-0.5">claude_desktop_config.json</code>{" "}
              (replace <code className="rounded bg-background px-1 py-0.5">&lt;path-to-project&gt;</code> with this
              project's full path), then restart Claude Desktop.
            </p>
            <CopyBlock code={DESKTOP_CONFIG} />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
