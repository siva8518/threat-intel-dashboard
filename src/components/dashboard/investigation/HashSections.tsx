// File Hash (SHA256/SHA1/MD5) Indicator-Specific Intelligence.
import { Section, KeyValueBlock } from "../reportPrimitives";
import { SourceBreakdown } from "./NetworkIndicatorSections";
import type { IocLookupResult } from "@/types/threat-intel";

interface HashModuleData {
  lookupResults: IocLookupResult[];
  fileInfo: { fileType: string | null; fileName: string | null; firstSubmitted: string | null; hashAlgorithm: string };
  detection: { malicious: number; suspicious: number; harmless: number; threatLabel: string | null } | null;
  malwareFamily: string | null;
  behavior: { available: boolean; malwareFamily?: string | null; threatScore?: number | null; detailedBehaviorAvailable?: boolean; detailedBehaviorNote?: string; reason?: string };
  registryHistory: { detectionPercent: number | null; lastSeen: string | null } | null;
}

export function HashIntelligenceSection({ data }: { data: HashModuleData }) {
  return (
    <div className="space-y-4">
      <KeyValueBlock
        title="File Info"
        pairs={[
          ["Hash Algorithm", data.fileInfo.hashAlgorithm],
          ["File Type", data.fileInfo.fileType],
          ["Known File Name", data.fileInfo.fileName],
          ["First Submitted", data.fileInfo.firstSubmitted ? new Date(data.fileInfo.firstSubmitted).toLocaleDateString() : null],
        ]}
      />

      {data.detection && (
        <KeyValueBlock
          title="Detection"
          pairs={[
            ["Malicious / Suspicious / Harmless", `${data.detection.malicious} / ${data.detection.suspicious} / ${data.detection.harmless}`],
            ["Threat Classification", data.detection.threatLabel],
          ]}
        />
      )}

      {data.malwareFamily && <KeyValueBlock title="Malware Family" pairs={[["Family", data.malwareFamily]]} />}

      <Section title="Behavior">
        {data.behavior.available ? (
          <div className="space-y-1 text-xs">
            <p>
              <span className="font-semibold text-foreground">Hybrid Analysis Threat Score: </span>
              {data.behavior.threatScore}/100
            </p>
            {!data.behavior.detailedBehaviorAvailable && <p className="text-muted">{data.behavior.detailedBehaviorNote}</p>}
          </div>
        ) : (
          <p className="text-xs text-muted">Not available — {data.behavior.reason}</p>
        )}
      </Section>

      {data.registryHistory && (
        <KeyValueBlock
          title="Malware Hash Registry History"
          pairs={[
            ["Historical Detection", data.registryHistory.detectionPercent != null ? `${data.registryHistory.detectionPercent}%` : null],
            ["Last Seen", data.registryHistory.lastSeen ? new Date(data.registryHistory.lastSeen).toLocaleDateString() : null],
          ]}
        />
      )}

      <SourceBreakdown results={data.lookupResults} />
    </div>
  );
}
