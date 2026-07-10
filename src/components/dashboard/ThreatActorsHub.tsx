import { RansomwareCampaigns } from "./RansomwareCampaigns";
import { TrendingMalware } from "./TrendingMalware";

interface ThreatActorsHubProps {
  countryFilter?: string | null;
  onClearCountryFilter?: () => void;
  industryFilter?: string | null;
  onClearIndustryFilter?: () => void;
}

/**
 * Consolidated "Threat Actors" tab: who's active (ransomware groups + OTX
 * adversary tags, with their recent campaigns) and what they're using
 * (trending malware families, framed as "tools" -- same underlying data,
 * no separate tools source exists). Replaces what used to be two separate
 * tabs ("Ransomware & Actors" and "Trending Malware").
 */
export function ThreatActorsHub({ countryFilter, onClearCountryFilter, industryFilter, onClearIndustryFilter }: ThreatActorsHubProps) {
  return (
    <div className="space-y-6">
      <RansomwareCampaigns
        countryFilter={countryFilter}
        onClearCountryFilter={onClearCountryFilter}
        industryFilter={industryFilter}
        onClearIndustryFilter={onClearIndustryFilter}
      />
      <TrendingMalware />
    </div>
  );
}
