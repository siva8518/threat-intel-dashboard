import { useQuery } from "@tanstack/react-query";
import { fetchAttackTechniques } from "@/api/dashboardApi";
import { AUTO_REFRESH_MS, STALE_TIME_MS } from "@/config/constants";
import { queryKeys } from "./queryKeys";

/**
 * ATT&CK techniques "observed", derived by cross-referencing malware
 * families in the current threat feed against a curated static
 * malware->technique map (server/data/malware-attack-map.json) -- a
 * best-effort approximation, not live telemetry (no free source provides that).
 */
export function useAttackTechniques() {
  return useQuery({
    queryKey: queryKeys.attackTechniques,
    queryFn: fetchAttackTechniques,
    staleTime: STALE_TIME_MS,
    refetchInterval: AUTO_REFRESH_MS,
    retry: 1,
  });
}
