import { useEffect, useState } from "react";
import { useIsFetching, useQueryClient } from "@tanstack/react-query";
import { RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export function RefreshBar() {
  const queryClient = useQueryClient();
  const isFetching = useIsFetching() > 0;
  const [lastRefreshed, setLastRefreshed] = useState(() => new Date());

  useEffect(() => {
    if (!isFetching) setLastRefreshed(new Date());
  }, [isFetching]);

  return (
    <div className="flex items-center gap-3 text-xs text-muted">
      <span>
        Last updated{" "}
        {lastRefreshed.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })} · auto-refreshes
        every 15 min
      </span>
      <Button
        variant="outline"
        size="sm"
        onClick={() => queryClient.invalidateQueries()}
        disabled={isFetching}
      >
        <RefreshCw className={cn("h-3.5 w-3.5", isFetching && "animate-spin")} />
        Refresh
      </Button>
    </div>
  );
}
