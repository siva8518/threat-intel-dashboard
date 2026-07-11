import { useQuery } from "@tanstack/react-query";
import { fetchChatHealth } from "@/api/chatApi";
import { queryKeys } from "./queryKeys";

/** Whether the local Ollama-backed chatbot is actually usable right now -- polled more often than most dashboard data since it reflects a local process the user might start/stop mid-session. */
export function useChatHealth() {
  return useQuery({
    queryKey: queryKeys.chatHealth,
    queryFn: fetchChatHealth,
    staleTime: 20_000,
    refetchInterval: 30_000,
    retry: 1,
  });
}
