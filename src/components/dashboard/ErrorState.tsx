import { AlertTriangle, Inbox } from "lucide-react";
import { motion } from "framer-motion";

export function ErrorState({ message }: { message: string }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 4 }}
      animate={{ opacity: 1, y: 0 }}
      className="flex flex-col items-center justify-center gap-3 py-12 text-center text-sm"
    >
      <div className="flex h-11 w-11 items-center justify-center rounded-full border border-high/30 bg-high/10">
        <AlertTriangle className="h-5 w-5 text-high" />
      </div>
      <p className="max-w-sm text-muted">{message}</p>
    </motion.div>
  );
}

export function EmptyState({ message }: { message: string }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 4 }}
      animate={{ opacity: 1, y: 0 }}
      className="flex flex-col items-center justify-center gap-3 py-12 text-center text-sm"
    >
      <div className="flex h-11 w-11 items-center justify-center rounded-full border border-white/10 bg-white/[0.04]">
        <Inbox className="h-5 w-5 text-muted" />
      </div>
      <p className="max-w-sm text-muted">{message}</p>
    </motion.div>
  );
}
