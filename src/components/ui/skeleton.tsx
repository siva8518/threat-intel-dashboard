import type { HTMLAttributes } from "react";
import { cn } from "@/lib/utils";

export function Skeleton({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "relative overflow-hidden rounded-lg bg-white/[0.06] bg-shimmer bg-[length:200%_100%] animate-shimmer",
        className,
      )}
      {...props}
    />
  );
}
