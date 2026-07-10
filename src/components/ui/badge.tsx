import type { HTMLAttributes } from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-xs font-semibold tracking-wide backdrop-blur-sm",
  {
    variants: {
      variant: {
        default: "border-primary/25 bg-primary/15 text-[#b8adff]",
        critical: "border-critical/30 bg-critical/15 text-critical shadow-[0_0_12px_-2px_theme(colors.critical)]",
        high: "border-high/30 bg-high/15 text-high",
        medium: "border-medium/30 bg-medium/15 text-medium",
        low: "border-low/30 bg-low/15 text-low",
        muted: "border-white/10 bg-white/5 text-muted",
        success: "border-low/30 bg-low/15 text-low",
        danger: "border-critical/30 bg-critical/15 text-critical shadow-[0_0_12px_-2px_theme(colors.critical)]",
        cyan: "border-accent-cyan/30 bg-accent-cyan/15 text-accent-cyan",
      },
    },
    defaultVariants: { variant: "default" },
  },
);

interface BadgeProps extends HTMLAttributes<HTMLSpanElement>, VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />;
}
