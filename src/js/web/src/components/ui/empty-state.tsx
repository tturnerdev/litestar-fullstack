import type { LucideIcon } from "lucide-react"
import type * as React from "react"
import { cn } from "@/lib/utils"

type EmptyStateVariant = "no-items" | "no-results"

interface EmptyStateProps {
  icon: LucideIcon
  title: string
  description: string
  action?: React.ReactNode
  variant?: EmptyStateVariant
  className?: string
}

/**
 * Reusable empty state component for list pages.
 *
 * - `no-items` (default): Nothing has been created yet. Shows a dashed border card with a prominent CTA.
 * - `no-results`: A search or filter returned nothing. Uses a softer appearance.
 */
export function EmptyState({ icon: Icon, title, description, action, variant = "no-items", className }: EmptyStateProps) {
  const isNoResults = variant === "no-results"

  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center rounded-xl border-2 border-dashed px-6 py-16 text-center",
        isNoResults ? "border-border/40 bg-muted/20" : "border-border/60 bg-card/40",
        className,
      )}
    >
      <div
        className={cn(
          "mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-full",
          isNoResults ? "bg-muted/60" : "bg-primary/10",
        )}
      >
        <Icon
          className={cn(
            "h-7 w-7",
            isNoResults ? "text-muted-foreground/60" : "text-primary/70",
          )}
        />
      </div>
      <h3 className="mb-1 text-lg font-semibold tracking-tight">{title}</h3>
      <p className="mb-6 max-w-sm text-sm text-muted-foreground">{description}</p>
      {action && <div>{action}</div>}
    </div>
  )
}
