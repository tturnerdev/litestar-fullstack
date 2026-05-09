import type React from "react"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"

export function TimestampField({ label, value, icon: Icon }: { label: string; value: string | null | undefined; icon?: React.ComponentType<{ className?: string }> }) {
  if (!value) {
    return (
      <div>
        <p className="text-sm text-muted-foreground">{label}</p>
        <p className="text-sm">---</p>
      </div>
    )
  }

  return (
    <div>
      <p className="text-sm text-muted-foreground">{label}</p>
      <Tooltip>
        <TooltipTrigger asChild>
          <p className="inline-flex cursor-default items-center gap-1.5 text-sm">
            {Icon && <Icon className="h-3.5 w-3.5 text-muted-foreground" />}
            {formatRelativeTimeShort(value)}
          </p>
        </TooltipTrigger>
        <TooltipContent>{formatDateTime(value)}</TooltipContent>
      </Tooltip>
    </div>
  )
}
