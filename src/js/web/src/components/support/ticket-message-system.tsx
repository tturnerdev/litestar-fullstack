import { Info } from "lucide-react"
import type { TicketMessage } from "@/lib/api/hooks/support"

interface TicketMessageSystemProps {
  message: TicketMessage
}

export function TicketMessageSystem({ message }: TicketMessageSystemProps) {
  return (
    <div className="flex items-center justify-center py-2">
      <div className="flex items-center gap-2 rounded-full border border-border/40 bg-muted/30 px-4 py-1.5">
        <Info className="h-3.5 w-3.5 text-muted-foreground" />
        <span className="text-xs text-muted-foreground">
          {message.bodyMarkdown}
        </span>
        <span className="text-xs text-muted-foreground/60">
          {message.createdAt ? new Date(message.createdAt).toLocaleString() : ""}
        </span>
      </div>
    </div>
  )
}
