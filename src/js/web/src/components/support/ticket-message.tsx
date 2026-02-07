import { Eye, MessageSquare } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader } from "@/components/ui/card"
import type { TicketMessage as TicketMessageType } from "@/lib/api/hooks/support"
import { cn } from "@/lib/utils"

export function TicketMessage({ message }: { message: TicketMessageType }) {
  const isInternal = message.isInternalNote
  const isSystem = message.isSystemMessage

  return (
    <Card
      className={cn(
        "border-border/60",
        isInternal && "border-amber-500/30 bg-amber-500/5",
        isSystem && "border-zinc-500/30 bg-zinc-500/5",
      )}
    >
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            {isSystem ? (
              <div className="flex h-8 w-8 items-center justify-center rounded-full bg-zinc-500/10">
                <MessageSquare className="h-4 w-4 text-zinc-500" />
              </div>
            ) : (
              <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary/10 text-primary text-sm font-medium">
                {message.author?.name?.[0]?.toUpperCase() ?? message.author?.email?.[0]?.toUpperCase() ?? "?"}
              </div>
            )}
            <div>
              <p className="text-sm font-medium">
                {isSystem ? "System" : message.author?.name ?? message.author?.email ?? "Unknown"}
              </p>
              <p className="text-xs text-muted-foreground">
                {message.createdAt ? new Date(message.createdAt).toLocaleString() : ""}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {isInternal && (
              <Badge variant="outline" className="border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-400 text-xs">
                <Eye className="mr-1 h-3 w-3" />
                Internal
              </Badge>
            )}
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div
          className="prose prose-sm dark:prose-invert max-w-none"
          dangerouslySetInnerHTML={{ __html: message.bodyHtml }}
        />
      </CardContent>
    </Card>
  )
}
