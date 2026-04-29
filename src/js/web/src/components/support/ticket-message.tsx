import { AlertTriangle, Eye, Loader2, Trash2 } from "lucide-react"
import { useState } from "react"
import { AttachmentList } from "@/components/support/attachment-list"
import { TicketMessageSystem } from "@/components/support/ticket-message-system"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader } from "@/components/ui/card"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import type { TicketMessage as TicketMessageType } from "@/lib/api/hooks/support"
import { useDeleteTicketMessage } from "@/lib/api/hooks/support"
import { useAuthStore } from "@/lib/auth"
import { cn } from "@/lib/utils"

// ── Helpers ──────────────────────────────────────────────────────────────

function formatRelativeTime(dateStr: string | null | undefined): string {
  if (!dateStr) return ""
  const date = new Date(dateStr)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffSec = Math.floor(diffMs / 1000)
  const diffMin = Math.floor(diffSec / 60)
  const diffHr = Math.floor(diffMin / 60)
  const diffDays = Math.floor(diffHr / 24)

  if (diffSec < 60) return "just now"
  if (diffMin < 60) return `${diffMin}m ago`
  if (diffHr < 24) return `${diffHr}h ago`
  if (diffDays < 7) return `${diffDays}d ago`
  return date.toLocaleDateString(undefined, { month: "short", day: "numeric", year: date.getFullYear() !== now.getFullYear() ? "numeric" : undefined })
}

function getAvatarColor(identifier: string): string {
  const colors = [
    "bg-blue-500/15 text-blue-700 dark:text-blue-400",
    "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400",
    "bg-violet-500/15 text-violet-700 dark:text-violet-400",
    "bg-amber-500/15 text-amber-700 dark:text-amber-400",
    "bg-rose-500/15 text-rose-700 dark:text-rose-400",
    "bg-cyan-500/15 text-cyan-700 dark:text-cyan-400",
    "bg-fuchsia-500/15 text-fuchsia-700 dark:text-fuchsia-400",
    "bg-orange-500/15 text-orange-700 dark:text-orange-400",
  ]
  let hash = 0
  for (let i = 0; i < identifier.length; i++) {
    hash = identifier.charCodeAt(i) + ((hash << 5) - hash)
  }
  return colors[Math.abs(hash) % colors.length]
}

// ── Props ────────────────────────────────────────────────────────────────

interface TicketMessageProps {
  message: TicketMessageType
  ticketId: string
  isFirstMessage?: boolean
}

// ── Component ────────────────────────────────────────────────────────────

export function TicketMessage({ message, ticketId, isFirstMessage = false }: TicketMessageProps) {
  const isInternal = message.isInternalNote
  const isSystem = message.isSystemMessage
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)
  const deleteMutation = useDeleteTicketMessage(ticketId)
  const currentUser = useAuthStore((s) => s.user)

  const isOwnMessage = currentUser?.id === message.author?.id
  const authorName = message.author?.name ?? message.author?.email ?? "Unknown"
  const authorInitial = message.author?.name?.[0]?.toUpperCase() ?? message.author?.email?.[0]?.toUpperCase() ?? "?"
  const avatarColor = getAvatarColor(message.author?.id ?? "unknown")

  if (isSystem) {
    return <TicketMessageSystem message={message} />
  }

  return (
    <>
      <Card
        className={cn(
          "group transition-colors",
          isInternal && "border-amber-500/30 bg-amber-500/5",
          isFirstMessage && "border-primary/20 bg-primary/[0.02]",
          !isInternal && !isFirstMessage && "border-border/60",
        )}
      >
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div
                className={cn(
                  "flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-sm font-medium",
                  avatarColor,
                )}
              >
                {authorInitial}
              </div>
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <p className="truncate text-sm font-medium">{authorName}</p>
                  {isOwnMessage && (
                    <Badge variant="outline" className="h-4 border-primary/30 bg-primary/5 px-1.5 text-[10px] text-primary">
                      You
                    </Badge>
                  )}
                  {isFirstMessage && (
                    <Badge variant="outline" className="h-4 border-primary/30 bg-primary/5 px-1.5 text-[10px] text-primary">
                      Original
                    </Badge>
                  )}
                </div>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <p className="cursor-default text-xs text-muted-foreground">
                      {formatRelativeTime(message.createdAt)}
                    </p>
                  </TooltipTrigger>
                  <TooltipContent side="bottom" align="start">
                    {message.createdAt ? new Date(message.createdAt).toLocaleString() : ""}
                  </TooltipContent>
                </Tooltip>
              </div>
            </div>
            <div className="flex items-center gap-2">
              {isInternal && (
                <Badge variant="outline" className="border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-400 text-xs">
                  <Eye className="mr-1 h-3 w-3" />
                  Internal
                </Badge>
              )}
              <Button
                size="sm"
                variant="ghost"
                className="h-7 w-7 p-0 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100 hover:text-destructive"
                onClick={() => setShowDeleteDialog(true)}
              >
                <Trash2 className="h-3.5 w-3.5" />
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          <div
            className="prose prose-sm dark:prose-invert max-w-none"
            dangerouslySetInnerHTML={{ __html: message.bodyHtml }}
          />
          {message.attachments && message.attachments.length > 0 && (
            <AttachmentList attachments={message.attachments} className="pt-2" />
          )}
        </CardContent>
      </Card>

      <Dialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-destructive" />
              Delete message
            </DialogTitle>
            <DialogDescription>
              Are you sure you want to delete this message from{" "}
              <span className="font-medium text-foreground">{authorName}</span>?
              This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowDeleteDialog(false)} disabled={deleteMutation.isPending}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={deleteMutation.isPending}
              onClick={() => {
                deleteMutation.mutate(message.id, {
                  onSuccess: () => setShowDeleteDialog(false),
                })
              }}
            >
              {deleteMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
