import { AlertTriangle, Check, Copy, Eye, Headphones, Loader2, Pencil, Reply, ThumbsUp, Trash2 } from "lucide-react"
import { useState } from "react"
import { AttachmentList } from "@/components/support/attachment-list"
import { TicketMessageSystem } from "@/components/support/ticket-message-system"
import { AlertDialog, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from "@/components/ui/alert-dialog"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader } from "@/components/ui/card"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import type { TicketMessage as TicketMessageType } from "@/lib/api/hooks/support"
import { useDeleteTicketMessage } from "@/lib/api/hooks/support"
import { useAuthStore } from "@/lib/auth"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"
import { cn } from "@/lib/utils"

// ── Helpers ──────────────────────────────────────────────────────────────

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

function wasEdited(message: TicketMessageType): boolean {
  if (!message.createdAt || !message.updatedAt) return false
  const created = new Date(message.createdAt).getTime()
  const updated = new Date(message.updatedAt).getTime()
  // Consider edited if updated at least 1 second after creation
  return updated - created > 1000
}

// ── Props ────────────────────────────────────────────────────────────────

interface TicketMessageProps {
  message: TicketMessageType
  ticketId: string
  isFirstMessage?: boolean
  onReply?: () => void
}

// ── Component ────────────────────────────────────────────────────────────

export function TicketMessage({ message, ticketId, isFirstMessage = false, onReply }: TicketMessageProps) {
  const isInternal = message.isInternalNote
  const isSystem = message.isSystemMessage
  const isStaff = message.isStaff === true
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)
  const [copied, setCopied] = useState(false)
  const [thumbsUp, setThumbsUp] = useState(false)
  const [thumbsUpCount, setThumbsUpCount] = useState(0)
  const deleteMutation = useDeleteTicketMessage(ticketId)
  const currentUser = useAuthStore((s) => s.user)

  const isOwnMessage = currentUser?.id === message.author?.id
  const authorName = message.author?.name ?? message.author?.email ?? "Unknown"
  const authorInitial = message.author?.name?.[0]?.toUpperCase() ?? message.author?.email?.[0]?.toUpperCase() ?? "?"
  const avatarColor = getAvatarColor(message.author?.id ?? "unknown")
  const edited = wasEdited(message)

  if (isSystem) {
    return <TicketMessageSystem message={message} />
  }

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(message.bodyMarkdown)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // Fallback: ignore if clipboard API is unavailable
    }
  }

  const handleThumbsUp = () => {
    setThumbsUp((prev) => !prev)
    setThumbsUpCount((prev) => (thumbsUp ? prev - 1 : prev + 1))
  }

  const leftBorderColor = isInternal ? "border-l-amber-500" : isStaff ? "border-l-blue-500" : "border-l-muted-foreground/20"

  return (
    <>
      <Card
        className={cn(
          "group border-l-[3px] transition-colors",
          leftBorderColor,
          isInternal && "border-amber-500/30 bg-amber-500/5",
          isFirstMessage && "border-primary/20 bg-primary/[0.02]",
          !isInternal && !isFirstMessage && "border-border/60",
        )}
      >
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className={cn("flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-sm font-medium", avatarColor)}>{authorInitial}</div>
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <p className="truncate text-sm font-medium">{authorName}</p>
                    </TooltipTrigger>
                    <TooltipContent>{authorName}</TooltipContent>
                  </Tooltip>
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
                  {isStaff && (
                    <Badge variant="outline" className="h-4 border-blue-500/30 bg-blue-500/10 px-1.5 text-[10px] text-blue-700 dark:text-blue-400">
                      <Headphones className="mr-0.5 h-2.5 w-2.5" />
                      Staff
                    </Badge>
                  )}
                </div>
                <div className="flex items-center gap-1.5">
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <p className="cursor-default text-xs text-muted-foreground">{formatRelativeTimeShort(message.createdAt)}</p>
                    </TooltipTrigger>
                    <TooltipContent side="bottom" align="start">
                      {formatDateTime(message.createdAt, "")}
                    </TooltipContent>
                  </Tooltip>
                  {edited && (
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <span className="flex cursor-default items-center gap-0.5 text-[10px] text-muted-foreground/70">
                          <Pencil className="h-2.5 w-2.5" />
                          edited
                        </span>
                      </TooltipTrigger>
                      <TooltipContent side="bottom" align="start">
                        Edited {formatDateTime(message.updatedAt, "")}
                      </TooltipContent>
                    </Tooltip>
                  )}
                </div>
              </div>
            </div>
            <div className="flex items-center gap-1">
              {isInternal && (
                <Badge variant="outline" className="border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-400 text-xs">
                  <Eye className="mr-1 h-3 w-3" />
                  Internal
                </Badge>
              )}
              {onReply && (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-7 w-7 p-0 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100 hover:text-primary"
                      onClick={onReply}
                    >
                      <Reply className="h-3.5 w-3.5" />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>Reply</TooltipContent>
                </Tooltip>
              )}
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-7 w-7 p-0 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100 hover:text-primary"
                    onClick={handleCopy}
                  >
                    {copied ? <Check className="h-3.5 w-3.5 text-emerald-500" /> : <Copy className="h-3.5 w-3.5" />}
                  </Button>
                </TooltipTrigger>
                <TooltipContent>{copied ? "Copied!" : "Copy message"}</TooltipContent>
              </Tooltip>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-7 w-7 p-0 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100 hover:text-destructive"
                    onClick={() => setShowDeleteDialog(true)}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Delete</TooltipContent>
              </Tooltip>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          {/* biome-ignore lint/security/noDangerouslySetInnerHtml: rendering sanitized HTML message content */}
          <div className="prose prose-sm dark:prose-invert max-w-none" dangerouslySetInnerHTML={{ __html: message.bodyHtml }} />
          {message.attachments && message.attachments.length > 0 && <AttachmentList attachments={message.attachments} className="pt-2" />}
          <div className="flex items-center gap-1 pt-1">
            <Button
              size="sm"
              variant="ghost"
              className={cn(
                "h-6 gap-1 rounded-full px-2 text-xs",
                thumbsUp ? "bg-blue-500/10 text-blue-600 hover:bg-blue-500/15 dark:text-blue-400" : "text-muted-foreground hover:text-foreground",
              )}
              onClick={handleThumbsUp}
            >
              <ThumbsUp className={cn("h-3 w-3", thumbsUp && "fill-current")} />
              {thumbsUpCount > 0 && <span>{thumbsUpCount}</span>}
            </Button>
          </div>
        </CardContent>
      </Card>

      <AlertDialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-destructive" />
              Delete message
            </AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete this message from <span className="font-medium text-foreground">{authorName}</span>? This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
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
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
