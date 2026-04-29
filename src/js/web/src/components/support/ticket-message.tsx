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
import type { TicketMessage as TicketMessageType } from "@/lib/api/hooks/support"
import { useDeleteTicketMessage } from "@/lib/api/hooks/support"
import { cn } from "@/lib/utils"

export function TicketMessage({ message, ticketId }: { message: TicketMessageType; ticketId: string }) {
  const isInternal = message.isInternalNote
  const isSystem = message.isSystemMessage
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)
  const deleteMutation = useDeleteTicketMessage(ticketId)

  if (isSystem) {
    return <TicketMessageSystem message={message} />
  }

  return (
    <>
      <Card
        className={cn(
          "group border-border/60",
          isInternal && "border-amber-500/30 bg-amber-500/5",
        )}
      >
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary/10 text-primary text-sm font-medium">
                {message.author?.name?.[0]?.toUpperCase() ?? message.author?.email?.[0]?.toUpperCase() ?? "?"}
              </div>
              <div>
                <p className="text-sm font-medium">
                  {message.author?.name ?? message.author?.email ?? "Unknown"}
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
              <span className="font-medium text-foreground">
                {message.author?.name ?? message.author?.email ?? "Unknown"}
              </span>
              ? This action cannot be undone.
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
