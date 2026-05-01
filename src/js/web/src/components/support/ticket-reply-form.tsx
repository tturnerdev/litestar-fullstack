import { Check, Eye, Keyboard, Loader2, Send, StickyNote, X } from "lucide-react"
import { useCallback, useEffect, useRef, useState } from "react"
import { AttachmentUpload, type PendingFile } from "@/components/support/attachment-upload"
import { useImagePasteHandler } from "@/components/support/image-paste-handler"
import { MarkdownEditor } from "@/components/support/markdown-editor"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Switch } from "@/components/ui/switch"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useCreateTicketMessage, usePasteImage, useUploadAttachment } from "@/lib/api/hooks/support"
import { useAuthStore } from "@/lib/auth"
import { cn } from "@/lib/utils"

export function TicketReplyForm({ ticketId }: { ticketId: string }) {
  const [body, setBody] = useState("")
  const [files, setFiles] = useState<PendingFile[]>([])
  const [isUploading, setIsUploading] = useState(false)
  const [isInternalNote, setIsInternalNote] = useState(false)
  const [showSuccess, setShowSuccess] = useState(false)
  const [showDiscardConfirm, setShowDiscardConfirm] = useState(false)
  const formRef = useRef<HTMLFormElement>(null)
  const createMessage = useCreateTicketMessage(ticketId)
  const pasteImage = usePasteImage(ticketId)
  const uploadAttachment = useUploadAttachment(ticketId)
  const user = useAuthStore((s) => s.user)
  const isSuperuser = user?.isSuperuser === true
  const userInitial = (user?.name?.[0] ?? user?.email?.[0] ?? "U").toUpperCase()

  // Clear success animation after delay
  useEffect(() => {
    if (!showSuccess) return
    const timer = setTimeout(() => setShowSuccess(false), 1500)
    return () => clearTimeout(timer)
  }, [showSuccess])

  const insertImageMarkdown = useCallback(
    (markdown: string) => {
      setBody((prev) => {
        const suffix = prev.endsWith("\n") || prev === "" ? "" : "\n"
        return prev + suffix + markdown + "\n"
      })
    },
    [],
  )

  const { handlePaste, handleDrop } = useImagePasteHandler({
    onUpload: (blob) => pasteImage.mutateAsync(blob),
    onInsert: insertImageMarkdown,
    onUploadStart: () => setIsUploading(true),
    onUploadEnd: () => setIsUploading(false),
  })

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!body.trim()) return

    // Upload pending files first
    if (files.length > 0) {
      try {
        await uploadAttachment.mutateAsync(files.map((f) => f.file))
      } catch {
        return // Error handled by hook
      }
    }

    createMessage.mutate(
      { bodyMarkdown: body, ...(isInternalNote && { isInternalNote: true }) },
      {
        onSuccess: () => {
          setBody("")
          setFiles([])
          setIsInternalNote(false)
          setShowSuccess(true)
        },
      },
    )
  }

  const isSending = createMessage.isPending || uploadAttachment.isPending
  const hasContent = body.trim().length > 0 || files.length > 0

  const handleDiscard = () => {
    if (body.length > 50) {
      setShowDiscardConfirm(true)
    } else {
      setBody("")
      setFiles([])
    }
  }

  const confirmDiscard = () => {
    setBody("")
    setFiles([])
    setShowDiscardConfirm(false)
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter" && body.trim() && !isSending) {
      e.preventDefault()
      formRef.current?.requestSubmit()
    }
  }

  return (
    <>
      <Card
        className={cn(
          "border-l-2 transition-colors",
          isInternalNote
            ? "border-amber-500/30 border-l-amber-500 bg-amber-500/5"
            : "border-border/60 border-l-primary/30",
        )}
      >
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div
                className={cn(
                  "flex h-6 w-6 items-center justify-center rounded-full text-xs font-medium",
                  isInternalNote
                    ? "bg-amber-500/15 text-amber-700 dark:text-amber-400"
                    : "bg-primary/10 text-primary",
                )}
              >
                {userInitial}
              </div>
              <CardTitle className="text-sm font-medium">
                {isInternalNote ? "Internal Note" : "Reply"}
              </CardTitle>
              {isInternalNote && (
                <Badge
                  variant="outline"
                  className="border-amber-500/30 bg-amber-500/10 text-[10px] text-amber-700 dark:text-amber-400"
                >
                  <Eye className="mr-0.5 h-2.5 w-2.5" />
                  Staff only
                </Badge>
              )}
              {showSuccess && (
                <div className="flex items-center gap-1 animate-in fade-in zoom-in duration-200">
                  <Check className="h-4 w-4 text-green-500" />
                  <span className="text-xs text-green-600">Sent</span>
                </div>
              )}
            </div>
            {isSuperuser && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <div className="flex items-center gap-2">
                    <label
                      htmlFor="internal-note-toggle"
                      className={cn(
                        "cursor-pointer text-xs font-medium transition-colors",
                        isInternalNote
                          ? "text-amber-700 dark:text-amber-400"
                          : "text-muted-foreground",
                      )}
                    >
                      <StickyNote className="mr-1 inline h-3 w-3" />
                      Internal Note
                    </label>
                    <Switch
                      id="internal-note-toggle"
                      checked={isInternalNote}
                      onCheckedChange={setIsInternalNote}
                      className="data-[state=checked]:bg-amber-500"
                    />
                  </div>
                </TooltipTrigger>
                <TooltipContent>
                  Internal notes are only visible to superusers
                </TooltipContent>
              </Tooltip>
            )}
          </div>
        </CardHeader>
        <CardContent>
          <form ref={formRef} onSubmit={handleSubmit} onKeyDown={handleKeyDown} className="space-y-4">
            <MarkdownEditor
              value={body}
              onChange={setBody}
              placeholder={
                isInternalNote
                  ? "Write an internal note... (only visible to superusers)"
                  : "Write your reply... (Markdown supported, paste images with Ctrl+V)"
              }
              minHeight="120px"
              onPaste={handlePaste}
              onDrop={handleDrop}
              disabled={isSending}
            />
            <div className="flex items-center justify-between">
              <span className="text-xs text-muted-foreground">{body.length} characters</span>
            </div>
            {isUploading && (
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <Loader2 className="h-3 w-3 animate-spin" />
                Uploading image...
              </div>
            )}
            <div className="flex items-start justify-between gap-4">
              <AttachmentUpload
                files={files}
                onFilesChange={setFiles}
                uploading={uploadAttachment.isPending}
                disabled={isSending}
                compact
              />
              <div className="flex items-center gap-2">
                {hasContent && (
                  <Button
                    type="button"
                    variant="ghost"
                    className="shrink-0 text-destructive hover:text-destructive"
                    onClick={handleDiscard}
                    disabled={isSending}
                  >
                    <X className="mr-2 h-4 w-4" />
                    Discard
                  </Button>
                )}
                <div className="flex items-center gap-2">
                  <Button
                    type="submit"
                    disabled={isSending || !body.trim()}
                    className={cn(
                      "shrink-0",
                      isInternalNote &&
                        "bg-amber-600 text-white hover:bg-amber-700 dark:bg-amber-600 dark:hover:bg-amber-700",
                    )}
                  >
                    {isSending ? (
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    ) : isInternalNote ? (
                      <StickyNote className="mr-2 h-4 w-4" />
                    ) : (
                      <Send className="mr-2 h-4 w-4" />
                    )}
                    {isSending
                      ? "Sending..."
                      : isInternalNote
                        ? "Add Internal Note"
                        : "Send Reply"}
                  </Button>
                  <span className="hidden items-center gap-1 text-xs text-muted-foreground sm:flex">
                    <Keyboard className="h-3 w-3" />
                    Ctrl+Enter
                  </span>
                </div>
              </div>
            </div>
          </form>
        </CardContent>
      </Card>

      <AlertDialog open={showDiscardConfirm} onOpenChange={setShowDiscardConfirm}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Discard reply?</AlertDialogTitle>
            <AlertDialogDescription>
              Your reply has unsaved content. Are you sure you want to discard it?
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setShowDiscardConfirm(false)}>
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction onClick={confirmDiscard}>
              Discard
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
