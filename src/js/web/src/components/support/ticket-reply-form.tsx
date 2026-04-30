import { Check, Keyboard, Loader2, Send, X } from "lucide-react"
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
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { useCreateTicketMessage, usePasteImage, useUploadAttachment } from "@/lib/api/hooks/support"
import { useAuthStore } from "@/lib/auth"

export function TicketReplyForm({ ticketId }: { ticketId: string }) {
  const [body, setBody] = useState("")
  const [files, setFiles] = useState<PendingFile[]>([])
  const [isUploading, setIsUploading] = useState(false)
  const [showSuccess, setShowSuccess] = useState(false)
  const [showDiscardConfirm, setShowDiscardConfirm] = useState(false)
  const formRef = useRef<HTMLFormElement>(null)
  const createMessage = useCreateTicketMessage(ticketId)
  const pasteImage = usePasteImage(ticketId)
  const uploadAttachment = useUploadAttachment(ticketId)
  const user = useAuthStore((s) => s.user)
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
      { bodyMarkdown: body },
      {
        onSuccess: () => {
          setBody("")
          setFiles([])
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
      <Card className="border-border/60 border-l-2 border-l-primary/30">
        <CardHeader className="pb-3">
          <div className="flex items-center gap-2">
            <div className="flex h-6 w-6 items-center justify-center rounded-full bg-primary/10 text-xs font-medium text-primary">
              {userInitial}
            </div>
            <CardTitle className="text-sm font-medium">Reply</CardTitle>
            {showSuccess && (
              <div className="flex items-center gap-1 animate-in fade-in zoom-in duration-200">
                <Check className="h-4 w-4 text-green-500" />
                <span className="text-xs text-green-600">Sent</span>
              </div>
            )}
          </div>
        </CardHeader>
        <CardContent>
          <form ref={formRef} onSubmit={handleSubmit} onKeyDown={handleKeyDown} className="space-y-4">
            <MarkdownEditor
              value={body}
              onChange={setBody}
              placeholder="Write your reply... (Markdown supported, paste images with Ctrl+V)"
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
                  <Button type="submit" disabled={isSending || !body.trim()} className="shrink-0">
                    {isSending ? (
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    ) : (
                      <Send className="mr-2 h-4 w-4" />
                    )}
                    {isSending ? "Sending..." : "Send Reply"}
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
