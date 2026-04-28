import { Loader2, Send } from "lucide-react"
import { useCallback, useState } from "react"
import { AttachmentUpload, type PendingFile } from "@/components/support/attachment-upload"
import { useImagePasteHandler } from "@/components/support/image-paste-handler"
import { MarkdownEditor } from "@/components/support/markdown-editor"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { useCreateTicketMessage, usePasteImage, useUploadAttachment } from "@/lib/api/hooks/support"

export function TicketReplyForm({ ticketId }: { ticketId: string }) {
  const [body, setBody] = useState("")
  const [files, setFiles] = useState<PendingFile[]>([])
  const [isUploading, setIsUploading] = useState(false)
  const createMessage = useCreateTicketMessage(ticketId)
  const pasteImage = usePasteImage(ticketId)
  const uploadAttachment = useUploadAttachment(ticketId)

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
        },
      },
    )
  }

  const isSending = createMessage.isPending || uploadAttachment.isPending

  return (
    <Card className="border-border/60">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-medium">Reply</CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-4">
          <MarkdownEditor
            value={body}
            onChange={setBody}
            placeholder="Write your reply... (Markdown supported, paste images with Ctrl+V)"
            minHeight="120px"
            onPaste={handlePaste}
            onDrop={handleDrop}
            disabled={isSending}
          />
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
            <Button type="submit" disabled={isSending || !body.trim()} className="shrink-0">
              {isSending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Send className="mr-2 h-4 w-4" />
              )}
              {isSending ? "Sending..." : "Send Reply"}
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  )
}
