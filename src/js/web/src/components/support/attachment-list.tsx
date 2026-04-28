import { Download, File, FileText, ImageIcon } from "lucide-react"
import { useState } from "react"
import { AttachmentPreview } from "@/components/support/attachment-preview"
import type { TicketAttachment } from "@/lib/api/hooks/support"
import { cn } from "@/lib/utils"

interface AttachmentListProps {
  attachments: TicketAttachment[]
  className?: string
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function getFileIcon(contentType: string) {
  if (contentType.startsWith("image/")) return ImageIcon
  if (contentType === "application/pdf") return FileText
  return File
}

export function AttachmentList({ attachments, className }: AttachmentListProps) {
  const [previewAttachment, setPreviewAttachment] = useState<TicketAttachment | null>(null)

  const nonInlineAttachments = attachments.filter((a) => !a.isInline)
  if (nonInlineAttachments.length === 0) return null

  return (
    <>
      <div className={cn("flex flex-wrap gap-2", className)}>
        {nonInlineAttachments.map((attachment) => {
          const Icon = getFileIcon(attachment.contentType)
          const isPreviewable =
            attachment.contentType.startsWith("image/") ||
            attachment.contentType === "application/pdf"
          const downloadUrl = attachment.url ?? `/api/support/attachments/${attachment.id}`

          return (
            <div
              key={attachment.id}
              className="group flex items-center gap-2 rounded-md border border-border/60 bg-muted/20 px-2.5 py-1.5 text-sm transition-colors hover:bg-muted/40"
            >
              <Icon className="h-4 w-4 shrink-0 text-muted-foreground" />
              {isPreviewable ? (
                <button
                  type="button"
                  onClick={() => setPreviewAttachment(attachment)}
                  className="max-w-[180px] truncate text-left hover:underline"
                >
                  {attachment.fileName}
                </button>
              ) : (
                <span className="max-w-[180px] truncate">{attachment.fileName}</span>
              )}
              <span className="text-xs text-muted-foreground">
                {formatFileSize(attachment.fileSizeBytes)}
              </span>
              <a
                href={downloadUrl}
                download={attachment.fileName}
                className="ml-0.5 rounded-sm p-0.5 text-muted-foreground opacity-0 transition-opacity hover:text-foreground group-hover:opacity-100"
              >
                <Download className="h-3.5 w-3.5" />
              </a>
            </div>
          )
        })}
      </div>

      {previewAttachment && (
        <AttachmentPreview
          attachment={previewAttachment}
          onClose={() => setPreviewAttachment(null)}
        />
      )}
    </>
  )
}
