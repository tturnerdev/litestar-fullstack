import { Download, DownloadCloud, File, FileText, ImageIcon, Paperclip } from "lucide-react"
import { useMemo, useState } from "react"
import { AttachmentPreview } from "@/components/support/attachment-preview"
import { Button } from "@/components/ui/button"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import type { TicketAttachment } from "@/lib/api/hooks/support"
import { formatBytes } from "@/lib/format-utils"
import { cn } from "@/lib/utils"

interface AttachmentListProps {
  attachments: TicketAttachment[]
  className?: string
}

function getFileIcon(contentType: string) {
  if (contentType.startsWith("image/")) return ImageIcon
  if (contentType === "application/pdf") return FileText
  return File
}

function getFileCategory(contentType: string): "image" | "document" | "other" {
  if (contentType.startsWith("image/")) return "image"
  if (contentType === "application/pdf" || contentType.startsWith("text/") || contentType.includes("document") || contentType.includes("spreadsheet")) return "document"
  return "other"
}

const chipStylesByCategory: Record<ReturnType<typeof getFileCategory>, string> = {
  image: "border-purple-500/30 hover:border-purple-500/50",
  document: "border-red-500/30 hover:border-red-500/50",
  other: "border-border/60 hover:border-border",
}

const iconStylesByCategory: Record<ReturnType<typeof getFileCategory>, string> = {
  image: "text-purple-500 dark:text-purple-400",
  document: "text-red-500 dark:text-red-400",
  other: "text-muted-foreground",
}

export function AttachmentList({ attachments, className }: AttachmentListProps) {
  const [previewAttachment, setPreviewAttachment] = useState<TicketAttachment | null>(null)

  const nonInlineAttachments = attachments.filter((a) => !a.isInline)

  const sortedAttachments = useMemo(() => {
    const order: Record<ReturnType<typeof getFileCategory>, number> = { image: 0, document: 1, other: 2 }
    return [...nonInlineAttachments].sort((a, b) => order[getFileCategory(a.contentType)] - order[getFileCategory(b.contentType)])
  }, [nonInlineAttachments])

  const totalBytes = useMemo(
    () => nonInlineAttachments.reduce((sum, a) => sum + a.fileSizeBytes, 0),
    [nonInlineAttachments],
  )

  if (nonInlineAttachments.length === 0) return null

  return (
    <>
      <div className={cn("space-y-2", className)}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-1.5 text-sm font-medium text-muted-foreground">
            <Paperclip className="h-4 w-4" />
            <span>Attachments ({nonInlineAttachments.length})</span>
          </div>
          {nonInlineAttachments.length > 1 && (
            <Button variant="ghost" size="sm" className="h-7 gap-1.5 text-xs" asChild>
              <a
                href={nonInlineAttachments.length === 1 ? (nonInlineAttachments[0].url ?? `/api/support/attachments/${nonInlineAttachments[0].id}`) : `/api/support/attachments/download-all?ids=${nonInlineAttachments.map((a) => a.id).join(",")}`}
                download
              >
                <DownloadCloud className="h-3.5 w-3.5" />
                Download all
              </a>
            </Button>
          )}
        </div>

        <div className="flex flex-wrap gap-2">
          {sortedAttachments.map((attachment) => {
            const Icon = getFileIcon(attachment.contentType)
            const category = getFileCategory(attachment.contentType)
            const isImage = category === "image"
            const isPreviewable = isImage || attachment.contentType === "application/pdf"
            const downloadUrl = attachment.url ?? `/api/support/attachments/${attachment.id}`

            return (
              <div
                key={attachment.id}
                className={cn(
                  "group flex items-center gap-2 rounded-md border bg-muted/20 px-2.5 py-1.5 text-sm transition-all hover:scale-[1.02] hover:bg-muted/40 hover:shadow-sm",
                  chipStylesByCategory[category],
                )}
              >
                {isImage && attachment.url ? (
                  <img
                    src={attachment.url}
                    alt={attachment.fileName}
                    className="h-8 w-8 shrink-0 rounded object-cover"
                  />
                ) : (
                  <Icon className={cn("h-4 w-4 shrink-0", iconStylesByCategory[category])} />
                )}
                {isPreviewable ? (
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <button
                        type="button"
                        onClick={() => setPreviewAttachment(attachment)}
                        className="max-w-[180px] truncate text-left hover:underline"
                      >
                        {attachment.fileName}
                      </button>
                    </TooltipTrigger>
                    <TooltipContent>{attachment.fileName}</TooltipContent>
                  </Tooltip>
                ) : (
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <span className="max-w-[180px] truncate">{attachment.fileName}</span>
                    </TooltipTrigger>
                    <TooltipContent>{attachment.fileName}</TooltipContent>
                  </Tooltip>
                )}
                <span className="text-xs text-muted-foreground">
                  {formatBytes(attachment.fileSizeBytes)}
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

        <p className="text-xs text-muted-foreground">
          {nonInlineAttachments.length} {nonInlineAttachments.length === 1 ? "file" : "files"}, {formatBytes(totalBytes)} total
        </p>
      </div>

      {previewAttachment && (
        <AttachmentPreview
          attachment={previewAttachment}
          onClose={() => setPreviewAttachment(null)}
          onPrev={(() => {
            const previewableAttachments = sortedAttachments.filter(
              (a) => a.contentType.startsWith("image/") || a.contentType === "application/pdf",
            )
            const idx = previewableAttachments.findIndex((a) => a.id === previewAttachment.id)
            if (idx > 0) return () => setPreviewAttachment(previewableAttachments[idx - 1])
            return undefined
          })()}
          onNext={(() => {
            const previewableAttachments = sortedAttachments.filter(
              (a) => a.contentType.startsWith("image/") || a.contentType === "application/pdf",
            )
            const idx = previewableAttachments.findIndex((a) => a.id === previewAttachment.id)
            if (idx < previewableAttachments.length - 1) return () => setPreviewAttachment(previewableAttachments[idx + 1])
            return undefined
          })()}
        />
      )}
    </>
  )
}
