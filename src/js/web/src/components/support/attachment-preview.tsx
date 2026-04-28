import { Download, X } from "lucide-react"
import { useCallback, useEffect } from "react"
import { Button } from "@/components/ui/button"
import type { TicketAttachment } from "@/lib/api/hooks/support"

interface AttachmentPreviewProps {
  attachment: TicketAttachment
  onClose: () => void
}

export function AttachmentPreview({ attachment, onClose }: AttachmentPreviewProps) {
  const downloadUrl = attachment.url ?? `/api/support/attachments/${attachment.id}`
  const isImage = attachment.contentType.startsWith("image/")
  const isPdf = attachment.contentType === "application/pdf"

  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose()
    },
    [onClose],
  )

  useEffect(() => {
    document.addEventListener("keydown", handleKeyDown)
    return () => document.removeEventListener("keydown", handleKeyDown)
  }, [handleKeyDown])

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <div className="relative mx-4 flex max-h-[90vh] max-w-[90vw] flex-col overflow-hidden rounded-lg border bg-background shadow-xl">
        <div className="flex items-center justify-between border-b px-4 py-3">
          <h3 className="truncate text-sm font-medium">{attachment.fileName}</h3>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" asChild>
              <a href={downloadUrl} download={attachment.fileName}>
                <Download className="mr-2 h-3.5 w-3.5" />
                Download
              </a>
            </Button>
            <Button variant="ghost" size="sm" onClick={onClose} className="h-8 w-8 p-0">
              <X className="h-4 w-4" />
              <span className="sr-only">Close</span>
            </Button>
          </div>
        </div>
        <div className="flex-1 overflow-auto p-4">
          {isImage && (
            <img
              src={downloadUrl}
              alt={attachment.fileName}
              className="mx-auto max-h-[70vh] rounded object-contain"
            />
          )}
          {isPdf && (
            <iframe
              src={downloadUrl}
              title={attachment.fileName}
              className="h-[70vh] w-full rounded"
            />
          )}
        </div>
      </div>
    </div>
  )
}
