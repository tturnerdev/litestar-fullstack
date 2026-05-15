import { Download, FileText, Loader2, X } from "lucide-react"
import { useState } from "react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { type Attachment, downloadAttachment, formatBytes } from "@/lib/api/hooks/uploads"
import { cn } from "@/lib/utils"

interface AttachmentChipProps {
  attachment: Attachment
  /** When provided, renders a remove button that invokes this callback. */
  onRemove?: (attachment: Attachment) => void
  /** Disables the remove control without hiding it. */
  removing?: boolean
  className?: string
}

/**
 * Compact inline representation of an Attachment: filename, size, a download
 * action and (optionally) a remove action. Authenticated downloads are
 * performed via `fetchAttachmentObjectUrl` so the request carries the bearer
 * token regardless of how the cookie auth is configured.
 */
export function AttachmentChip({ attachment, onRemove, removing = false, className }: AttachmentChipProps) {
  const [isDownloading, setIsDownloading] = useState(false)

  const handleDownload = async () => {
    setIsDownloading(true)
    try {
      await downloadAttachment(attachment)
    } catch (error) {
      toast.error("Unable to download attachment", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    } finally {
      setIsDownloading(false)
    }
  }

  return (
    <div className={cn("inline-flex max-w-full items-center gap-2 rounded-md border border-border/60 bg-card/60 py-1 pl-2 pr-1 text-sm shadow-sm", className)}>
      <FileText className="h-4 w-4 shrink-0 text-muted-foreground" />
      <span className="min-w-0 truncate font-medium" title={attachment.originalFilename}>
        {attachment.originalFilename}
      </span>
      <span className="shrink-0 text-xs text-muted-foreground">{formatBytes(attachment.sizeBytes)}</span>
      <Button type="button" variant="ghost" size="sm" className="h-7 px-2" onClick={handleDownload} disabled={isDownloading} aria-label={`Download ${attachment.originalFilename}`}>
        {isDownloading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Download className="h-3.5 w-3.5" />}
      </Button>
      {onRemove && (
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className="h-7 px-2 text-muted-foreground hover:text-destructive"
          onClick={() => onRemove(attachment)}
          disabled={removing}
          aria-label={`Remove ${attachment.originalFilename}`}
        >
          {removing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <X className="h-3.5 w-3.5" />}
        </Button>
      )}
    </div>
  )
}
