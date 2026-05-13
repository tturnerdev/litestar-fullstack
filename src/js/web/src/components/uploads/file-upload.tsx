import { AlertCircle, Loader2, Upload, X } from "lucide-react"
import { useCallback, useId, useRef, useState } from "react"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { type Attachment, type AttachmentPurpose, formatBytes, MAX_UPLOAD_SIZE_BYTES, useUploadFile } from "@/lib/api/hooks/uploads"
import { cn } from "@/lib/utils"

interface FileUploadProps {
  /**
   * Comma-separated `accept` value for the file input, e.g. `image/*` or
   * `.pdf,.png`. Optional.
   */
  accept?: string
  /** Maps to the `?purpose=` query parameter. Defaults to "attachment". */
  purpose?: AttachmentPurpose
  /** Override the client-side size cap (defaults to the server-side 25 MiB). */
  maxSizeBytes?: number
  /** Compact rendering (no drop-zone, just a button). */
  compact?: boolean
  /** Label rendered on the trigger button. */
  buttonLabel?: string
  /** Helper copy shown beneath the drop zone. */
  description?: string
  className?: string
  /** Fired with the created Attachment on a successful upload. */
  onUploaded?: (attachment: Attachment) => void
}

/**
 * Reusable file picker / drag-and-drop component that uploads to
 * `POST /api/uploads`. Mirrors the server-side 25 MiB cap client-side and
 * surfaces server error messages inline.
 */
export function FileUpload({
  accept,
  purpose = "attachment",
  maxSizeBytes = MAX_UPLOAD_SIZE_BYTES,
  compact = false,
  buttonLabel = "Choose file",
  description,
  className,
  onUploaded,
}: FileUploadProps) {
  const inputId = useId()
  const inputRef = useRef<HTMLInputElement | null>(null)
  const upload = useUploadFile()
  const [dragActive, setDragActive] = useState(false)
  const [progress, setProgress] = useState(0)
  const [error, setError] = useState<string | null>(null)

  const acceptsType = useCallback(
    (file: File): boolean => {
      if (!accept) {
        return true
      }
      const entries = accept
        .split(",")
        .map((entry) => entry.trim().toLowerCase())
        .filter(Boolean)
      if (entries.length === 0) {
        return true
      }
      const name = file.name.toLowerCase()
      const type = file.type.toLowerCase()
      return entries.some((entry) => {
        if (entry.startsWith(".")) {
          return name.endsWith(entry)
        }
        if (entry.endsWith("/*")) {
          return type.startsWith(entry.slice(0, -1))
        }
        return type === entry
      })
    },
    [accept],
  )

  const startUpload = useCallback(
    async (file: File) => {
      setError(null)
      if (!acceptsType(file)) {
        setError(`File type not allowed. Accepted: ${accept}`)
        return
      }
      if (file.size > maxSizeBytes) {
        setError(`File is too large (max ${formatBytes(maxSizeBytes)}).`)
        return
      }
      setProgress(0)
      try {
        const attachment = await upload.mutateAsync({
          file,
          purpose,
          onProgress: setProgress,
        })
        onUploaded?.(attachment)
      } catch (err) {
        const detail =
          typeof err === "object" && err && "detail" in err && typeof (err as { detail: unknown }).detail === "string"
            ? (err as { detail: string }).detail
            : err instanceof Error
              ? err.message
              : "Upload failed"
        setError(detail)
      } finally {
        setProgress(0)
        if (inputRef.current) {
          inputRef.current.value = ""
        }
      }
    },
    [accept, acceptsType, maxSizeBytes, onUploaded, purpose, upload.mutateAsync],
  )

  const handleFiles = useCallback(
    (files: FileList | null) => {
      if (!files || files.length === 0) {
        return
      }
      void startUpload(files[0])
    },
    [startUpload],
  )

  const onDragOver = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault()
    event.stopPropagation()
    if (!upload.isPending) {
      setDragActive(true)
    }
  }

  const onDragLeave = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault()
    event.stopPropagation()
    setDragActive(false)
  }

  const onDrop = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault()
    event.stopPropagation()
    setDragActive(false)
    if (upload.isPending) {
      return
    }
    handleFiles(event.dataTransfer.files)
  }

  const triggerPicker = () => {
    inputRef.current?.click()
  }

  const isPending = upload.isPending

  if (compact) {
    return (
      <div className={cn("inline-flex flex-col gap-2", className)}>
        <input
          ref={inputRef}
          id={inputId}
          type="file"
          accept={accept}
          className="sr-only"
          disabled={isPending}
          onChange={(event) => handleFiles(event.target.files)}
        />
        <Button type="button" variant="outline" onClick={triggerPicker} disabled={isPending}>
          {isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Upload className="h-4 w-4" />}
          {isPending ? `Uploading… ${progress}%` : buttonLabel}
        </Button>
        {error && (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
      </div>
    )
  }

  return (
    <div className={cn("flex flex-col gap-3", className)}>
      <div
        role="button"
        tabIndex={0}
        onClick={triggerPicker}
        onKeyDown={(event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault()
            triggerPicker()
          }
        }}
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        onDrop={onDrop}
        aria-disabled={isPending}
        className={cn(
          "flex flex-col items-center justify-center gap-3 rounded-xl border-2 border-dashed border-border/70 bg-card/40 px-6 py-10 text-center transition-colors",
          "hover:border-primary/50 hover:bg-card/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/50",
          dragActive && "border-primary bg-primary/5",
          isPending && "cursor-progress opacity-80",
        )}
      >
        <input
          ref={inputRef}
          id={inputId}
          type="file"
          accept={accept}
          className="sr-only"
          disabled={isPending}
          onChange={(event) => handleFiles(event.target.files)}
        />
        <div className="flex h-12 w-12 items-center justify-center rounded-full bg-muted text-muted-foreground">
          {isPending ? <Loader2 className="h-5 w-5 animate-spin" /> : <Upload className="h-5 w-5" />}
        </div>
        <div className="space-y-1">
          <p className="text-sm font-medium">{isPending ? `Uploading… ${progress}%` : "Drop a file here, or click to browse"}</p>
          <p className="text-xs text-muted-foreground">{description ?? `Up to ${formatBytes(maxSizeBytes)}.${accept ? ` Accepted: ${accept}` : ""}`}</p>
        </div>
        {isPending ? (
          <div className="w-full max-w-xs">
            <div
              role="progressbar"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={progress}
              aria-label="Upload progress"
              className="h-1.5 w-full overflow-hidden rounded-full bg-muted"
            >
              <div className="h-full bg-primary transition-[width]" style={{ width: `${progress}%` }} />
            </div>
          </div>
        ) : (
          <span className="pointer-events-none inline-flex items-center gap-2 rounded-md border bg-background px-3 py-1.5 text-sm font-medium shadow-xs">
            <Upload className="h-4 w-4" />
            {buttonLabel}
          </span>
        )}
      </div>
      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription className="flex items-center justify-between gap-2">
            <span>{error}</span>
            <button type="button" onClick={() => setError(null)} className="text-xs underline-offset-2 hover:underline" aria-label="Dismiss error">
              <X className="h-3 w-3" />
            </button>
          </AlertDescription>
        </Alert>
      )}
    </div>
  )
}
