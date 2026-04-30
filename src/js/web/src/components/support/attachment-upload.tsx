import { File as FileIcon, FileText, FileUp, Image, Loader2, X } from "lucide-react"
import { useCallback, useRef, useState } from "react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { formatBytes } from "@/lib/format-utils"
import { cn } from "@/lib/utils"

interface PendingFile {
  id: string
  file: File
  name: string
  size: number
}

interface AttachmentUploadProps {
  files: PendingFile[]
  onFilesChange: (files: PendingFile[]) => void
  uploading?: boolean
  disabled?: boolean
  compact?: boolean
}

const MAX_FILE_SIZE = 10 * 1024 * 1024 // 10 MB

const ALLOWED_EXTENSIONS = new Set([
  // Images
  "jpg", "jpeg", "png", "gif", "webp", "svg", "bmp", "ico",
  // Documents
  "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv", "rtf",
  // Archives
  "zip", "tar", "gz", "rar", "7z",
])

function getFileExtension(name: string): string {
  const parts = name.split(".")
  return parts.length > 1 ? parts[parts.length - 1].toLowerCase() : ""
}

function isImageFile(name: string): boolean {
  const ext = getFileExtension(name)
  return ["jpg", "jpeg", "png", "gif", "webp", "svg", "bmp", "ico"].includes(ext)
}

function isPdfFile(name: string): boolean {
  return getFileExtension(name) === "pdf"
}

function getFileTypeIcon(name: string, className: string) {
  if (isImageFile(name)) return <Image className={className} />
  if (isPdfFile(name)) return <FileText className={className} />
  return <FileIcon className={className} />
}

function getFileTypeBorderColor(name: string): string {
  if (isImageFile(name)) return "border-l-blue-400"
  if (isPdfFile(name)) return "border-l-red-400"
  return "border-l-gray-400"
}

let fileIdCounter = 0

export function AttachmentUpload({
  files,
  onFilesChange,
  uploading = false,
  disabled = false,
  compact = false,
}: AttachmentUploadProps) {
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [isDragging, setIsDragging] = useState(false)

  const validateAndAddFiles = useCallback(
    (newFiles: FileList | File[]) => {
      const valid: PendingFile[] = []
      for (const file of Array.from(newFiles)) {
        const ext = getFileExtension(file.name)
        if (!ext || !ALLOWED_EXTENSIONS.has(ext)) {
          toast.error(`"${file.name}" is not a supported file type`, {
            description: "Allowed: images, PDFs, documents, and archives.",
          })
          continue
        }
        if (file.size > MAX_FILE_SIZE) {
          toast.error(`"${file.name}" exceeds the 10 MB limit`, {
            description: `File size: ${formatBytes(file.size)}.`,
          })
          continue
        }
        valid.push({
          id: `file-${++fileIdCounter}`,
          file,
          name: file.name,
          size: file.size,
        })
      }
      if (valid.length > 0) {
        onFilesChange([...files, ...valid])
      }
    },
    [files, onFilesChange],
  )

  const removeFile = useCallback(
    (id: string) => {
      onFilesChange(files.filter((f) => f.id !== id))
    },
    [files, onFilesChange],
  )

  const clearAll = useCallback(() => {
    onFilesChange([])
  }, [onFilesChange])

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(true)
  }, [])

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(false)
  }, [])

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault()
      setIsDragging(false)
      if (e.dataTransfer.files.length > 0) {
        validateAndAddFiles(e.dataTransfer.files)
      }
    },
    [validateAndAddFiles],
  )

  if (compact) {
    return (
      <div className="space-y-2">
        <input
          ref={fileInputRef}
          type="file"
          multiple
          className="hidden"
          onChange={(e) => {
            if (e.target.files) validateAndAddFiles(e.target.files)
            e.target.value = ""
          }}
          disabled={disabled}
        />
        <div className="flex items-center gap-2">
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="relative"
            onClick={() => fileInputRef.current?.click()}
            disabled={disabled || uploading}
          >
            {uploading ? (
              <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />
            ) : (
              <FileUp className="mr-2 h-3.5 w-3.5" />
            )}
            Attach files
            {files.length > 0 && (
              <span className="absolute -right-1.5 -top-1.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-primary px-1 text-[10px] font-medium text-primary-foreground">
                {files.length}
              </span>
            )}
          </Button>
          {files.length >= 2 && (
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="h-7 w-7 p-0 text-muted-foreground hover:text-foreground"
              onClick={clearAll}
            >
              <X className="h-3.5 w-3.5" />
            </Button>
          )}
        </div>
        {files.length > 0 && (
          <div className="flex flex-wrap gap-2">
            {files.map((f) => (
              <div
                key={f.id}
                className={cn(
                  "flex items-center gap-1.5 rounded-md border border-border/60 border-l-2 bg-muted/30 px-2 py-1 text-xs",
                  getFileTypeBorderColor(f.name),
                  uploading && "animate-pulse",
                )}
              >
                {getFileTypeIcon(f.name, "h-3 w-3 shrink-0 text-muted-foreground")}
                <Tooltip>
                  <TooltipTrigger asChild>
                    <span className="max-w-[150px] truncate">{f.name}</span>
                  </TooltipTrigger>
                  <TooltipContent>{f.name}</TooltipContent>
                </Tooltip>
                <span className="text-muted-foreground">({formatBytes(f.size)})</span>
                <button
                  type="button"
                  onClick={() => removeFile(f.id)}
                  className="ml-0.5 rounded-sm p-0.5 text-muted-foreground hover:bg-muted hover:text-foreground"
                >
                  <X className="h-3 w-3" />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    )
  }

  return (
    <div className="space-y-3">
      <input
        ref={fileInputRef}
        type="file"
        multiple
        className="hidden"
        onChange={(e) => {
          if (e.target.files) validateAndAddFiles(e.target.files)
          e.target.value = ""
        }}
        disabled={disabled}
      />
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        className={cn(
          "flex cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed px-4 py-6 transition-all",
          isDragging
            ? "border-primary/50 bg-primary/5 [animation:border-dash_8s_linear_infinite]"
            : "border-border/60 bg-muted/20 hover:border-border hover:bg-muted/40",
          disabled && "pointer-events-none opacity-50",
        )}
        style={
          isDragging
            ? {
                backgroundImage:
                  "repeating-linear-gradient(90deg, transparent, transparent 6px, hsl(var(--primary) / 0.08) 6px, hsl(var(--primary) / 0.08) 12px)",
                backgroundSize: "12px 100%",
              }
            : undefined
        }
      >
        {uploading ? (
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        ) : (
          <FileUp className="h-6 w-6 text-muted-foreground" />
        )}
        <div className="text-center">
          <p className="text-sm font-medium">
            {isDragging ? "Drop files here" : "Drag & drop files here"}
          </p>
          <p className="text-xs text-muted-foreground">or click to browse (max 10 MB per file)</p>
        </div>
      </div>

      {files.length > 0 && (
        <div className="space-y-1.5">
          <div className="flex items-center justify-between">
            <span className="text-xs text-muted-foreground">
              {files.length} file{files.length !== 1 ? "s" : ""} selected
            </span>
            {files.length >= 2 && (
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="h-6 gap-1 px-2 text-xs text-muted-foreground hover:text-foreground"
                onClick={clearAll}
              >
                <X className="h-3 w-3" />
                Clear all
              </Button>
            )}
          </div>
          {files.map((f) => (
            <div
              key={f.id}
              className={cn(
                "flex items-center justify-between rounded-md border border-border/60 border-l-2 bg-muted/20 px-3 py-2",
                getFileTypeBorderColor(f.name),
                uploading && "animate-pulse",
              )}
            >
              <div className="flex items-center gap-2 min-w-0">
                {getFileTypeIcon(f.name, "h-4 w-4 shrink-0 text-muted-foreground")}
                <Tooltip>
                  <TooltipTrigger asChild>
                    <span className="truncate text-sm">{f.name}</span>
                  </TooltipTrigger>
                  <TooltipContent>{f.name}</TooltipContent>
                </Tooltip>
                <span className="shrink-0 text-xs text-muted-foreground">
                  {formatBytes(f.size)}
                </span>
              </div>
              <button
                type="button"
                onClick={() => removeFile(f.id)}
                className="ml-2 rounded-sm p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export type { PendingFile }
