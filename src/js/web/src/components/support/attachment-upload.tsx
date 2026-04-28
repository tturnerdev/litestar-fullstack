import { FileUp, Loader2, X } from "lucide-react"
import { useCallback, useRef, useState } from "react"
import { Button } from "@/components/ui/button"
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

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
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

  const addFiles = useCallback(
    (newFiles: FileList | File[]) => {
      const additions: PendingFile[] = Array.from(newFiles).map((file) => ({
        id: `file-${++fileIdCounter}`,
        file,
        name: file.name,
        size: file.size,
      }))
      onFilesChange([...files, ...additions])
    },
    [files, onFilesChange],
  )

  const removeFile = useCallback(
    (id: string) => {
      onFilesChange(files.filter((f) => f.id !== id))
    },
    [files, onFilesChange],
  )

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
        addFiles(e.dataTransfer.files)
      }
    },
    [addFiles],
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
            if (e.target.files) addFiles(e.target.files)
            e.target.value = ""
          }}
          disabled={disabled}
        />
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => fileInputRef.current?.click()}
          disabled={disabled || uploading}
        >
          {uploading ? (
            <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />
          ) : (
            <FileUp className="mr-2 h-3.5 w-3.5" />
          )}
          Attach files
        </Button>
        {files.length > 0 && (
          <div className="flex flex-wrap gap-2">
            {files.map((f) => (
              <div
                key={f.id}
                className="flex items-center gap-1.5 rounded-md border border-border/60 bg-muted/30 px-2 py-1 text-xs"
              >
                <span className="max-w-[150px] truncate">{f.name}</span>
                <span className="text-muted-foreground">({formatFileSize(f.size)})</span>
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
          if (e.target.files) addFiles(e.target.files)
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
          "flex cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed px-4 py-6 transition-colors",
          isDragging
            ? "border-primary/50 bg-primary/5"
            : "border-border/60 bg-muted/20 hover:border-border hover:bg-muted/40",
          disabled && "pointer-events-none opacity-50",
        )}
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
          <p className="text-xs text-muted-foreground">or click to browse</p>
        </div>
      </div>

      {files.length > 0 && (
        <div className="space-y-1.5">
          {files.map((f) => (
            <div
              key={f.id}
              className="flex items-center justify-between rounded-md border border-border/60 bg-muted/20 px-3 py-2"
            >
              <div className="flex items-center gap-2 min-w-0">
                <FileUp className="h-4 w-4 shrink-0 text-muted-foreground" />
                <span className="truncate text-sm">{f.name}</span>
                <span className="shrink-0 text-xs text-muted-foreground">
                  {formatFileSize(f.size)}
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
