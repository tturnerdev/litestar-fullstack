import {
  ChevronLeft,
  ChevronRight,
  Download,
  FileText,
  Maximize2,
  X,
  ZoomIn,
  ZoomOut,
} from "lucide-react"
import { useCallback, useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import type { TicketAttachment } from "@/lib/api/hooks/support"
import { formatBytes } from "@/lib/format-utils"

const MIN_ZOOM = 0.5
const MAX_ZOOM = 3
const ZOOM_STEP = 0.25
const DEFAULT_ZOOM = 1

interface AttachmentPreviewProps {
  attachment: TicketAttachment
  onClose: () => void
  onPrev?: () => void
  onNext?: () => void
}

export function AttachmentPreview({ attachment, onClose, onPrev, onNext }: AttachmentPreviewProps) {
  const downloadUrl = attachment.url ?? `/api/support/attachments/${attachment.id}`
  const isImage = attachment.contentType.startsWith("image/")
  const isPdf = attachment.contentType === "application/pdf"

  const [zoom, setZoom] = useState(DEFAULT_ZOOM)
  const [isLoaded, setIsLoaded] = useState(false)

  function handleZoomIn() {
    setZoom((prev) => Math.min(prev + ZOOM_STEP, MAX_ZOOM))
  }

  function handleZoomOut() {
    setZoom((prev) => Math.max(prev - ZOOM_STEP, MIN_ZOOM))
  }

  function handleFitToWindow() {
    setZoom(DEFAULT_ZOOM)
  }

  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      switch (e.key) {
        case "Escape":
          onClose()
          break
        case "ArrowLeft":
          onPrev?.()
          break
        case "ArrowRight":
          onNext?.()
          break
        case "+":
        case "=":
          e.preventDefault()
          setZoom((prev) => Math.min(prev + ZOOM_STEP, MAX_ZOOM))
          break
        case "-":
          e.preventDefault()
          setZoom((prev) => Math.max(prev - ZOOM_STEP, MIN_ZOOM))
          break
      }
    },
    [onClose, onPrev, onNext],
  )

  useEffect(() => {
    document.addEventListener("keydown", handleKeyDown)
    return () => document.removeEventListener("keydown", handleKeyDown)
  }, [handleKeyDown])

  // Reset loaded state and zoom when attachment changes
  useEffect(() => {
    setIsLoaded(false)
    setZoom(DEFAULT_ZOOM)
  }, [attachment.id])

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm animate-in fade-in duration-200"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <div className="relative mx-4 flex max-h-[90vh] max-w-[90vw] flex-col overflow-hidden rounded-lg border bg-background shadow-xl animate-in zoom-in-95 fade-in duration-200">
        {/* Header */}
        <div className="flex items-center justify-between border-b px-4 py-3">
          <div className="flex items-center gap-2 min-w-0">
            <FileText className="h-4 w-4 shrink-0 text-muted-foreground" />
            <h3 className="truncate text-sm font-medium">{attachment.fileName}</h3>
          </div>
          <div className="flex items-center gap-2">
            <Tooltip>
              <TooltipTrigger asChild>
                <Button variant="outline" size="sm" asChild>
                  <a href={downloadUrl} download={attachment.fileName}>
                    <Download className="mr-2 h-3.5 w-3.5" />
                    Download
                  </a>
                </Button>
              </TooltipTrigger>
              <TooltipContent>Download file</TooltipContent>
            </Tooltip>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button variant="ghost" size="sm" onClick={onClose} className="h-8 w-8 p-0">
                  <X className="h-4 w-4" />
                  <span className="sr-only">Close</span>
                </Button>
              </TooltipTrigger>
              <TooltipContent>Esc to close</TooltipContent>
            </Tooltip>
          </div>
        </div>

        {/* File info bar */}
        <div className="flex items-center justify-between border-b bg-muted/30 px-4 py-2">
          <div className="flex items-center gap-3 text-xs text-muted-foreground">
            <span>{formatBytes(attachment.fileSizeBytes)}</span>
            <span className="text-border">|</span>
            <span>{attachment.contentType}</span>
          </div>
          {isImage && (
            <div className="flex items-center gap-1">
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 w-7 p-0"
                    onClick={handleZoomOut}
                    disabled={zoom <= MIN_ZOOM}
                  >
                    <ZoomOut className="h-3.5 w-3.5" />
                    <span className="sr-only">Zoom out</span>
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Zoom out (-)</TooltipContent>
              </Tooltip>
              <span className="min-w-[3rem] text-center text-xs text-muted-foreground">
                {Math.round(zoom * 100)}%
              </span>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 w-7 p-0"
                    onClick={handleZoomIn}
                    disabled={zoom >= MAX_ZOOM}
                  >
                    <ZoomIn className="h-3.5 w-3.5" />
                    <span className="sr-only">Zoom in</span>
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Zoom in (+)</TooltipContent>
              </Tooltip>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 w-7 p-0"
                    onClick={handleFitToWindow}
                    disabled={zoom === DEFAULT_ZOOM}
                  >
                    <Maximize2 className="h-3.5 w-3.5" />
                    <span className="sr-only">Fit to window</span>
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Fit to window</TooltipContent>
              </Tooltip>
            </div>
          )}
        </div>

        {/* Content area */}
        <div className="relative flex-1 overflow-auto p-4">
          {/* Navigation arrows */}
          {onPrev && (
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="sm"
                  className="absolute left-2 top-1/2 z-10 h-8 w-8 -translate-y-1/2 rounded-full bg-background/80 p-0 shadow-sm hover:bg-background"
                  onClick={onPrev}
                >
                  <ChevronLeft className="h-4 w-4" />
                  <span className="sr-only">Previous</span>
                </Button>
              </TooltipTrigger>
              <TooltipContent side="right">Previous (Left arrow)</TooltipContent>
            </Tooltip>
          )}
          {onNext && (
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="sm"
                  className="absolute right-2 top-1/2 z-10 h-8 w-8 -translate-y-1/2 rounded-full bg-background/80 p-0 shadow-sm hover:bg-background"
                  onClick={onNext}
                >
                  <ChevronRight className="h-4 w-4" />
                  <span className="sr-only">Next</span>
                </Button>
              </TooltipTrigger>
              <TooltipContent side="left">Next (Right arrow)</TooltipContent>
            </Tooltip>
          )}

          {isImage && (
            <div className="flex items-center justify-center min-h-[200px]">
              {!isLoaded && <Skeleton className="absolute inset-4 rounded" />}
              <img
                src={downloadUrl}
                alt={attachment.fileName}
                className="mx-auto max-h-[70vh] rounded object-contain transition-transform duration-150"
                style={{ transform: `scale(${zoom})`, transformOrigin: "center center" }}
                onLoad={() => setIsLoaded(true)}
              />
            </div>
          )}
          {isPdf && (
            <div className="relative min-h-[200px]">
              {!isLoaded && <Skeleton className="absolute inset-0 rounded" />}
              <iframe
                src={downloadUrl}
                title={attachment.fileName}
                className="h-[70vh] w-full rounded"
                onLoad={() => setIsLoaded(true)}
              />
            </div>
          )}
          {!isImage && !isPdf && (
            <div className="flex h-[200px] flex-col items-center justify-center gap-2 text-muted-foreground">
              <FileText className="h-8 w-8" />
              <p className="text-sm">Preview not available for this file type.</p>
            </div>
          )}
        </div>

        {/* Keyboard hints */}
        <div className="border-t bg-muted/30 px-4 py-1.5">
          <p className="text-center text-[10px] text-muted-foreground">
            <kbd className="rounded bg-muted px-1 py-0.5 font-mono text-[10px]">Esc</kbd> close
            {isImage && (
              <>
                {" "}&middot;{" "}
                <kbd className="rounded bg-muted px-1 py-0.5 font-mono text-[10px]">+</kbd>
                <kbd className="rounded bg-muted px-1 py-0.5 font-mono text-[10px]">-</kbd> zoom
              </>
            )}
            {(onPrev || onNext) && (
              <>
                {" "}&middot;{" "}
                <kbd className="rounded bg-muted px-1 py-0.5 font-mono text-[10px]">&larr;</kbd>
                <kbd className="rounded bg-muted px-1 py-0.5 font-mono text-[10px]">&rarr;</kbd> navigate
              </>
            )}
          </p>
        </div>
      </div>
    </div>
  )
}
