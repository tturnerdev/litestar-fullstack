import { useCallback } from "react"
import type { PastedImage } from "@/lib/api/hooks/support"

interface ImagePasteHandlerOptions {
  onUpload: (blob: Blob) => Promise<PastedImage>
  onInsert: (markdownImage: string) => void
  onUploadStart?: () => void
  onUploadEnd?: () => void
}

export function useImagePasteHandler({ onUpload, onInsert, onUploadStart, onUploadEnd }: ImagePasteHandlerOptions) {
  const handlePaste = useCallback(
    async (e: React.ClipboardEvent<HTMLTextAreaElement>) => {
      const items = e.clipboardData?.items
      if (!items) return

      for (const item of Array.from(items)) {
        if (item.type.startsWith("image/")) {
          e.preventDefault()
          const blob = item.getAsFile()
          if (!blob) continue

          onUploadStart?.()
          try {
            const result = await onUpload(blob)
            onInsert(`![${result.fileName}](${result.url})`)
          } catch {
            // Error toast handled by the mutation hook
          } finally {
            onUploadEnd?.()
          }
          return
        }
      }
    },
    [onUpload, onInsert, onUploadStart, onUploadEnd],
  )

  const handleDrop = useCallback(
    async (e: React.DragEvent<HTMLTextAreaElement>) => {
      const files = e.dataTransfer?.files
      if (!files) return

      for (const file of Array.from(files)) {
        if (file.type.startsWith("image/")) {
          e.preventDefault()
          onUploadStart?.()
          try {
            const result = await onUpload(file)
            onInsert(`![${result.fileName}](${result.url})`)
          } catch {
            // Error toast handled by the mutation hook
          } finally {
            onUploadEnd?.()
          }
          return
        }
      }
    },
    [onUpload, onInsert, onUploadStart, onUploadEnd],
  )

  return { handlePaste, handleDrop }
}
