import html2canvas from "html2canvas-pro"
import { Camera, FileUp, Loader2, X } from "lucide-react"
import { useCallback, useRef } from "react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"

const CATEGORIES = ["Bug", "Feature Request", "Performance Issue", "UI/UX Issue", "Other"] as const
export type IssueCategory = (typeof CATEGORIES)[number]

const MAX_FILE_SIZE = 10 * 1024 * 1024 // 10MB
const ACCEPTED_EXTENSIONS = ".png,.jpg,.jpeg,.gif,.webp,.pdf,.txt,.log,.csv"

export interface ReportFormData {
  title: string
  category: IssueCategory | ""
  description: string
  screenshot: string | null
  files: File[]
}

interface ReportIssueTabProps {
  formData: ReportFormData
  onFormDataChange: (data: ReportFormData) => void
  onCaptureScreenshot: () => void
  isCapturing: boolean
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

export function ReportIssueTab({ formData, onFormDataChange, onCaptureScreenshot, isCapturing }: ReportIssueTabProps) {
  const fileInputRef = useRef<HTMLInputElement>(null)

  const updateField = useCallback(
    <K extends keyof ReportFormData>(field: K, value: ReportFormData[K]) => {
      onFormDataChange({ ...formData, [field]: value })
    },
    [formData, onFormDataChange],
  )

  const handleFileChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const selectedFiles = Array.from(e.target.files ?? [])
      const validFiles: File[] = []

      for (const file of selectedFiles) {
        if (file.size > MAX_FILE_SIZE) {
          toast.error(`"${file.name}" exceeds the 10MB size limit`)
          continue
        }
        validFiles.push(file)
      }

      onFormDataChange({ ...formData, files: [...formData.files, ...validFiles] })

      if (fileInputRef.current) {
        fileInputRef.current.value = ""
      }
    },
    [formData, onFormDataChange],
  )

  const removeFile = useCallback(
    (index: number) => {
      const next = formData.files.filter((_, i) => i !== index)
      onFormDataChange({ ...formData, files: next })
    },
    [formData, onFormDataChange],
  )

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!formData.title.trim()) {
      toast.error("Please enter a title")
      return
    }
    if (!formData.category) {
      toast.error("Please select a category")
      return
    }
    if (!formData.description.trim()) {
      toast.error("Please enter a description")
      return
    }

    const payload = {
      title: formData.title.trim(),
      category: formData.category,
      description: formData.description.trim(),
      screenshotAttached: !!formData.screenshot,
      fileCount: formData.files.length,
    }

    console.log("[Help] Issue report submitted:", payload)
    if (formData.screenshot) {
      console.log("[Help] Screenshot data URL length:", formData.screenshot.length)
    }
    for (const file of formData.files) {
      console.log("[Help] Attached file:", file.name, formatFileSize(file.size))
    }

    toast.success("Issue report submitted successfully", {
      description: "Thank you for your feedback. Our team will review it shortly.",
    })

    onFormDataChange({
      title: "",
      category: "",
      description: "",
      screenshot: null,
      files: [],
    })
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4 pt-2">
      <div className="grid gap-2">
        <Label htmlFor="report-title">Title</Label>
        <Input
          id="report-title"
          placeholder="Brief summary of the issue"
          value={formData.title}
          onChange={(e) => updateField("title", e.target.value)}
          required
        />
      </div>

      <div className="grid gap-2">
        <Label htmlFor="report-category">Category</Label>
        <Select value={formData.category} onValueChange={(value) => updateField("category", value as IssueCategory)}>
          <SelectTrigger id="report-category">
            <SelectValue placeholder="Select a category" />
          </SelectTrigger>
          <SelectContent>
            {CATEGORIES.map((cat) => (
              <SelectItem key={cat} value={cat}>
                {cat}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="grid gap-2">
        <Label htmlFor="report-description">Description</Label>
        <Textarea
          id="report-description"
          placeholder="Describe the issue in detail. Include steps to reproduce if applicable."
          value={formData.description}
          onChange={(e) => updateField("description", e.target.value)}
          rows={4}
          required
        />
      </div>

      <div className="grid gap-2">
        <Label>Screenshot</Label>
        {formData.screenshot ? (
          <div className="relative inline-block">
            <img
              src={formData.screenshot}
              alt="Captured screenshot"
              className="max-h-40 rounded-md border border-border object-contain"
            />
            <button
              type="button"
              onClick={() => updateField("screenshot", null)}
              className="absolute -top-2 -right-2 flex size-5 items-center justify-center rounded-full bg-destructive text-white shadow-sm transition-opacity hover:opacity-90"
            >
              <X className="size-3" />
            </button>
          </div>
        ) : (
          <Button type="button" variant="outline" size="sm" onClick={onCaptureScreenshot} disabled={isCapturing}>
            {isCapturing ? (
              <>
                <Loader2 className="size-4 animate-spin" />
                Capturing...
              </>
            ) : (
              <>
                <Camera className="size-4" />
                Capture Screenshot
              </>
            )}
          </Button>
        )}
        <p className="text-xs text-muted-foreground">
          Captures the current portal view behind this dialog
        </p>
      </div>

      <div className="grid gap-2">
        <Label>Attachments</Label>
        <div className="flex items-center gap-2">
          <Button type="button" variant="outline" size="sm" onClick={() => fileInputRef.current?.click()}>
            <FileUp className="size-4" />
            Attach Files
          </Button>
          <span className="text-xs text-muted-foreground">Max 10MB per file</span>
        </div>
        <input
          ref={fileInputRef}
          type="file"
          accept={ACCEPTED_EXTENSIONS}
          multiple
          onChange={handleFileChange}
          className="hidden"
        />
        {formData.files.length > 0 && (
          <ul className="space-y-1">
            {formData.files.map((file, index) => (
              <li key={`${file.name}-${index}`} className="flex items-center justify-between rounded-md border border-border/60 bg-card/50 px-3 py-1.5 text-sm">
                <span className="truncate pr-2">
                  {file.name}
                  <span className="ml-2 text-xs text-muted-foreground">{formatFileSize(file.size)}</span>
                </span>
                <button
                  type="button"
                  onClick={() => removeFile(index)}
                  className="shrink-0 text-muted-foreground transition-colors hover:text-destructive"
                >
                  <X className="size-4" />
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="flex justify-end pt-2">
        <Button type="submit">Submit Report</Button>
      </div>
    </form>
  )
}

export async function captureScreenshot(): Promise<string> {
  const canvas = await html2canvas(document.body, {
    useCORS: true,
    allowTaint: true,
    scale: window.devicePixelRatio > 1 ? 1.5 : 1,
    logging: false,
    ignoreElements: (element) => {
      // Ignore radix overlays and portals so the dialog is not captured
      const isOverlay = element.hasAttribute("data-slot") && element.getAttribute("data-slot") === "dialog-overlay"
      const isDialogContent = element.hasAttribute("data-slot") && element.getAttribute("data-slot") === "dialog-content"
      return isOverlay || isDialogContent
    },
  })
  return canvas.toDataURL("image/png")
}
