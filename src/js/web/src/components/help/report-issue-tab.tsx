import html2canvas from "html2canvas-pro"
import { Bug, Camera, FileUp, HelpCircle, Lightbulb, Loader2, MessageSquare, X } from "lucide-react"
import { useCallback, useMemo, useRef, useState } from "react"
import { toast } from "sonner"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { Textarea } from "@/components/ui/textarea"
import { formatBytes } from "@/lib/format-utils"

const CATEGORIES = ["Error / Bug", "Comment", "Feature Request", "Other"] as const
export type IssueCategory = (typeof CATEGORIES)[number]

const CATEGORY_ICONS: Record<IssueCategory, React.ElementType> = {
  "Error / Bug": Bug,
  "Comment": MessageSquare,
  "Feature Request": Lightbulb,
  "Other": HelpCircle,
}

const MAX_DESCRIPTION_LENGTH = 2000
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

export function ReportIssueTab({ formData, onFormDataChange, onCaptureScreenshot, isCapturing }: ReportIssueTabProps) {
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [isSubmitting, setIsSubmitting] = useState(false)

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

  const totalAttachmentSize = useMemo(() => {
    return formData.files.reduce((sum, file) => sum + file.size, 0)
  }, [formData.files])

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

    setIsSubmitting(true)

    try {
      const body = new FormData()
      body.append("title", formData.title.trim())
      body.append("category", formData.category)
      body.append("description", formData.description.trim())

      // Convert base64 data URL screenshot to a File object
      if (formData.screenshot) {
        const res = await fetch(formData.screenshot)
        const blob = await res.blob()
        body.append("screenshot", new File([blob], "screenshot.png", { type: "image/png" }))
      }

      for (const file of formData.files) {
        body.append("files", file)
      }

      const headers: Record<string, string> = {}
      const token = window.localStorage.getItem("access_token")
      if (token) {
        headers["Authorization"] = `Bearer ${token}`
      }
      const csrfToken = window.__LITESTAR_CSRF__
      if (csrfToken) {
        headers["X-XSRF-TOKEN"] = csrfToken
      }

      const apiUrl = import.meta.env.VITE_API_URL ?? ""
      const response = await fetch(`${apiUrl}/api/support/feedback`, {
        method: "POST",
        headers,
        body,
        credentials: "include",
      })

      if (!response.ok) {
        const errorData = await response.json().catch(() => null)
        throw new Error(errorData?.detail ?? `Server error (${response.status})`)
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
    } catch (err) {
      toast.error("Failed to submit report", {
        description: err instanceof Error ? err.message : "Please try again later.",
      })
    } finally {
      setIsSubmitting(false)
    }
  }

  const attachmentCount = formData.files.length + (formData.screenshot ? 1 : 0)

  return (
    <form onSubmit={handleSubmit} className="space-y-4 pt-2">
      {/* --- Details Section --- */}
      <div className="grid gap-2">
        <Label htmlFor="report-title">
          Title <span className="text-destructive">*</span>
        </Label>
        <Input
          id="report-title"
          placeholder="Brief summary of the issue"
          value={formData.title}
          onChange={(e) => updateField("title", e.target.value)}
          required
        />
        <p className="text-xs text-muted-foreground">Concise summary of the issue or request</p>
      </div>

      <div className="grid gap-2">
        <Label htmlFor="report-category">
          Category <span className="text-destructive">*</span>
        </Label>
        <Select value={formData.category} onValueChange={(value) => updateField("category", value as IssueCategory)}>
          <SelectTrigger id="report-category">
            <SelectValue placeholder="Select a category" />
          </SelectTrigger>
          <SelectContent>
            {CATEGORIES.map((cat) => {
              const Icon = CATEGORY_ICONS[cat]
              return (
                <SelectItem key={cat} value={cat}>
                  <span className="flex items-center gap-2">
                    <Icon className="size-4 text-muted-foreground" />
                    {cat}
                  </span>
                </SelectItem>
              )
            })}
          </SelectContent>
        </Select>
      </div>

      <div className="grid gap-2">
        <Label htmlFor="report-description">
          Description <span className="text-destructive">*</span>
        </Label>
        <Textarea
          id="report-description"
          placeholder="Describe the issue in detail. Include steps to reproduce if applicable."
          value={formData.description}
          onChange={(e) => {
            if (e.target.value.length <= MAX_DESCRIPTION_LENGTH) {
              updateField("description", e.target.value)
            }
          }}
          rows={4}
          required
        />
        <div className="flex items-center justify-between">
          <p className="text-xs text-muted-foreground">Be as specific as possible</p>
          <span
            className={`text-xs ${
              formData.description.length > MAX_DESCRIPTION_LENGTH * 0.9
                ? "text-destructive"
                : "text-muted-foreground"
            }`}
          >
            {formData.description.length}/{MAX_DESCRIPTION_LENGTH}
          </span>
        </div>
      </div>

      <Separator />

      {/* --- Screenshot Section --- */}
      <div className="grid gap-2">
        <Label>Screenshot</Label>
        <div className="rounded-md border-2 border-dashed border-border/60 p-4">
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
            <div className="flex flex-col items-center gap-2 py-2 text-center">
              <Camera className="size-8 text-muted-foreground/50" />
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
              <p className="text-xs text-muted-foreground">
                Captures the current portal view behind this dialog
              </p>
            </div>
          )}
        </div>
      </div>

      <Separator />

      {/* --- Attachments Section --- */}
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
          <>
            <ul className="space-y-1">
              {formData.files.map((file, index) => (
                <li key={`${file.name}-${index}`} className="flex items-center justify-between rounded-md border border-border/60 bg-card/50 px-3 py-1.5 text-sm">
                  <span className="truncate pr-2">
                    {file.name}
                    <span className="ml-2 text-xs text-muted-foreground">{formatBytes(file.size)}</span>
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
            <p className="text-xs text-muted-foreground">
              {formData.files.length} {formData.files.length === 1 ? "file" : "files"}, {formatBytes(totalAttachmentSize)} total
            </p>
          </>
        )}
      </div>

      <Separator />

      {/* --- Preview Section --- */}
      {(formData.title || formData.category || attachmentCount > 0) && (
        <div className="rounded-md border border-border bg-muted/30 p-3">
          <p className="mb-2 text-xs font-medium text-muted-foreground uppercase tracking-wide">Submission Preview</p>
          <div className="space-y-1 text-sm">
            {formData.title && (
              <div className="flex items-center gap-2">
                <span className="text-muted-foreground">Title:</span>
                <span className="font-medium truncate">{formData.title}</span>
              </div>
            )}
            {formData.category && (
              <div className="flex items-center gap-2">
                <span className="text-muted-foreground">Category:</span>
                <Badge variant="secondary" className="text-xs">
                  {formData.category}
                </Badge>
              </div>
            )}
            {attachmentCount > 0 && (
              <div className="flex items-center gap-2">
                <span className="text-muted-foreground">Attachments:</span>
                <span>{attachmentCount} {attachmentCount === 1 ? "item" : "items"}</span>
              </div>
            )}
          </div>
        </div>
      )}

      <div className="flex justify-end pt-2">
        <Button type="submit" disabled={isSubmitting}>
          {isSubmitting ? (
            <>
              <Loader2 className="size-4 animate-spin" />
              Submitting...
            </>
          ) : (
            "Submit Report"
          )}
        </Button>
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
