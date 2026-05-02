import { Link } from "@tanstack/react-router"
import { AlertCircle, CheckCircle2, Clock, FileText, FileUp, Info, Loader2, Phone, Send, Upload, X } from "lucide-react"
import { useCallback, useMemo, useRef, useState } from "react"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useFaxMessages, useFaxNumbers, useSendFax } from "@/lib/api/hooks/fax"
import { formatBytes } from "@/lib/format-utils"

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PHONE_REGEX = /^\+?[1-9]\d{1,14}$/
const ACCEPTED_TYPES = ["application/pdf", "image/tiff"]
const ACCEPTED_EXTENSIONS = ".pdf,.tif,.tiff"
const MAX_FILE_SIZE = 20 * 1024 * 1024
const MAX_TEXT_LENGTH = 5000
const MAX_RECENT_RECIPIENTS = 5

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Format phone number input as user types: +1 (212) 555-1234 */
function formatPhoneDisplay(value: string): string {
  const digits = value.replace(/\D/g, "")
  if (digits.length === 0) return ""
  // US numbers: +1 (XXX) XXX-XXXX
  if (digits.length <= 1) return `+${digits}`
  if (digits.length <= 4) return `+${digits[0]} (${digits.slice(1)}`
  if (digits.length <= 7) return `+${digits[0]} (${digits.slice(1, 4)}) ${digits.slice(4)}`
  if (digits.length <= 11) return `+${digits[0]} (${digits.slice(1, 4)}) ${digits.slice(4, 7)}-${digits.slice(7, 11)}`
  // International — just group
  return `+${digits}`
}

/** Strip formatting to get raw number for API */
function stripPhone(value: string): string {
  const stripped = value.replace(/[\s()-]/g, "")
  return stripped.startsWith("+") ? stripped : `+${stripped}`
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function SendFaxForm() {
  const { data: faxNumbers, isLoading } = useFaxNumbers(1, 100)
  const { data: recentMessages } = useFaxMessages({
    direction: "outbound",
    pageSize: 50,
    sortOrder: "desc",
    orderBy: "createdAt",
  })
  const sendFax = useSendFax()
  const fileInputRef = useRef<HTMLInputElement>(null)
  const dropZoneRef = useRef<HTMLDivElement>(null)

  // Form state
  const [faxNumberId, setFaxNumberId] = useState("")
  const [remoteNumber, setRemoteNumber] = useState("")
  const [contentMode, setContentMode] = useState<"file" | "text">("file")
  const [textBody, setTextBody] = useState("")
  const [file, setFile] = useState<File | null>(null)
  const [previewUrl, setPreviewUrl] = useState<string | null>(null)

  // Validation state
  const [numberError, setNumberError] = useState<string | null>(null)
  const [fileError, setFileError] = useState<string | null>(null)
  const [senderError, setSenderError] = useState<string | null>(null)

  // UX state
  const [isDragging, setIsDragging] = useState(false)
  const [showConfirmDialog, setShowConfirmDialog] = useState(false)
  const [showSuccessState, setShowSuccessState] = useState(false)
  const [sentMessageId, setSentMessageId] = useState<string | null>(null)

  // Derived
  const activeNumbers = faxNumbers?.items.filter((n) => n.isActive) ?? []
  const selectedNumber = activeNumbers.find((n) => n.id === faxNumberId)
  const hasContent = contentMode === "file" ? !!file : textBody.trim().length > 0
  const canSubmit = !!faxNumberId && !!remoteNumber.trim() && hasContent && !sendFax.isPending
  const fileSizePercent = file ? Math.min((file.size / MAX_FILE_SIZE) * 100, 100) : 0
  const textLengthPercent = (textBody.length / MAX_TEXT_LENGTH) * 100
  const isTextOverLimit = textBody.length > MAX_TEXT_LENGTH

  // Deduplicate recent outbound numbers for quick recipient selection
  const recentRecipients = useMemo(() => {
    if (!recentMessages?.items) return []
    const seen = new Set<string>()
    const results: Array<{ number: string; displayNumber: string }> = []
    for (const msg of recentMessages.items) {
      const num = msg.remoteNumber
      if (!num || seen.has(num)) continue
      seen.add(num)
      results.push({ number: num, displayNumber: formatPhoneDisplay(num) })
      if (results.length >= MAX_RECENT_RECIPIENTS) break
    }
    return results
  }, [recentMessages?.items])

  // ---- File handling ----

  function validateAndSetFile(selected: File) {
    setFileError(null)
    if (!ACCEPTED_TYPES.includes(selected.type)) {
      setFileError("Only PDF and TIFF files are accepted")
      return
    }
    if (selected.size > MAX_FILE_SIZE) {
      setFileError("File size must be under 20 MB")
      return
    }
    setFile(selected)
    if (selected.type === "application/pdf") {
      setPreviewUrl(URL.createObjectURL(selected))
    } else {
      setPreviewUrl(null)
    }
  }

  function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const selected = e.target.files?.[0] ?? null
    setFileError(null)
    if (selected) {
      validateAndSetFile(selected)
    } else {
      handleClearFile()
    }
  }

  function handleClearFile() {
    if (previewUrl) URL.revokeObjectURL(previewUrl)
    setFile(null)
    setPreviewUrl(null)
    setFileError(null)
    if (fileInputRef.current) fileInputRef.current.value = ""
  }

  // ---- Drag & drop ----

  const handleDragEnter = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(true)
  }, [])

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    // Only leave if we actually left the drop zone
    if (dropZoneRef.current && !dropZoneRef.current.contains(e.relatedTarget as Node)) {
      setIsDragging(false)
    }
  }, [])

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
  }, [])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(false)
    const droppedFile = e.dataTransfer.files[0]
    if (droppedFile) {
      validateAndSetFile(droppedFile)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // ---- Phone formatting ----

  function handlePhoneChange(e: React.ChangeEvent<HTMLInputElement>) {
    const raw = e.target.value
    setRemoteNumber(formatPhoneDisplay(raw))
    if (numberError) setNumberError(null)
  }

  // ---- Validation ----

  function validateNumber(): boolean {
    const cleaned = stripPhone(remoteNumber)
    if (!cleaned || cleaned === "+") {
      setNumberError("Recipient fax number is required")
      return false
    }
    if (!PHONE_REGEX.test(cleaned)) {
      setNumberError("Enter a valid fax number (e.g. +12125551234)")
      return false
    }
    setNumberError(null)
    return true
  }

  function validateSender(): boolean {
    if (!faxNumberId) {
      setSenderError("Select a sender fax number")
      return false
    }
    setSenderError(null)
    return true
  }

  function validateAll(): boolean {
    const senderOk = validateSender()
    const numberOk = validateNumber()
    let contentOk = hasContent
    if (!contentOk) {
      setFileError(contentMode === "file" ? "Upload a document to send" : "Enter text content to send")
    }
    if (contentMode === "text" && textBody.length > MAX_TEXT_LENGTH) {
      setFileError(`Text content exceeds maximum length of ${MAX_TEXT_LENGTH.toLocaleString()} characters`)
      contentOk = false
    }
    return senderOk && numberOk && contentOk
  }

  // ---- Submit flow ----

  function handlePreSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!validateAll()) return
    setShowConfirmDialog(true)
  }

  function handleConfirmSend() {
    setShowConfirmDialog(false)
    sendFax.mutate(
      {
        faxNumberId,
        destinationNumber: stripPhone(remoteNumber),
        subject: contentMode === "file" ? file?.name : "Text Fax",
        body: contentMode === "text" ? textBody : undefined,
      },
      {
        onSuccess: (data) => {
          setSentMessageId(data?.id ?? null)
          setShowSuccessState(true)
        },
      },
    )
  }

  function handleReset() {
    setFaxNumberId("")
    setRemoteNumber("")
    setTextBody("")
    setContentMode("file")
    handleClearFile()
    setSenderError(null)
    setNumberError(null)
    setFileError(null)
    setShowSuccessState(false)
    setSentMessageId(null)
  }

  // ---- Loading state ----

  if (isLoading) {
    return (
      <div className="grid gap-6 lg:grid-cols-5">
        <div className="lg:col-span-3">
          <SkeletonCard />
        </div>
        <div className="lg:col-span-2">
          <SkeletonCard />
        </div>
      </div>
    )
  }

  // ---- Success state ----

  if (showSuccessState) {
    return (
      <Card className="mx-auto max-w-lg">
        <CardContent className="flex flex-col items-center gap-4 py-12 text-center">
          <div className="rounded-full bg-green-100 p-3 dark:bg-green-900/30">
            <CheckCircle2 className="h-8 w-8 text-green-600 dark:text-green-400" />
          </div>
          <div className="space-y-1">
            <h3 className="text-lg font-semibold">Fax Queued Successfully</h3>
            <p className="text-sm text-muted-foreground">Your fax to {remoteNumber} has been queued for sending.</p>
          </div>
          <Separator className="my-2" />
          <div className="flex flex-wrap gap-3">
            {sentMessageId && (
              <Button variant="outline" size="sm" asChild>
                <Link to="/fax/messages/$messageId" params={{ messageId: sentMessageId }}>
                  View Message
                </Link>
              </Button>
            )}
            <Button variant="outline" size="sm" asChild>
              <Link to="/fax/messages">View All Messages</Link>
            </Button>
            <Button size="sm" onClick={handleReset}>
              Send Another Fax
            </Button>
          </div>
        </CardContent>
      </Card>
    )
  }

  // ---- Main form ----

  return (
    <>
      <div className="grid gap-6 lg:grid-cols-5">
        {/* Left: Form */}
        <div className="lg:col-span-3">
          <Card>
            <CardHeader>
              <CardTitle>Compose Fax</CardTitle>
              <CardDescription>Fill in the sender, recipient, and attach a document to send.</CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handlePreSubmit} className="space-y-8">
                {/* Section: From */}
                <fieldset className="space-y-4">
                  <legend className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
                    <Phone className="h-4 w-4" />
                    From
                  </legend>
                  <div className="space-y-2">
                    <Label htmlFor="source-number">
                      Sender Fax Number <span className="text-destructive">*</span>
                    </Label>
                    <Select
                      value={faxNumberId}
                      onValueChange={(v) => {
                        setFaxNumberId(v)
                        if (senderError) setSenderError(null)
                      }}
                    >
                      <SelectTrigger id="source-number" aria-invalid={!!senderError}>
                        <SelectValue placeholder="Select a fax number" />
                      </SelectTrigger>
                      <SelectContent>
                        {activeNumbers.map((num) => (
                          <SelectItem key={num.id} value={num.id}>
                            {num.number}
                            {num.label ? ` -- ${num.label}` : ""}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    {senderError && (
                      <p className="flex items-center gap-1 text-xs text-destructive">
                        <AlertCircle className="h-3 w-3" />
                        {senderError}
                      </p>
                    )}
                    {activeNumbers.length === 0 && (
                      <p className="text-xs text-muted-foreground">
                        No active fax numbers available.{" "}
                        <Link to="/fax/numbers" className="underline underline-offset-2 hover:text-foreground">
                          Add one
                        </Link>
                      </p>
                    )}
                  </div>
                </fieldset>

                <Separator />

                {/* Section: To */}
                <fieldset className="space-y-4">
                  <legend className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
                    <Send className="h-4 w-4" />
                    To
                  </legend>
                  <div className="space-y-2">
                    <Label htmlFor="destination">
                      Recipient Fax Number <span className="text-destructive">*</span>
                    </Label>
                    <Input
                      id="destination"
                      type="tel"
                      placeholder="+1 (212) 555-1234"
                      value={remoteNumber}
                      onChange={handlePhoneChange}
                      onBlur={validateNumber}
                      aria-invalid={!!numberError}
                    />
                    {numberError ? (
                      <p className="flex items-center gap-1 text-xs text-destructive">
                        <AlertCircle className="h-3 w-3" />
                        {numberError}
                      </p>
                    ) : (
                      <p className="text-xs text-muted-foreground">Enter the recipient's fax number in E.164 format</p>
                    )}
                  </div>

                  {/* Recent recipients */}
                  {recentRecipients.length > 0 && (
                    <div className="space-y-2">
                      <p className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
                        <Clock className="h-3 w-3" />
                        Recent Recipients
                      </p>
                      <div className="flex flex-wrap gap-1.5">
                        {recentRecipients.map((r) => (
                          <Button
                            key={r.number}
                            type="button"
                            variant="outline"
                            size="sm"
                            className="h-7 text-xs"
                            onClick={() => {
                              setRemoteNumber(formatPhoneDisplay(r.number))
                              setNumberError(null)
                            }}
                          >
                            {r.displayNumber}
                          </Button>
                        ))}
                      </div>
                    </div>
                  )}
                </fieldset>

                <Separator />

                {/* Section: Content */}
                <fieldset className="space-y-4">
                  <legend className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
                    <FileText className="h-4 w-4" />
                    Content <span className="text-destructive">*</span>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Info className="h-3.5 w-3.5 text-muted-foreground cursor-help" />
                      </TooltipTrigger>
                      <TooltipContent>
                        <p>Supported formats: PDF, TIFF. Maximum file size: 20MB.</p>
                      </TooltipContent>
                    </Tooltip>
                  </legend>

                  <Tabs value={contentMode} onValueChange={(v) => setContentMode(v as "file" | "text")}>
                    <TabsList>
                      <TabsTrigger value="file">Upload Document</TabsTrigger>
                      <TabsTrigger value="text">Text Content</TabsTrigger>
                    </TabsList>

                    {/* File upload tab */}
                    <TabsContent value="file" className="mt-4 space-y-3">
                      {file ? (
                        <>
                          <div className="flex items-center gap-3 rounded-lg border border-border/60 bg-muted/30 p-4">
                            <div className="rounded-md bg-primary/10 p-2">
                              <FileText className="h-5 w-5 text-primary" />
                            </div>
                            <div className="flex-1 min-w-0">
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <p className="text-sm font-medium truncate">{file.name}</p>
                                </TooltipTrigger>
                                <TooltipContent side="top" className="max-w-sm">
                                  <p>{file.name}</p>
                                </TooltipContent>
                              </Tooltip>
                              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                                <span>{formatBytes(file.size)}</span>
                                <Badge variant="secondary" className="text-[10px] px-1.5 py-0">
                                  {file.type === "application/pdf" ? "PDF" : "TIFF"}
                                </Badge>
                              </div>
                            </div>
                            <Button type="button" variant="ghost" size="sm" onClick={handleClearFile} aria-label="Remove file">
                              <X className="h-4 w-4" />
                            </Button>
                          </div>
                          <div className="space-y-1">
                            <div className="h-1 w-full overflow-hidden rounded-full bg-muted">
                              <div
                                className={`h-full rounded-full transition-all ${fileSizePercent > 90 ? "bg-amber-500" : "bg-primary"}`}
                                style={{ width: `${fileSizePercent}%` }}
                              />
                            </div>
                            <p className="text-xs text-muted-foreground text-right">
                              {formatBytes(file.size)} of {formatBytes(MAX_FILE_SIZE)}
                            </p>
                          </div>
                        </>
                      ) : (
                        <div
                          ref={dropZoneRef}
                          onDragEnter={handleDragEnter}
                          onDragLeave={handleDragLeave}
                          onDragOver={handleDragOver}
                          onDrop={handleDrop}
                          onClick={() => fileInputRef.current?.click()}
                          onKeyDown={(e) => {
                            if (e.key === "Enter" || e.key === " ") {
                              e.preventDefault()
                              fileInputRef.current?.click()
                            }
                          }}
                          role="button"
                          tabIndex={0}
                          className={`
                            flex cursor-pointer flex-col items-center justify-center gap-3 rounded-lg border-2 border-dashed p-8
                            transition-colors duration-150
                            ${isDragging ? "border-primary bg-primary/5 text-primary" : "border-border/60 text-muted-foreground hover:border-primary/40 hover:bg-muted/30"}
                            ${fileError ? "border-destructive/60" : ""}
                          `}
                        >
                          <Upload className={`h-8 w-8 ${isDragging ? "text-primary" : "text-muted-foreground/40"}`} />
                          <div className="text-center">
                            <p className="text-sm font-medium">{isDragging ? "Drop file here" : "Drag and drop a file, or click to browse"}</p>
                            <p className="mt-1 text-xs text-muted-foreground">PDF or TIFF, max 20 MB</p>
                          </div>
                        </div>
                      )}
                      <input ref={fileInputRef} type="file" accept={ACCEPTED_EXTENSIONS} className="hidden" onChange={handleFileChange} />
                      {fileError && (
                        <p className="flex items-center gap-1 text-xs text-destructive">
                          <AlertCircle className="h-3 w-3" />
                          {fileError}
                        </p>
                      )}
                    </TabsContent>

                    {/* Text content tab */}
                    <TabsContent value="text" className="mt-4 space-y-3">
                      <div className="space-y-2">
                        <div className="flex items-center justify-between">
                          <Label htmlFor="text-body">Fax Text Content</Label>
                          <span
                            className={`text-xs tabular-nums ${
                              isTextOverLimit
                                ? "font-medium text-destructive"
                                : textBody.length > MAX_TEXT_LENGTH * 0.9
                                  ? "text-amber-600 dark:text-amber-400"
                                  : "text-muted-foreground"
                            }`}
                          >
                            {textBody.length.toLocaleString()} / {MAX_TEXT_LENGTH.toLocaleString()}
                          </span>
                        </div>
                        <Textarea
                          id="text-body"
                          placeholder="Type the content of your fax here..."
                          value={textBody}
                          onChange={(e) => {
                            setTextBody(e.target.value)
                            if (fileError) setFileError(null)
                          }}
                          aria-invalid={isTextOverLimit}
                          className={`min-h-[200px] ${isTextOverLimit ? "border-destructive focus-visible:ring-destructive" : ""}`}
                        />
                        <div className="space-y-1.5">
                          <div className="h-1 w-full overflow-hidden rounded-full bg-muted">
                            <div
                              className={`h-full rounded-full transition-all ${isTextOverLimit ? "bg-destructive" : textLengthPercent > 90 ? "bg-amber-500" : "bg-primary"}`}
                              style={{ width: `${Math.min(textLengthPercent, 100)}%` }}
                            />
                          </div>
                          <p className="text-xs text-muted-foreground">Text will be rendered as a fax document on the server.</p>
                        </div>
                      </div>
                    </TabsContent>
                  </Tabs>
                </fieldset>

                <Separator />

                {/* Submit */}
                <div className="space-y-3">
                  <div className="flex items-center gap-3">
                    <Button type="submit" disabled={!canSubmit || isTextOverLimit}>
                      {sendFax.isPending ? (
                        <>
                          <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                          Sending...
                        </>
                      ) : (
                        <>
                          <Send className="mr-2 h-4 w-4" />
                          Review &amp; Send
                        </>
                      )}
                    </Button>
                    <Button type="button" variant="outline" asChild>
                      <Link to="/fax">Cancel</Link>
                    </Button>
                  </div>
                  {sendFax.isError && (
                    <p className="flex items-center gap-1.5 text-sm text-destructive">
                      <AlertCircle className="h-4 w-4 shrink-0" />
                      {sendFax.error instanceof Error ? sendFax.error.message : "Failed to send fax. Please try again."}
                    </p>
                  )}
                </div>
              </form>
            </CardContent>
          </Card>
        </div>

        {/* Right: Preview */}
        <div className="lg:col-span-2">
          <Card className="sticky top-24">
            <CardHeader>
              <CardTitle className="text-base">Document Preview</CardTitle>
            </CardHeader>
            <CardContent>
              {previewUrl ? (
                <div className="overflow-hidden rounded-lg border border-border/60">
                  <iframe src={previewUrl} title="PDF preview" className="h-[500px] w-full border-none" />
                </div>
              ) : file && file.type !== "application/pdf" ? (
                <div className="flex h-[300px] flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-border/60 text-muted-foreground">
                  <FileText className="h-10 w-10 text-muted-foreground/30" />
                  <p className="text-sm">TIFF preview not available</p>
                  <p className="text-xs">{file.name}</p>
                </div>
              ) : contentMode === "text" && textBody.trim() ? (
                <div className="rounded-lg border border-border/60 p-4">
                  <p className="text-xs font-medium text-muted-foreground mb-2 uppercase tracking-wide">Text Preview</p>
                  <div className="whitespace-pre-wrap text-sm leading-relaxed max-h-[460px] overflow-y-auto">{textBody}</div>
                </div>
              ) : (
                <div className="flex h-[300px] flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-border/60 text-muted-foreground">
                  <FileUp className="h-10 w-10 text-muted-foreground/30" />
                  <p className="text-sm">{contentMode === "file" ? "Upload a PDF to see a preview" : "Start typing to see a preview"}</p>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Confirmation dialog */}
      <AlertDialog open={showConfirmDialog} onOpenChange={setShowConfirmDialog}>
        <AlertDialogContent className="sm:max-w-md">
          <AlertDialogHeader>
            <AlertDialogTitle>Confirm Fax</AlertDialogTitle>
            <AlertDialogDescription>Review the details below before sending.</AlertDialogDescription>
          </AlertDialogHeader>
          <div className="space-y-3 py-2">
            <div className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
              <span className="font-medium text-muted-foreground">From:</span>
              <span>
                {selectedNumber?.number}
                {selectedNumber?.label ? ` (${selectedNumber.label})` : ""}
              </span>
              <span className="font-medium text-muted-foreground">To:</span>
              <span>{remoteNumber}</span>
              <span className="font-medium text-muted-foreground">Content:</span>
              <span>
                {contentMode === "file" && file ? (
                  <span className="flex items-center gap-2">
                    <FileText className="h-3.5 w-3.5 text-muted-foreground" />
                    {file.name}
                    <Badge variant="secondary" className="text-[10px] px-1.5 py-0">
                      {formatBytes(file.size)}
                    </Badge>
                  </span>
                ) : (
                  `Text (${textBody.length.toLocaleString()} characters)`
                )}
              </span>
            </div>
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setShowConfirmDialog(false)}>Go Back</AlertDialogCancel>
            <AlertDialogAction onClick={handleConfirmSend} disabled={sendFax.isPending}>
              {sendFax.isPending ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Sending...
                </>
              ) : (
                <>
                  <Send className="mr-2 h-4 w-4" />
                  Send Fax
                </>
              )}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
