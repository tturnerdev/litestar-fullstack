import { useNavigate } from "@tanstack/react-router"
import { FileText, FileUp, Send, X } from "lucide-react"
import { useRef, useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { SkeletonCard } from "@/components/ui/skeleton"
import { useFaxNumbers, useSendFax } from "@/lib/api/hooks/fax"

const PHONE_REGEX = /^\+?[1-9]\d{1,14}$/

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B"
  const k = 1024
  const sizes = ["B", "KB", "MB", "GB"]
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${Number.parseFloat((bytes / k ** i).toFixed(1))} ${sizes[i]}`
}

export function SendFaxForm() {
  const navigate = useNavigate()
  const { data: faxNumbers, isLoading } = useFaxNumbers(1, 100)
  const sendFax = useSendFax()
  const fileInputRef = useRef<HTMLInputElement>(null)

  const [faxNumberId, setFaxNumberId] = useState("")
  const [remoteNumber, setRemoteNumber] = useState("")
  const [file, setFile] = useState<File | null>(null)
  const [previewUrl, setPreviewUrl] = useState<string | null>(null)
  const [numberError, setNumberError] = useState<string | null>(null)
  const [fileError, setFileError] = useState<string | null>(null)

  if (isLoading) {
    return <SkeletonCard />
  }

  function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const selected = e.target.files?.[0] ?? null
    setFileError(null)

    if (selected) {
      if (selected.type !== "application/pdf") {
        setFileError("Only PDF files are accepted")
        setFile(null)
        setPreviewUrl(null)
        return
      }
      if (selected.size > 20 * 1024 * 1024) {
        setFileError("File size must be under 20 MB")
        setFile(null)
        setPreviewUrl(null)
        return
      }
      setFile(selected)
      setPreviewUrl(URL.createObjectURL(selected))
    } else {
      setFile(null)
      setPreviewUrl(null)
    }
  }

  function handleClearFile() {
    setFile(null)
    setPreviewUrl(null)
    setFileError(null)
    if (fileInputRef.current) fileInputRef.current.value = ""
  }

  function validateNumber(): boolean {
    const cleaned = remoteNumber.replace(/[\s()-]/g, "")
    if (!cleaned) {
      setNumberError("Destination number is required")
      return false
    }
    if (!PHONE_REGEX.test(cleaned)) {
      setNumberError("Please enter a valid phone number (E.164 format, e.g. +12125551234)")
      return false
    }
    setNumberError(null)
    return true
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!faxNumberId || !file) return
    if (!validateNumber()) return

    sendFax.mutate(
      {
        faxNumberId,
        destinationNumber: remoteNumber.replace(/[\s()-]/g, ""),
        subject: file.name,
      },
      {
        onSuccess: () => {
          setFaxNumberId("")
          setRemoteNumber("")
          handleClearFile()
          navigate({ to: "/fax/messages" })
        },
      },
    )
  }

  const activeNumbers = faxNumbers?.items.filter((n) => n.isActive) ?? []
  const canSubmit = !!faxNumberId && !!remoteNumber.trim() && !!file && !sendFax.isPending

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>Send a Fax</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="space-y-2">
              <Label htmlFor="source-number">Source Fax Number</Label>
              <Select value={faxNumberId} onValueChange={setFaxNumberId}>
                <SelectTrigger id="source-number">
                  <SelectValue placeholder="Select a fax number" />
                </SelectTrigger>
                <SelectContent>
                  {activeNumbers.map((num) => (
                    <SelectItem key={num.id} value={num.id}>
                      {num.number} {num.label ? `(${num.label})` : ""}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {activeNumbers.length === 0 && (
                <p className="text-xs text-muted-foreground">No active fax numbers available.</p>
              )}
            </div>

            <div className="space-y-2">
              <Label htmlFor="destination">Destination Number</Label>
              <Input
                id="destination"
                type="tel"
                placeholder="+12125551234"
                value={remoteNumber}
                onChange={(e) => {
                  setRemoteNumber(e.target.value)
                  if (numberError) setNumberError(null)
                }}
                onBlur={validateNumber}
                aria-invalid={!!numberError}
              />
              {numberError && <p className="text-xs text-destructive">{numberError}</p>}
            </div>

            <div className="space-y-2">
              <Label htmlFor="file">Document (PDF)</Label>
              {file ? (
                <div className="flex items-center gap-3 rounded-lg border border-border/60 bg-muted/30 p-3">
                  <FileText className="h-5 w-5 text-muted-foreground shrink-0" />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium truncate">{file.name}</p>
                    <p className="text-xs text-muted-foreground">{formatBytes(file.size)}</p>
                  </div>
                  <Button type="button" variant="ghost" size="sm" onClick={handleClearFile}>
                    <X className="h-4 w-4" />
                  </Button>
                </div>
              ) : (
                <div className="flex items-center gap-3">
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => fileInputRef.current?.click()}
                  >
                    <FileUp className="mr-2 h-4 w-4" /> Choose File
                  </Button>
                  <span className="text-sm text-muted-foreground">PDF, max 20 MB</span>
                </div>
              )}
              <input
                ref={fileInputRef}
                id="file"
                type="file"
                accept=".pdf,application/pdf"
                className="hidden"
                onChange={handleFileChange}
              />
              {fileError && <p className="text-xs text-destructive">{fileError}</p>}
            </div>

            <Button type="submit" disabled={!canSubmit} className="w-full sm:w-auto">
              <Send className="mr-2 h-4 w-4" />
              {sendFax.isPending ? "Sending..." : "Send Fax"}
            </Button>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Preview</CardTitle>
        </CardHeader>
        <CardContent>
          {previewUrl ? (
            <div className="overflow-hidden rounded-lg border border-border/60">
              <iframe
                src={previewUrl}
                title="PDF preview"
                className="h-[500px] w-full"
                style={{ border: "none" }}
              />
            </div>
          ) : (
            <div className="flex h-[300px] flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-border/60 text-muted-foreground">
              <FileText className="h-10 w-10 text-muted-foreground/30" />
              <p className="text-sm">Upload a PDF to see a preview</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
