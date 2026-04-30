import {
  AlertTriangle,
  ArrowLeftRight,
  Check,
  Copy,
  Download,
  FileText,
  Mail,
  Printer,
  RotateCcw,
  Trash2,
} from "lucide-react"
import { useState } from "react"
import { DirectionBadge, FaxStatusBadge } from "@/components/fax/fax-status-badge"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import type { FaxMessage } from "@/lib/api/hooks/fax"
import { useDownloadFaxDocument } from "@/lib/api/hooks/fax"

function formatRelativeTime(dateStr: string | null): string {
  if (!dateStr) return "--"
  const now = Date.now()
  const date = new Date(dateStr).getTime()
  const diffMs = now - date
  const diffSec = Math.floor(diffMs / 1000)
  if (diffSec < 60) return "just now"
  const diffMin = Math.floor(diffSec / 60)
  if (diffMin < 60) return `${diffMin}m ago`
  const diffHr = Math.floor(diffMin / 60)
  if (diffHr < 24) return `${diffHr}h ago`
  const diffDays = Math.floor(diffHr / 24)
  if (diffDays < 30) return `${diffDays}d ago`
  const diffMonths = Math.floor(diffDays / 30)
  return `${diffMonths}mo ago`
}

function formatFullDate(dateStr: string | null): string {
  if (!dateStr) return "--"
  return new Date(dateStr).toLocaleString()
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B"
  const k = 1024
  const sizes = ["B", "KB", "MB", "GB"]
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${Number.parseFloat((bytes / k ** i).toFixed(1))} ${sizes[i]}`
}

function formatPhoneNumber(phone: string): string {
  const digits = phone.replace(/\D/g, "")
  const raw = digits.length === 11 && digits.startsWith("1") ? digits.slice(1) : digits
  if (raw.length === 10) {
    return `${raw.slice(0, 3)}-${raw.slice(3, 6)}-${raw.slice(6)}`
  }
  return phone
}

function RelativeTimestamp({ dateStr }: { dateStr: string | null }) {
  if (!dateStr) return <span>--</span>
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="cursor-default border-b border-dotted border-muted-foreground/40">
          {formatRelativeTime(dateStr)}
        </span>
      </TooltipTrigger>
      <TooltipContent>{formatFullDate(dateStr)}</TooltipContent>
    </Tooltip>
  )
}

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false)

  function handleCopy() {
    navigator.clipboard.writeText(value)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button variant="ghost" size="sm" className="h-6 w-6 p-0" onClick={handleCopy}>
          {copied ? <Check className="h-3 w-3 text-green-600" /> : <Copy className="h-3 w-3 text-muted-foreground" />}
          <span className="sr-only">Copy</span>
        </Button>
      </TooltipTrigger>
      <TooltipContent>{copied ? "Copied!" : "Copy"}</TooltipContent>
    </Tooltip>
  )
}

interface FaxMessageDetailProps {
  message: FaxMessage
  onDelete: () => void
  onResend?: () => void
  isDeleting: boolean
}

export function FaxMessageDetail({ message, onDelete, onResend, isDeleting }: FaxMessageDetailProps) {
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const { data: pdfUrl, isLoading: pdfLoading } = useDownloadFaxDocument(message.id)

  function handleConfirmDelete() {
    onDelete()
    setDeleteDialogOpen(false)
  }

  function handlePrint() {
    if (!pdfUrl) return
    const printWindow = window.open(pdfUrl, "_blank")
    printWindow?.addEventListener("load", () => {
      printWindow.print()
    })
  }

  const isFailed = message.status === "failed"
  const canResend = isFailed && message.direction === "outbound" && onResend

  return (
    <div className="space-y-6">
      {isFailed && message.errorMessage && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Transmission Failed</AlertTitle>
          <AlertDescription>{message.errorMessage}</AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <ArrowLeftRight className="h-4 w-4 text-muted-foreground" />
            <CardTitle>Transmission Details</CardTitle>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-3 text-sm md:grid-cols-2">
            <div>
              <p className="text-muted-foreground">Direction</p>
              <div className="mt-1">
                <DirectionBadge direction={message.direction} />
              </div>
            </div>
            <div>
              <p className="text-muted-foreground">Status</p>
              <div className="mt-1">
                <FaxStatusBadge status={message.status} />
              </div>
            </div>
            <div>
              <p className="text-muted-foreground">Remote Number</p>
              <div className="mt-1 flex items-center gap-1.5">
                <p className="font-mono">{formatPhoneNumber(message.remoteNumber)}</p>
                <CopyButton value={message.remoteNumber} />
              </div>
            </div>
            <div>
              <p className="text-muted-foreground">Remote Name</p>
              <p>{message.remoteName ?? "--"}</p>
            </div>
            <div>
              <p className="text-muted-foreground">Pages</p>
              <p>{message.pageCount}</p>
            </div>
            <div>
              <p className="text-muted-foreground">File Size</p>
              <p>{formatBytes(message.fileSizeBytes)}</p>
            </div>
            <div>
              <p className="text-muted-foreground">Date</p>
              <p><RelativeTimestamp dateStr={message.receivedAt} /></p>
            </div>
            <div>
              <p className="text-muted-foreground">Created</p>
              <p><RelativeTimestamp dateStr={message.createdAt} /></p>
            </div>
            <div className="md:col-span-2">
              <p className="text-muted-foreground">Message ID</p>
              <div className="mt-1 flex items-center gap-1.5">
                <p className="font-mono text-xs">{message.id}</p>
                <CopyButton value={message.id} />
              </div>
            </div>
          </div>

          <Separator />

          {message.deliveredToEmails && message.deliveredToEmails.length > 0 && (
            <>
              <div>
                <p className="text-sm text-muted-foreground mb-2">Delivered To</p>
                <div className="flex flex-wrap gap-1.5">
                  {message.deliveredToEmails.map((email) => (
                    <Badge
                      key={email}
                      variant="secondary"
                      className="gap-1 font-mono text-xs"
                    >
                      <Mail className="h-3 w-3" />
                      {email}
                    </Badge>
                  ))}
                </div>
              </div>
              <Separator />
            </>
          )}

          <div className="flex flex-wrap gap-2 pt-1">
            <Button variant="outline" asChild>
              <a href={`/api/fax/messages/${message.id}/download`} download>
                <Download className="mr-2 h-4 w-4" /> Download Document
              </a>
            </Button>
            {canResend && (
              <Button variant="outline" onClick={onResend}>
                <RotateCcw className="mr-2 h-4 w-4" /> Resend
              </Button>
            )}
            <Dialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
              <DialogTrigger asChild>
                <Button variant="destructive" disabled={isDeleting}>
                  <Trash2 className="mr-2 h-4 w-4" />
                  {isDeleting ? "Deleting..." : "Delete Message"}
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Delete Fax Message</DialogTitle>
                  <DialogDescription>
                    This will permanently delete this fax message and its associated document.
                    This action cannot be undone.
                  </DialogDescription>
                </DialogHeader>
                <DialogFooter>
                  <Button variant="outline" onClick={() => setDeleteDialogOpen(false)}>
                    Cancel
                  </Button>
                  <Button variant="destructive" onClick={handleConfirmDelete} disabled={isDeleting}>
                    {isDeleting ? "Deleting..." : "Delete"}
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <FileText className="h-4 w-4 text-muted-foreground" />
            <CardTitle>Document</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          {pdfLoading ? (
            <Skeleton className="h-[600px] w-full rounded-lg" />
          ) : pdfUrl ? (
            <>
              <div className="flex items-center justify-end gap-2 mb-3">
                <Button variant="outline" size="sm" onClick={handlePrint}>
                  <Printer className="mr-2 h-3.5 w-3.5" /> Print
                </Button>
                <Button variant="outline" size="sm" asChild>
                  <a href={`/api/fax/messages/${message.id}/download`} download>
                    <Download className="mr-2 h-3.5 w-3.5" /> Download
                  </a>
                </Button>
              </div>
              <div className="overflow-hidden rounded-lg border border-border/60">
                <iframe
                  src={pdfUrl}
                  title="Fax document preview"
                  className="h-[600px] w-full"
                  style={{ border: "none" }}
                />
              </div>
            </>
          ) : (
            <div className="flex h-[200px] flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-border/60 text-muted-foreground">
              <FileText className="h-8 w-8" />
              <p className="text-sm">Document preview is not available.</p>
              <Button variant="outline" size="sm" asChild>
                <a href={`/api/fax/messages/${message.id}/download`} download>
                  <Download className="mr-2 h-3.5 w-3.5" /> Download instead
                </a>
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
