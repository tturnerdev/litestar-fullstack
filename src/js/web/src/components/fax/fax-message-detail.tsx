import { Download, FileText, Trash2 } from "lucide-react"
import { useState } from "react"
import { DirectionBadge, FaxStatusBadge } from "@/components/fax/fax-status-badge"
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
import { Skeleton } from "@/components/ui/skeleton"
import type { FaxMessage } from "@/lib/api/hooks/fax"
import { useDownloadFaxDocument } from "@/lib/api/hooks/fax"

function formatDate(dateStr: string | null): string {
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

interface FaxMessageDetailProps {
  message: FaxMessage
  onDelete: () => void
  isDeleting: boolean
}

export function FaxMessageDetail({ message, onDelete, isDeleting }: FaxMessageDetailProps) {
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const { data: pdfUrl, isLoading: pdfLoading } = useDownloadFaxDocument(message.id)

  function handleConfirmDelete() {
    onDelete()
    setDeleteDialogOpen(false)
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Message Details</CardTitle>
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
              <p className="font-mono">{message.remoteNumber}</p>
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
              <p>{formatDate(message.receivedAt)}</p>
            </div>
            <div>
              <p className="text-muted-foreground">Created</p>
              <p>{formatDate(message.createdAt)}</p>
            </div>
            {message.errorMessage && (
              <div className="md:col-span-2">
                <p className="text-muted-foreground">Error</p>
                <p className="text-red-600 dark:text-red-400">{message.errorMessage}</p>
              </div>
            )}
            {message.deliveredToEmails && message.deliveredToEmails.length > 0 && (
              <div className="md:col-span-2">
                <p className="text-muted-foreground">Delivered To</p>
                <div className="flex flex-wrap gap-1 mt-1">
                  {message.deliveredToEmails.map((email) => (
                    <span
                      key={email}
                      className="inline-flex items-center rounded-md bg-muted px-2 py-0.5 text-xs font-mono"
                    >
                      {email}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
          <div className="flex flex-wrap gap-2 pt-2">
            <Button variant="outline" asChild>
              <a href={`/api/fax/messages/${message.id}/download`} download>
                <Download className="mr-2 h-4 w-4" /> Download Document
              </a>
            </Button>
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
            <CardTitle>Document Preview</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          {pdfLoading ? (
            <Skeleton className="h-[600px] w-full rounded-lg" />
          ) : pdfUrl ? (
            <div className="overflow-hidden rounded-lg border border-border/60">
              <iframe
                src={pdfUrl}
                title="Fax document preview"
                className="h-[600px] w-full"
                style={{ border: "none" }}
              />
            </div>
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
