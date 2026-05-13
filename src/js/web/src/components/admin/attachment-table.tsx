import { Download, Loader2, Trash2 } from "lucide-react"
import { useState } from "react"
import { toast } from "sonner"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { SkeletonTable } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { type Attachment, downloadAttachment, formatBytes, useAdminAttachments, useDeleteAttachment } from "@/lib/api/hooks/uploads"

const PAGE_SIZE = 25

export function AttachmentTable() {
  const [page, setPage] = useState(1)
  const { data, isLoading, isError } = useAdminAttachments({ page, pageSize: PAGE_SIZE })
  const deleteAttachment = useDeleteAttachment()
  const [downloadingId, setDownloadingId] = useState<string | null>(null)

  if (isLoading) {
    return <SkeletonTable rows={6} />
  }

  if (isError || !data) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Attachments</CardTitle>
        </CardHeader>
        <CardContent className="text-muted-foreground">We could not load attachments.</CardContent>
      </Card>
    )
  }

  const totalPages = Math.max(1, Math.ceil(data.total / PAGE_SIZE))

  const handleDownload = async (attachment: Attachment) => {
    setDownloadingId(attachment.id)
    try {
      await downloadAttachment(attachment)
    } catch (error) {
      toast.error("Unable to download attachment", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    } finally {
      setDownloadingId(null)
    }
  }

  const handleDelete = (attachment: Attachment) => {
    if (typeof window !== "undefined" && !window.confirm(`Delete "${attachment.originalFilename}"? This cannot be undone.`)) {
      return
    }
    deleteAttachment.mutate(attachment.id)
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Attachments</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Filename</TableHead>
              <TableHead>Size</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Purpose</TableHead>
              <TableHead>Uploader</TableHead>
              <TableHead>Created</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.items.length === 0 && (
              <TableRow>
                <TableCell colSpan={7} className="text-center text-muted-foreground">
                  No attachments found.
                </TableCell>
              </TableRow>
            )}
            {data.items.map((attachment) => (
              <TableRow key={attachment.id}>
                <TableCell className="max-w-[280px]">
                  <span className="block truncate font-medium" title={attachment.originalFilename}>
                    {attachment.originalFilename}
                  </span>
                </TableCell>
                <TableCell>{formatBytes(attachment.sizeBytes)}</TableCell>
                <TableCell className="text-muted-foreground">{attachment.contentType}</TableCell>
                <TableCell>
                  <Badge variant="secondary">{attachment.purpose}</Badge>
                </TableCell>
                <TableCell className="font-mono text-xs text-muted-foreground" title={attachment.uploadedById}>
                  {attachment.uploadedById.slice(0, 8)}
                </TableCell>
                <TableCell className="text-muted-foreground">{new Date(attachment.createdAt).toLocaleString()}</TableCell>
                <TableCell className="text-right">
                  <div className="inline-flex gap-2">
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() => handleDownload(attachment)}
                      disabled={downloadingId === attachment.id}
                      aria-label={`Download ${attachment.originalFilename}`}
                    >
                      {downloadingId === attachment.id ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
                    </Button>
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() => handleDelete(attachment)}
                      disabled={deleteAttachment.isPending}
                      aria-label={`Delete ${attachment.originalFilename}`}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        <div className="flex items-center justify-between">
          <p className="text-xs text-muted-foreground">
            Page {page} of {totalPages} · {data.total} total
          </p>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page <= 1}>
              Previous
            </Button>
            <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page >= totalPages}>
              Next
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
