import { createFileRoute, Link, useRouter } from "@tanstack/react-router"
import { useState } from "react"
import {
  AlertCircle,
  AlertTriangle,
  ArrowDownLeft,
  ArrowLeft,
  ArrowUpRight,
  Clock,
  Download,
  FileText,
  Hash,
  Info,
  Loader2,
  Mail,
  Trash2,
} from "lucide-react"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
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
import { Button, buttonVariants } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"
import { SkeletonCard } from "@/components/ui/skeleton"
import { CopyButton } from "@/components/ui/copy-button"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { DirectionBadge, FaxStatusBadge } from "@/components/fax/fax-status-badge"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { useDeleteFaxMessage, useDownloadFaxDocument, useFaxMessage } from "@/lib/api/hooks/fax"
import { formatDateTime, formatRelativeTime } from "@/lib/date-utils"
import { formatBytes } from "@/lib/format-utils"

export const Route = createFileRoute("/_app/fax/messages/$messageId/")({
  component: FaxMessageDetailPage,
})

// -- Timestamp with tooltip -------------------------------------------------

function TimestampField({
  label,
  value,
}: {
  label: string
  value: string | null | undefined
}) {
  if (!value) {
    return (
      <div>
        <p className="text-muted-foreground text-sm">{label}</p>
        <p className="text-sm">---</p>
      </div>
    )
  }

  return (
    <div>
      <p className="text-muted-foreground text-sm">{label}</p>
      <Tooltip>
        <TooltipTrigger asChild>
          <p className="cursor-default text-sm">{formatRelativeTime(value)}</p>
        </TooltipTrigger>
        <TooltipContent>{formatDateTime(value)}</TooltipContent>
      </Tooltip>
    </div>
  )
}

// -- Main page --------------------------------------------------------------

function FaxMessageDetailPage() {
  useDocumentTitle("Fax Message")
  const { messageId } = Route.useParams()
  const router = useRouter()
  const { data, isLoading, isError } = useFaxMessage(messageId)
  const deleteMutation = useDeleteFaxMessage()
  const { data: pdfUrl, isLoading: pdfLoading } = useDownloadFaxDocument(
    data ? messageId : "",
  )

  const [deleteOpen, setDeleteOpen] = useState(false)

  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader eyebrow="Fax" title="Message Details" />
        <PageSection>
          <SkeletonCard />
        </PageSection>
        <PageSection delay={0.1}>
          <SkeletonCard className="h-[200px]" />
        </PageSection>
        <PageSection delay={0.2}>
          <SkeletonCard className="h-[400px]" />
        </PageSection>
      </PageContainer>
    )
  }

  if (isError || !data) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader
          eyebrow="Fax"
          title="Message Details"
          actions={
            <Button variant="outline" size="sm" asChild>
              <Link to="/fax/messages">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back to messages
              </Link>
            </Button>
          }
        />
        <PageSection>
          <Card>
            <CardContent className="py-8 text-center text-muted-foreground">
              We could not load this message.
            </CardContent>
          </Card>
        </PageSection>
      </PageContainer>
    )
  }

  const handleDelete = () => {
    deleteMutation.mutate(messageId, {
      onSuccess: () => {
        router.navigate({ to: "/fax/messages" })
      },
    })
  }

  const directionLabel = data.direction === "inbound" ? "From" : "To"
  const remoteDisplay = data.remoteName
    ? `${data.remoteName} (${data.remoteNumber})`
    : data.remoteNumber

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Fax"
        title="Fax Message"
        description={`${directionLabel} ${remoteDisplay}`}
        breadcrumbs={
          <Breadcrumb>
            <BreadcrumbList>
              <BreadcrumbItem>
                <BreadcrumbLink asChild>
                  <Link to="/home">Home</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbLink asChild>
                  <Link to="/fax/messages">Fax Messages</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbPage>Message</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
        actions={
          <div className="flex items-center gap-3">
            <FaxStatusBadge status={data.status} />
            <DirectionBadge direction={data.direction} />
            <Button variant="outline" size="sm" asChild>
              <a href={`/api/fax/messages/${messageId}/download`} download>
                <Download className="mr-2 h-4 w-4" /> Download
              </a>
            </Button>
            <Button variant="outline" size="sm" asChild>
              <Link to="/fax/messages">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back
              </Link>
            </Button>
          </div>
        }
      />

      {/* Error alert -- prominently displayed if the message failed */}
      {data.status === "failed" && data.errorMessage && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Transmission Failed</AlertTitle>
          <AlertDescription className="font-mono text-xs">
            {data.errorMessage}
          </AlertDescription>
        </Alert>
      )}

      {/* Message Info */}
      <PageSection>
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Info className="h-5 w-5 text-muted-foreground" />
              <CardTitle>Message Info</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-3">
              <div>
                <p className="text-muted-foreground">Direction</p>
                <div className="mt-1 flex items-center gap-2">
                  {data.direction === "inbound" ? (
                    <ArrowDownLeft className="h-4 w-4 text-blue-500" />
                  ) : (
                    <ArrowUpRight className="h-4 w-4 text-violet-500" />
                  )}
                  <DirectionBadge direction={data.direction} />
                </div>
              </div>
              <div>
                <p className="text-muted-foreground">Status</p>
                <div className="mt-1">
                  <FaxStatusBadge status={data.status} />
                </div>
              </div>
              <div>
                <p className="text-muted-foreground">
                  {data.direction === "inbound" ? "From Number" : "To Number"}
                </p>
                <div className="flex items-center gap-1">
                  <p className="font-mono">{data.remoteNumber}</p>
                  <CopyButton value={data.remoteNumber} label="remote number" />
                </div>
              </div>
              <div>
                <p className="text-muted-foreground">Remote Name</p>
                <p>{data.remoteName ?? "---"}</p>
              </div>
              {data.deliveredToEmails && data.deliveredToEmails.length > 0 && (
                <div className="md:col-span-2 lg:col-span-3">
                  <p className="text-muted-foreground">Delivered To</p>
                  <div className="mt-1.5 flex flex-wrap gap-2">
                    {data.deliveredToEmails.map((email) => (
                      <Badge
                        key={email}
                        variant="outline"
                        className="gap-1.5 font-mono text-xs"
                      >
                        <Mail className="h-3 w-3 text-muted-foreground" />
                        {email}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </PageSection>

      {/* Transmission Details */}
      <PageSection delay={0.1}>
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Clock className="h-5 w-5 text-muted-foreground" />
              <CardTitle>Transmission Details</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-4">
              <div>
                <p className="text-muted-foreground">Pages</p>
                <p className="text-lg font-semibold">{data.pageCount}</p>
              </div>
              <div>
                <p className="text-muted-foreground">File Size</p>
                <p>{formatBytes(data.fileSizeBytes)}</p>
              </div>
              <TimestampField
                label={data.direction === "inbound" ? "Received" : "Sent"}
                value={data.receivedAt}
              />
              <TimestampField label="Created" value={data.createdAt} />
            </div>
            {data.errorMessage && data.status !== "failed" && (
              <div className="mt-4">
                <Separator className="mb-4" />
                <div>
                  <p className="text-muted-foreground text-sm">Error Message</p>
                  <p className="mt-1 font-mono text-xs text-red-600 dark:text-red-400">
                    {data.errorMessage}
                  </p>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </PageSection>

      {/* Content / Document Preview */}
      <PageSection delay={0.15}>
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FileText className="h-5 w-5 text-muted-foreground" />
                <CardTitle>Content</CardTitle>
              </div>
              <Button variant="outline" size="sm" asChild>
                <a href={`/api/fax/messages/${messageId}/download`} download>
                  <Download className="mr-2 h-3.5 w-3.5" /> Download Document
                </a>
              </Button>
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
                  className="h-[600px] w-full border-none"
                />
              </div>
            ) : (
              <div className="flex h-[200px] flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-border/60 text-muted-foreground">
                <FileText className="h-8 w-8" />
                <p className="text-sm">Document preview is not available.</p>
                <Button variant="outline" size="sm" asChild>
                  <a href={`/api/fax/messages/${messageId}/download`} download>
                    <Download className="mr-2 h-3.5 w-3.5" /> Download instead
                  </a>
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      </PageSection>

      {/* Metadata */}
      <PageSection delay={0.2}>
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Hash className="h-5 w-5 text-muted-foreground" />
              <CardTitle>Metadata</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-3">
              <div>
                <p className="text-muted-foreground">Message ID</p>
                <div className="flex items-center gap-1">
                  <p className="font-mono text-xs">{messageId}</p>
                  <CopyButton value={messageId} label="message ID" />
                </div>
              </div>
              <div>
                <p className="text-muted-foreground">Fax Number ID</p>
                <div className="flex items-center gap-1">
                  <p className="font-mono text-xs">{data.faxNumberId}</p>
                  <CopyButton value={data.faxNumberId} label="fax number ID" />
                </div>
              </div>
              <div>
                <p className="text-muted-foreground">File Path</p>
                <div className="flex items-center gap-1">
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <p className="truncate font-mono text-xs">{data.filePath || "---"}</p>
                    </TooltipTrigger>
                    <TooltipContent side="top" className="max-w-sm">
                      <p>{data.filePath || "---"}</p>
                    </TooltipContent>
                  </Tooltip>
                  {data.filePath && <CopyButton value={data.filePath} label="file path" />}
                </div>
              </div>
              <TimestampField label="Created" value={data.createdAt} />
              <TimestampField label="Updated" value={data.updatedAt} />
              <TimestampField
                label={data.direction === "inbound" ? "Received At" : "Sent At"}
                value={data.receivedAt}
              />
            </div>
          </CardContent>
        </Card>
      </PageSection>

      {/* Danger Zone */}
      <PageSection delay={0.25}>
        <Card className="border-destructive/30">
          <CardHeader>
            <CardTitle className="text-destructive">Danger Zone</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium text-sm">Delete this fax message</p>
                <p className="text-sm text-muted-foreground">
                  This will permanently delete this fax message and its associated document.
                  This action cannot be undone.
                </p>
              </div>
              <Button
                variant="destructive"
                size="sm"
                onClick={() => setDeleteOpen(true)}
                disabled={deleteMutation.isPending}
              >
                <Trash2 className="mr-2 h-4 w-4" /> Delete
              </Button>
            </div>
          </CardContent>
        </Card>
      </PageSection>

      {/* Delete confirmation dialog */}
      <AlertDialog open={deleteOpen} onOpenChange={setDeleteOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-destructive" />
              Delete fax message?
            </AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete this fax message from{" "}
              <strong>{data.remoteNumber}</strong> and its associated document.
              This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel
              onClick={() => setDeleteOpen(false)}
              disabled={deleteMutation.isPending}
            >
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              className={buttonVariants({ variant: "destructive" })}
              onClick={() => {
                handleDelete()
                setDeleteOpen(false)
              }}
              disabled={deleteMutation.isPending}
            >
              {deleteMutation.isPending && (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              )}
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </PageContainer>
  )
}
