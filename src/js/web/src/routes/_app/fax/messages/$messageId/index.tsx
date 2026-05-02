import { createFileRoute, Link, useRouter } from "@tanstack/react-router"
import { useMemo, useState } from "react"
import {
  AlertCircle,
  AlertTriangle,
  ArrowDownLeft,
  ArrowLeft,
  ArrowUpRight,
  CheckCircle2,
  Clock,
  Copy,
  Download,
  FileText,
  Hash,
  History,
  Info,
  Loader2,
  Mail,
  MoreHorizontal,
  Plus,
  RefreshCw,
  Send,
  Trash2,
  XCircle,
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
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { EmptyState } from "@/components/ui/empty-state"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"
import { SkeletonCard } from "@/components/ui/skeleton"
import { CopyButton } from "@/components/ui/copy-button"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { DirectionBadge, FaxStatusBadge } from "@/components/fax/fax-status-badge"
import { EntityActivityPanel } from "@/components/shared/entity-activity-panel"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { useDeleteFaxMessage, useDownloadFaxDocument, useFaxMessage } from "@/lib/api/hooks/fax"
import { formatDateTime, formatRelativeTime, formatRelativeTimeShort } from "@/lib/date-utils"
import { formatBytes } from "@/lib/format-utils"
import type { FaxMessage, FaxStatus } from "@/lib/generated/api"

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

// -- Fax Message Timeline ---------------------------------------------------

interface FaxTimelineEvent {
  id: string
  timestamp: string
  label: string
  description?: string
  icon: React.ComponentType<{ className?: string }>
  dotColor: string
}

/** Map fax status values to the order they appear in a lifecycle. */
const STATUS_ORDER: Record<string, number> = {
  queued: 0,
  sending: 1,
  sent: 2,
  received: 2,
  delivered: 3,
  failed: 99,
}

/**
 * Determine which statuses the message likely passed through based on its
 * current status and direction.  For example an outbound "delivered" message
 * went through queued -> sending -> sent -> delivered.
 */
function inferStatusTransitions(
  status: FaxStatus | undefined,
  direction: "inbound" | "outbound",
): FaxStatus[] {
  if (!status) return []

  if (direction === "inbound") {
    // Inbound messages jump straight to received/delivered or failed.
    switch (status) {
      case "delivered":
        return ["received", "delivered"]
      case "received":
        return ["received"]
      case "failed":
        return ["received", "failed"]
      default:
        return [status]
    }
  }

  // Outbound lifecycle
  switch (status) {
    case "queued":
      return ["queued"]
    case "sending":
      return ["queued", "sending"]
    case "sent":
      return ["queued", "sending", "sent"]
    case "delivered":
      return ["queued", "sending", "sent", "delivered"]
    case "failed":
      return ["queued", "sending", "failed"]
    default:
      return [status]
  }
}

const STATUS_META: Record<
  string,
  { label: string; icon: React.ComponentType<{ className?: string }>; dotColor: string }
> = {
  queued: { label: "Queued for transmission", icon: Clock, dotColor: "bg-slate-500" },
  sending: { label: "Transmission in progress", icon: Send, dotColor: "bg-amber-500" },
  sent: { label: "Sent successfully", icon: CheckCircle2, dotColor: "bg-blue-500" },
  received: { label: "Received", icon: CheckCircle2, dotColor: "bg-emerald-500" },
  delivered: { label: "Delivered", icon: CheckCircle2, dotColor: "bg-emerald-500" },
  failed: { label: "Transmission failed", icon: XCircle, dotColor: "bg-red-500" },
}

function buildFaxTimelineEvents(message: FaxMessage): FaxTimelineEvent[] {
  const events: FaxTimelineEvent[] = []

  // 1. Created
  if (message.createdAt) {
    events.push({
      id: "created",
      timestamp: message.createdAt,
      label: message.direction === "inbound" ? "Fax received by system" : "Fax message created",
      description:
        message.direction === "inbound"
          ? `From ${message.remoteName ?? message.remoteNumber}`
          : `To ${message.remoteName ?? message.remoteNumber}`,
      icon: Plus,
      dotColor: "bg-green-500",
    })
  }

  // 2. Inferred status transitions (placed between created and final timestamps)
  const transitions = inferStatusTransitions(message.status, message.direction)
  const createdMs = message.createdAt ? new Date(message.createdAt).getTime() : 0
  const finalMs = message.receivedAt
    ? new Date(message.receivedAt).getTime()
    : message.updatedAt
      ? new Date(message.updatedAt).getTime()
      : createdMs

  // Distribute intermediate statuses evenly between created and final
  const intermediateStatuses = transitions.filter((s) => {
    // Don't duplicate the "created" event or the final status that maps to receivedAt
    const order = STATUS_ORDER[s] ?? 0
    const isFinal = s === transitions[transitions.length - 1]
    return !isFinal && order > 0
  })

  for (let i = 0; i < intermediateStatuses.length; i++) {
    const s = intermediateStatuses[i]
    const meta = STATUS_META[s] ?? {
      label: s,
      icon: RefreshCw,
      dotColor: "bg-zinc-400",
    }
    // Interpolate timestamps between created and final
    const fraction = (i + 1) / (intermediateStatuses.length + 1)
    const interpolatedMs = createdMs + (finalMs - createdMs) * fraction
    events.push({
      id: `status-${s}`,
      timestamp: new Date(interpolatedMs).toISOString(),
      label: meta.label,
      icon: meta.icon,
      dotColor: meta.dotColor,
    })
  }

  // 3. Received/Sent timestamp (the key "completion" event)
  if (message.receivedAt) {
    const finalStatus = transitions[transitions.length - 1]
    const meta = finalStatus
      ? STATUS_META[finalStatus]
      : undefined
    events.push({
      id: "received",
      timestamp: message.receivedAt,
      label:
        message.direction === "inbound"
          ? (meta?.label ?? "Received")
          : (meta?.label ?? "Sent"),
      description: message.pageCount
        ? `${message.pageCount} page${message.pageCount !== 1 ? "s" : ""} transmitted`
        : undefined,
      icon: meta?.icon ?? CheckCircle2,
      dotColor: meta?.dotColor ?? "bg-emerald-500",
    })
  } else if (message.status === "failed") {
    // Failed but no receivedAt -- still show the failure event
    events.push({
      id: "failed",
      timestamp: message.updatedAt ?? message.createdAt ?? "",
      label: "Transmission failed",
      description: message.errorMessage ?? undefined,
      icon: XCircle,
      dotColor: "bg-red-500",
    })
  }

  // 4. Email delivery (if delivered to email recipients)
  if (
    message.deliveredToEmails &&
    message.deliveredToEmails.length > 0 &&
    message.status === "delivered"
  ) {
    const ts = message.receivedAt ?? message.updatedAt ?? message.createdAt ?? ""
    const deliveryMs = ts ? new Date(ts).getTime() + 1000 : 0
    events.push({
      id: "email-delivery",
      timestamp: new Date(deliveryMs).toISOString(),
      label: "Delivered to email",
      description: message.deliveredToEmails.join(", "),
      icon: Mail,
      dotColor: "bg-blue-500",
    })
  }

  // 5. Last updated (if distinct from other timestamps)
  if (
    message.updatedAt &&
    message.updatedAt !== message.createdAt &&
    message.updatedAt !== message.receivedAt
  ) {
    events.push({
      id: "updated",
      timestamp: message.updatedAt,
      label: "Record updated",
      icon: RefreshCw,
      dotColor: "bg-zinc-400",
    })
  }

  events.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())

  return events
}

function FaxMessageTimeline({ message }: { message: FaxMessage }) {
  const events = useMemo(() => buildFaxTimelineEvents(message), [message])

  if (events.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-6 text-center">
        <Clock className="mb-2 h-6 w-6 text-muted-foreground/40" />
        <p className="text-sm text-muted-foreground">No timeline events</p>
      </div>
    )
  }

  return (
    <div className="relative space-y-0">
      {events.map((event, index) => {
        const Icon = event.icon
        const isLast = index === events.length - 1

        return (
          <div key={event.id} className="relative flex gap-3 pb-5 last:pb-0">
            {/* Vertical connector line */}
            {!isLast && (
              <div className="absolute left-3 top-7 h-[calc(100%-12px)] w-px bg-border" />
            )}

            {/* Dot with icon */}
            <div
              className={`mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-white ${event.dotColor}`}
            >
              <Icon className="h-3 w-3" />
            </div>

            {/* Content */}
            <div className="min-w-0 flex-1 space-y-0.5">
              <p className="text-sm font-medium leading-snug">{event.label}</p>
              {event.description && (
                <p className="truncate text-xs text-muted-foreground">{event.description}</p>
              )}
              <Tooltip>
                <TooltipTrigger asChild>
                  <p className="cursor-default text-xs text-muted-foreground/70">
                    {formatRelativeTimeShort(event.timestamp)}
                  </p>
                </TooltipTrigger>
                <TooltipContent>{formatDateTime(event.timestamp)}</TooltipContent>
              </Tooltip>
            </div>
          </div>
        )
      })}
    </div>
  )
}

// -- Main page --------------------------------------------------------------

function FaxMessageDetailPage() {
  useDocumentTitle("Fax Message")
  const { messageId } = Route.useParams()
  const router = useRouter()
  const { data, isLoading, isError, refetch } = useFaxMessage(messageId)
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
          <EmptyState
            icon={AlertCircle}
            title="Unable to load message"
            description="Something went wrong. Please try again."
            action={<Button variant="outline" size="sm" onClick={() => refetch()}>Try again</Button>}
          />
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
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm">
                  <MoreHorizontal className="h-4 w-4" />
                  <span className="sr-only">Actions</span>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => navigator.clipboard.writeText(messageId)}>
                  <Copy className="mr-2 h-4 w-4" />
                  Copy Message ID
                </DropdownMenuItem>
                <DropdownMenuItem asChild>
                  <a href={`/api/fax/messages/${messageId}/download`} download>
                    <Download className="mr-2 h-4 w-4" />
                    Download Document
                  </a>
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  className="text-destructive focus:text-destructive"
                  onClick={() => setDeleteOpen(true)}
                >
                  <Trash2 className="mr-2 h-4 w-4" />
                  Delete Message
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
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
        <SectionErrorBoundary name="Message Info">
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
        </SectionErrorBoundary>
      </PageSection>

      {/* Transmission Details */}
      <PageSection delay={0.1}>
        <SectionErrorBoundary name="Transmission Details">
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
        </SectionErrorBoundary>
      </PageSection>

      {/* Message History */}
      <PageSection delay={0.12}>
        <SectionErrorBoundary name="Message History">
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <History className="h-5 w-5 text-muted-foreground" />
              <CardTitle>Message History</CardTitle>
            </div>
          </CardHeader>
          <CardContent className="space-y-6">
            <FaxMessageTimeline message={data} />

            <Separator />

            {/* Audit Trail */}
            <div>
              <p className="mb-3 text-xs font-medium uppercase tracking-wider text-muted-foreground">
                Audit Trail
              </p>
              <EntityActivityPanel
                targetType="fax_message"
                targetId={messageId}
              />
            </div>
          </CardContent>
        </Card>
        </SectionErrorBoundary>
      </PageSection>

      {/* Content / Document Preview */}
      <PageSection delay={0.18}>
        <SectionErrorBoundary name="Document Preview">
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
        </SectionErrorBoundary>
      </PageSection>

      {/* Metadata */}
      <PageSection delay={0.22}>
        <SectionErrorBoundary name="Metadata">
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
                  {data.faxNumberId ? (
                    <Link
                      to="/fax/numbers/$faxNumberId"
                      params={{ faxNumberId: data.faxNumberId }}
                      className="font-mono text-xs text-primary hover:underline"
                    >
                      {data.faxNumberId}
                    </Link>
                  ) : (
                    <p className="font-mono text-xs">---</p>
                  )}
                  {data.faxNumberId && <CopyButton value={data.faxNumberId} label="fax number ID" />}
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
        </SectionErrorBoundary>
      </PageSection>

      {/* Danger Zone */}
      <PageSection delay={0.28}>
        <SectionErrorBoundary name="Danger Zone">
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
        </SectionErrorBoundary>
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
