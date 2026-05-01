import { createFileRoute, Link, useNavigate } from "@tanstack/react-router"
import { useMemo, useState } from "react"
import {
  AlertCircle,
  AlertTriangle,
  ArrowLeft,
  ArrowUpRight,
  Check,
  Eye,
  Hash,
  MessageSquare,
  Pencil,
  Phone,
  Send,
  Trash2,
  X,
} from "lucide-react"
import { DirectionBadge, FaxStatusBadge } from "@/components/fax/fax-status-badge"
import { EmailRouteEditor } from "@/components/fax/email-route-editor"
import { FaxNumberEditDialog } from "@/components/fax/fax-number-edit-dialog"
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
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Skeleton } from "@/components/ui/skeleton"
import { CopyButton } from "@/components/ui/copy-button"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useDocumentTitle } from "@/hooks/use-document-title"
import {
  useDeleteFaxNumber,
  useFaxMessages,
  useFaxNumber,
  useUpdateFaxNumber,
} from "@/lib/api/hooks/fax"
import { EntityActivityPanel } from "@/components/shared/entity-activity-panel"
import { formatDateTime, formatRelativeTime } from "@/lib/date-utils"
import { formatPhoneNumber } from "@/lib/format-utils"

export const Route = createFileRoute("/_app/fax/numbers/$faxNumberId/")({
  component: FaxNumberDetailPage,
})

// ── Timestamp with tooltip ──────────────────────────────────────────────

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

// ── Status badge ────────────────────────────────────────────────────────

function ActiveStatusBadge({ isActive }: { isActive: boolean }) {
  return isActive ? (
    <Badge className="gap-1 bg-emerald-100 text-emerald-700 hover:bg-emerald-100 dark:bg-emerald-900/30 dark:text-emerald-400">
      <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
      Active
    </Badge>
  ) : (
    <Badge variant="outline" className="gap-1 text-muted-foreground">
      <span className="h-1.5 w-1.5 rounded-full bg-muted-foreground" />
      Inactive
    </Badge>
  )
}

// ── Main page ───────────────────────────────────────────────────────────

function FaxNumberDetailPage() {
  const { faxNumberId } = Route.useParams()
  const navigate = useNavigate()
  const { data, isLoading, isError, refetch } = useFaxNumber(faxNumberId)
  useDocumentTitle(data?.number ?? "Fax Number")
  const updateFaxNumber = useUpdateFaxNumber(faxNumberId)
  const deleteFaxNumber = useDeleteFaxNumber()

  // Fetch recent messages (last 5) -- filter client-side by faxNumberId
  const { data: messagesData } = useFaxMessages({
    page: 1,
    pageSize: 50,
    orderBy: "received_at",
    sortOrder: "desc",
  })

  const [editingLabel, setEditingLabel] = useState(false)
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)
  const [labelValue, setLabelValue] = useState("")

  // Filter messages for this fax number and take the last 5
  const recentMessages = useMemo(() => {
    if (!messagesData?.items) return []
    return messagesData.items
      .filter((msg) => msg.faxNumberId === faxNumberId)
      .slice(0, 5)
  }, [messagesData?.items, faxNumberId])

  // Message count summary
  const messageCounts = useMemo(() => {
    if (!messagesData?.items) return { sent: 0, received: 0, total: 0 }
    const forNumber = messagesData.items.filter((msg) => msg.faxNumberId === faxNumberId)
    const sent = forNumber.filter((msg) => msg.direction === "outbound").length
    const received = forNumber.filter((msg) => msg.direction === "inbound").length
    return { sent, received, total: sent + received }
  }, [messagesData?.items, faxNumberId])

  function startEditingLabel() {
    setLabelValue(data?.label ?? "")
    setEditingLabel(true)
  }

  function cancelEditingLabel() {
    setEditingLabel(false)
    setLabelValue("")
  }

  function saveLabel() {
    const trimmed = labelValue.trim()
    updateFaxNumber.mutate(
      { label: trimmed || null },
      { onSuccess: () => setEditingLabel(false) },
    )
  }

  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        {/* Header skeleton */}
        <div className="space-y-2">
          <Skeleton className="h-4 w-36" />
          <Skeleton className="h-8 w-48" />
          <Skeleton className="h-4 w-36" />
        </div>
        {/* Number Info card */}
        <PageSection>
          <div className="rounded-xl border border-border/60 bg-card/80 p-6 space-y-4">
            <div className="flex items-center gap-2">
              <Skeleton className="h-5 w-5 rounded" />
              <Skeleton className="h-6 w-28" />
            </div>
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {Array.from({ length: 4 }).map((_, i) => (
                <div key={i} className="space-y-1.5">
                  <Skeleton className="h-3.5 w-24" />
                  <Skeleton className="h-5 w-36" />
                </div>
              ))}
            </div>
          </div>
        </PageSection>
        {/* Email Routes card */}
        <PageSection delay={0.1}>
          <div className="rounded-xl border border-border/60 bg-card/80 p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Skeleton className="h-5 w-5 rounded" />
                <Skeleton className="h-6 w-28" />
              </div>
              <Skeleton className="h-9 w-28 rounded-md" />
            </div>
            <div className="space-y-2">
              {Array.from({ length: 2 }).map((_, i) => (
                <Skeleton key={i} className="h-14 w-full rounded-md" />
              ))}
            </div>
          </div>
        </PageSection>
        {/* Recent Messages card */}
        <PageSection delay={0.15}>
          <div className="rounded-xl border border-border/60 bg-card/80 p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Skeleton className="h-5 w-5 rounded" />
                <Skeleton className="h-6 w-36" />
              </div>
              <Skeleton className="h-8 w-20 rounded-md" />
            </div>
            <div className="space-y-2">
              {Array.from({ length: 3 }).map((_, i) => (
                <Skeleton key={i} className="h-12 w-full rounded-md" />
              ))}
            </div>
          </div>
        </PageSection>
        {/* Metadata card */}
        <PageSection delay={0.2}>
          <div className="rounded-xl border border-border/60 bg-card/80 p-6 space-y-4">
            <div className="flex items-center gap-2">
              <Skeleton className="h-5 w-5 rounded" />
              <Skeleton className="h-6 w-24" />
            </div>
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
              {Array.from({ length: 4 }).map((_, i) => (
                <div key={i} className="space-y-1.5">
                  <Skeleton className="h-3.5 w-20" />
                  <Skeleton className="h-5 w-32" />
                </div>
              ))}
            </div>
          </div>
        </PageSection>
      </PageContainer>
    )
  }

  if (isError || !data) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader
          eyebrow="Communications"
          title="Fax Number Details"
          actions={
            <Button variant="outline" size="sm" asChild>
              <Link to="/fax/numbers">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back to numbers
              </Link>
            </Button>
          }
        />
        <PageSection>
          <EmptyState
            icon={AlertCircle}
            title="Unable to load fax number"
            description="Something went wrong. Please try again."
            action={<Button variant="outline" size="sm" onClick={() => refetch()}>Try again</Button>}
          />
        </PageSection>
      </PageContainer>
    )
  }

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Communications"
        title={data.label ?? formatPhoneNumber(data.number)}
        description={data.label ? formatPhoneNumber(data.number) : undefined}
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
                  <Link to="/fax">Fax</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbLink asChild>
                  <Link to="/fax/numbers">Numbers</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbPage>{data.label ?? data.number}</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
        actions={
          <div className="flex items-center gap-3">
            <ActiveStatusBadge isActive={data.isActive} />
            <Button size="sm" asChild>
              <Link to="/fax/send">
                <Send className="mr-2 h-4 w-4" /> Send Fax
              </Link>
            </Button>
            <FaxNumberEditDialog
              faxNumber={data}
              trigger={
                <Button variant="outline" size="sm">
                  <Pencil className="mr-2 h-4 w-4" /> Edit
                </Button>
              }
            />
            <Button
              variant="outline"
              size="sm"
              className="text-destructive hover:bg-destructive/10"
              onClick={() => setShowDeleteDialog(true)}
            >
              <Trash2 className="mr-2 h-4 w-4" />
              Delete
            </Button>
            <Button variant="outline" size="sm" asChild>
              <Link to="/fax/numbers">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back
              </Link>
            </Button>
          </div>
        }
      />

      {/* Delete confirmation dialog */}
      <AlertDialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-destructive" />
              Delete fax number?
            </AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete{" "}
              <strong>{data.label ?? formatPhoneNumber(data.number)}</strong> and all
              associated email routes. This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setShowDeleteDialog(false)} disabled={deleteFaxNumber.isPending}>
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              className={buttonVariants({ variant: "destructive" })}
              disabled={deleteFaxNumber.isPending}
              onClick={() => {
                deleteFaxNumber.mutate(faxNumberId, {
                  onSuccess: () => {
                    setShowDeleteDialog(false)
                    navigate({ to: "/fax/numbers" })
                  },
                })
              }}
            >
              {deleteFaxNumber.isPending ? "Deleting..." : "Delete fax number"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Number Info */}
      <PageSection>
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Phone className="h-5 w-5 text-muted-foreground" />
              <CardTitle>Number Info</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-3">
              <div>
                <p className="text-muted-foreground">Fax Number</p>
                <p className="font-mono text-base font-medium">{formatPhoneNumber(data.number)}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Label</p>
                {editingLabel ? (
                  <div className="flex items-center gap-2">
                    <Input
                      value={labelValue}
                      onChange={(e) => setLabelValue(e.target.value)}
                      placeholder="e.g. Main Fax, Billing Dept"
                      className="h-9 max-w-xs"
                      onKeyDown={(e) => {
                        if (e.key === "Enter") saveLabel()
                        if (e.key === "Escape") cancelEditingLabel()
                      }}
                      autoFocus
                    />
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={saveLabel}
                      disabled={updateFaxNumber.isPending}
                    >
                      <Check className="h-4 w-4 text-emerald-600" />
                    </Button>
                    <Button variant="ghost" size="sm" onClick={cancelEditingLabel}>
                      <X className="h-4 w-4" />
                    </Button>
                  </div>
                ) : (
                  <div className="flex items-center gap-2">
                    <p className="font-medium">{data.label || "---"}</p>
                    <Button variant="ghost" size="sm" onClick={startEditingLabel} className="h-7 w-7 p-0" aria-label="Edit label">
                      <Pencil className="h-3.5 w-3.5 text-muted-foreground" />
                    </Button>
                  </div>
                )}
              </div>
              <div>
                <p className="text-muted-foreground">Status</p>
                <div className="mt-0.5 flex items-center gap-3">
                  <ActiveStatusBadge isActive={data.isActive} />
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 text-xs"
                    onClick={() => updateFaxNumber.mutate({ isActive: !data.isActive })}
                    disabled={updateFaxNumber.isPending}
                  >
                    {updateFaxNumber.isPending
                      ? "..."
                      : data.isActive
                        ? "Deactivate"
                        : "Activate"}
                  </Button>
                </div>
              </div>
              <div>
                <p className="text-muted-foreground">Assignment</p>
                <p>{data.teamId ? "Team" : "Personal"}</p>
              </div>
              {messageCounts.total > 0 && (
                <div className="md:col-span-2">
                  <p className="text-muted-foreground">Message Summary</p>
                  <div className="mt-1 flex items-center gap-3">
                    <Badge variant="outline" className="gap-1.5 font-mono text-xs">
                      <ArrowUpRight className="h-3 w-3 text-violet-500" />
                      {messageCounts.sent} sent
                    </Badge>
                    <Badge variant="outline" className="gap-1.5 font-mono text-xs">
                      <ArrowLeft className="h-3 w-3 text-blue-500" />
                      {messageCounts.received} received
                    </Badge>
                  </div>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </PageSection>

      {/* Email Routes */}
      <PageSection delay={0.1}>
        <EmailRouteEditor faxNumberId={faxNumberId} />
      </PageSection>

      {/* Recent Messages */}
      <PageSection delay={0.15}>
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <MessageSquare className="h-5 w-5 text-muted-foreground" />
                <CardTitle>Recent Messages</CardTitle>
              </div>
              <Button variant="ghost" size="sm" asChild>
                <Link to="/fax/messages">
                  View all <ArrowUpRight className="ml-1 h-3.5 w-3.5" />
                </Link>
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            {recentMessages.length === 0 ? (
              <div className="flex flex-col items-center gap-2 py-6 text-center">
                <MessageSquare className="h-8 w-8 text-muted-foreground/50" />
                <p className="text-sm text-muted-foreground">No messages yet for this number.</p>
                <Button size="sm" variant="outline" asChild>
                  <Link to="/fax/send">
                    <Send className="mr-2 h-3.5 w-3.5" /> Send a fax
                  </Link>
                </Button>
              </div>
            ) : (
              <div className="space-y-2">
                {recentMessages.map((msg) => (
                  <Link
                    key={msg.id}
                    to="/fax/messages/$messageId"
                    params={{ messageId: msg.id }}
                    className="flex items-center justify-between rounded-md border border-border/60 px-3 py-2.5 transition-colors hover:bg-muted/50"
                  >
                    <div className="flex items-center gap-3">
                      <DirectionBadge direction={msg.direction} />
                      <div className="flex flex-col gap-0.5">
                        <span className="font-mono text-sm">{msg.remoteNumber}</span>
                        {msg.remoteName && (
                          <span className="text-xs text-muted-foreground">{msg.remoteName}</span>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <FaxStatusBadge status={msg.status} />
                      <Badge variant="outline" className="font-mono text-xs">
                        {msg.pageCount} pg{msg.pageCount === 1 ? "" : "s"}
                      </Badge>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span className="cursor-default whitespace-nowrap text-xs text-muted-foreground">
                            {formatRelativeTime(msg.receivedAt ?? msg.createdAt)}
                          </span>
                        </TooltipTrigger>
                        <TooltipContent>
                          {formatDateTime(msg.receivedAt ?? msg.createdAt)}
                        </TooltipContent>
                      </Tooltip>
                      <Eye className="h-3.5 w-3.5 text-muted-foreground" />
                    </div>
                  </Link>
                ))}
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
            <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-4">
              <div>
                <p className="text-muted-foreground text-sm">Fax Number ID</p>
                <div className="flex items-center gap-1">
                  <p className="font-mono text-xs">{faxNumberId}</p>
                  <CopyButton value={faxNumberId} label="fax number ID" />
                </div>
              </div>
              <TimestampField label="Created" value={data.createdAt} />
              <TimestampField label="Updated" value={data.updatedAt} />
              <div>
                <p className="text-muted-foreground text-sm">Owner</p>
                <p className="text-sm">{data.teamId ? "Team-assigned" : "Personal"}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </PageSection>

      {/* Activity History */}
      <PageSection delay={0.25}>
        <Card>
          <CardHeader>
            <CardTitle>Activity History</CardTitle>
          </CardHeader>
          <CardContent>
            <EntityActivityPanel
              targetType="fax_number"
              targetId={faxNumberId}
            />
          </CardContent>
        </Card>
      </PageSection>

      {/* Danger Zone */}
      <PageSection delay={0.3}>
        <Card className="border-destructive/30">
          <CardHeader>
            <CardTitle className="text-destructive">Danger Zone</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium text-sm">Delete this fax number</p>
                <p className="text-sm text-muted-foreground">
                  This action cannot be undone. All email routes and message associations will be
                  permanently removed.
                </p>
              </div>
              <Button
                variant="destructive"
                size="sm"
                onClick={() => setShowDeleteDialog(true)}
              >
                <Trash2 className="mr-2 h-4 w-4" /> Delete
              </Button>
            </div>
          </CardContent>
        </Card>
      </PageSection>
    </PageContainer>
  )
}
