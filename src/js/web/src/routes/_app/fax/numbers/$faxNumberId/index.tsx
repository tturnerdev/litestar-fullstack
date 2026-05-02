import { createFileRoute, Link, useBlocker, useNavigate } from "@tanstack/react-router"
import {
  AlertCircle,
  AlertTriangle,
  ArrowLeft,
  ArrowUpRight,
  ChevronRight,
  Copy,
  Eye,
  Link2,
  Loader2,
  MessageSquare,
  MoreHorizontal,
  Pencil,
  Phone,
  Save,
  Send,
  ShieldAlert,
  Trash2,
  Users,
  X,
} from "lucide-react"
import { useCallback, useEffect, useMemo, useState } from "react"
import { toast } from "sonner"
import { EmailRouteEditor } from "@/components/fax/email-route-editor"
import { DirectionBadge, FaxStatusBadge } from "@/components/fax/fax-status-badge"
import { EntityActivityPanel } from "@/components/shared/entity-activity-panel"
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
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb"
import { Button, buttonVariants } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { CopyButton } from "@/components/ui/copy-button"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { useDeleteFaxNumber, useFaxMessages, useFaxNumber, useUpdateFaxNumber } from "@/lib/api/hooks/fax"
import { useTeam } from "@/lib/api/hooks/teams"
import { formatDateTime, formatRelativeTime } from "@/lib/date-utils"
import { formatPhoneNumber } from "@/lib/format-utils"
import { cn } from "@/lib/utils"

export const Route = createFileRoute("/_app/fax/numbers/$faxNumberId/")({
  component: FaxNumberDetailPage,
})

// ── Timestamp with tooltip ──────────────────────────────────────────────

function TimestampField({ label, value }: { label: string; value: string | null | undefined }) {
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
  useDocumentTitle(data?.number ? `${data.number} - Fax Number` : "Fax Number")
  const deleteFaxNumber = useDeleteFaxNumber()
  const teamQuery = useTeam(data?.teamId ?? "")

  // Fetch recent messages (last 5) -- filter client-side by faxNumberId
  const { data: messagesData } = useFaxMessages({
    page: 1,
    pageSize: 50,
    orderBy: "received_at",
    sortOrder: "desc",
  })

  const [showDeleteDialog, setShowDeleteDialog] = useState(false)
  const [editing, setEditing] = useState(false)

  // Filter messages for this fax number and take the last 5
  const recentMessages = useMemo(() => {
    if (!messagesData?.items) return []
    return messagesData.items.filter((msg) => msg.faxNumberId === faxNumberId).slice(0, 5)
  }, [messagesData?.items, faxNumberId])

  // Message count summary
  const messageCounts = useMemo(() => {
    if (!messagesData?.items) return { sent: 0, received: 0, total: 0 }
    const forNumber = messagesData.items.filter((msg) => msg.faxNumberId === faxNumberId)
    const sent = forNumber.filter((msg) => msg.direction === "outbound").length
    const received = forNumber.filter((msg) => msg.direction === "inbound").length
    return { sent, received, total: sent + received }
  }, [messagesData?.items, faxNumberId])

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
            action={
              <Button variant="outline" size="sm" onClick={() => refetch()}>
                Try again
              </Button>
            }
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
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm">
                  <MoreHorizontal className="h-4 w-4" />
                  <span className="sr-only">Actions</span>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => navigator.clipboard.writeText(faxNumberId)}>
                  <Copy className="mr-2 h-4 w-4" />
                  Copy Fax Number ID
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => navigator.clipboard.writeText(data.number)}>
                  <Copy className="mr-2 h-4 w-4" />
                  Copy Phone Number
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={() => setEditing(true)}>
                  <Pencil className="mr-2 h-4 w-4" />
                  Edit
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem className="text-destructive focus:text-destructive" onClick={() => setShowDeleteDialog(true)}>
                  <Trash2 className="mr-2 h-4 w-4" />
                  Delete Fax Number
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
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
              This will permanently delete <strong>{data.label ?? formatPhoneNumber(data.number)}</strong> and all associated email routes. This action cannot be undone.
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

      {/* Number Info (inline editing) */}
      <PageSection>
        <SectionErrorBoundary name="Number Info">
          <FaxNumberSettingsCard faxNumberId={faxNumberId} messageCounts={messageCounts} editing={editing} setEditing={setEditing} />
        </SectionErrorBoundary>
      </PageSection>

      {/* Email Routes */}
      <PageSection delay={0.1}>
        <SectionErrorBoundary name="Email Routes">
          <EmailRouteEditor faxNumberId={faxNumberId} />
        </SectionErrorBoundary>
      </PageSection>

      {/* Recent Messages */}
      <PageSection delay={0.15}>
        <SectionErrorBoundary name="Recent Messages">
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
                          {msg.remoteName && <span className="text-xs text-muted-foreground">{msg.remoteName}</span>}
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        <FaxStatusBadge status={msg.status} />
                        <Badge variant="outline" className="font-mono text-xs">
                          {msg.pageCount} pg{msg.pageCount === 1 ? "" : "s"}
                        </Badge>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <span className="cursor-default whitespace-nowrap text-xs text-muted-foreground">{formatRelativeTime(msg.receivedAt ?? msg.createdAt)}</span>
                          </TooltipTrigger>
                          <TooltipContent>{formatDateTime(msg.receivedAt ?? msg.createdAt)}</TooltipContent>
                        </Tooltip>
                        <Eye className="h-3.5 w-3.5 text-muted-foreground" />
                      </div>
                    </Link>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </SectionErrorBoundary>
      </PageSection>

      {/* Related Resources */}
      <PageSection delay={0.2}>
        <SectionErrorBoundary name="Related Resources">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Link2 className="h-5 w-5 text-muted-foreground" />
                Related Resources
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                {/* Team */}
                {data.teamId ? (
                  <Link
                    to="/teams/$teamId"
                    params={{ teamId: data.teamId }}
                    className="group flex items-center gap-3 rounded-lg border border-border/60 px-4 py-3 transition-colors hover:bg-muted/50 hover:border-primary/30"
                  >
                    <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-blue-500/10 text-blue-600 dark:text-blue-400">
                      <Users className="h-4.5 w-4.5" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className="text-xs text-muted-foreground">Team</p>
                      <p className="truncate text-sm font-medium group-hover:text-primary">{teamQuery.data?.name ?? "Loading..."}</p>
                    </div>
                    <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground/50 transition-transform group-hover:translate-x-0.5 group-hover:text-primary" />
                  </Link>
                ) : (
                  <div className="flex items-center gap-3 rounded-lg border border-dashed border-border/60 px-4 py-3">
                    <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-muted text-muted-foreground/50">
                      <Users className="h-4.5 w-4.5" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className="text-xs text-muted-foreground">Team</p>
                      <p className="text-sm text-muted-foreground">Not assigned</p>
                    </div>
                  </div>
                )}

                {/* E911 Registration */}
                <Link to="/e911" className="group flex items-center gap-3 rounded-lg border border-border/60 px-4 py-3 transition-colors hover:bg-muted/50 hover:border-primary/30">
                  <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-red-500/10 text-red-600 dark:text-red-400">
                    <ShieldAlert className="h-4.5 w-4.5" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="text-xs text-muted-foreground">E911 Registrations</p>
                    <p className="truncate text-sm font-medium group-hover:text-primary">View registrations</p>
                  </div>
                  <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground/50 transition-transform group-hover:translate-x-0.5 group-hover:text-primary" />
                </Link>
              </div>
            </CardContent>
          </Card>
        </SectionErrorBoundary>
      </PageSection>

      {/* Activity History */}
      <PageSection delay={0.25}>
        <SectionErrorBoundary name="Activity History">
          <Card>
            <CardHeader>
              <CardTitle>Activity History</CardTitle>
            </CardHeader>
            <CardContent>
              <EntityActivityPanel targetType="fax_number" targetId={faxNumberId} />
            </CardContent>
          </Card>
        </SectionErrorBoundary>
      </PageSection>

      {/* Danger Zone */}
      <PageSection delay={0.3}>
        <SectionErrorBoundary name="Danger Zone">
          <Card className="border-destructive/30">
            <CardHeader>
              <CardTitle className="text-destructive">Danger Zone</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium text-sm">Delete this fax number</p>
                  <p className="text-sm text-muted-foreground">This action cannot be undone. All email routes and message associations will be permanently removed.</p>
                </div>
                <Button variant="destructive" size="sm" onClick={() => setShowDeleteDialog(true)}>
                  <Trash2 className="mr-2 h-4 w-4" /> Delete
                </Button>
              </div>
            </CardContent>
          </Card>
        </SectionErrorBoundary>
      </PageSection>
    </PageContainer>
  )
}

// ── Fax Number Settings Card (inline editing) ──────────────────────────

interface SettingsFormData {
  label: string
  isActive: boolean
}

function FaxNumberSettingsCard({
  faxNumberId,
  messageCounts,
  editing,
  setEditing,
}: {
  faxNumberId: string
  messageCounts: { sent: number; received: number; total: number }
  editing: boolean
  setEditing: (editing: boolean) => void
}) {
  const { data, isLoading, isError, refetch } = useFaxNumber(faxNumberId)
  const updateMutation = useUpdateFaxNumber(faxNumberId)
  const [formData, setFormData] = useState<SettingsFormData>({
    label: "",
    isActive: true,
  })

  const syncFormFromData = useCallback(() => {
    if (data) {
      setFormData({
        label: data.label ?? "",
        isActive: data.isActive,
      })
    }
  }, [data])

  useEffect(() => {
    syncFormFromData()
  }, [syncFormFromData])

  const formDirty = useMemo(() => {
    if (!editing || !data) return false
    return formData.label !== (data.label ?? "") || formData.isActive !== data.isActive
  }, [editing, data, formData])

  const blocker = useBlocker({
    shouldBlockFn: () => formDirty,
    withResolver: true,
  })

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Skeleton className="h-5 w-5 rounded" />
            <Skeleton className="h-6 w-28" />
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="space-y-1.5">
                <Skeleton className="h-3.5 w-24" />
                <Skeleton className="h-5 w-36" />
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    )
  }

  if (isError || !data) {
    return (
      <EmptyState
        icon={AlertCircle}
        title="Unable to load fax number settings"
        description="Something went wrong. Please try again."
        action={
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            Try again
          </Button>
        }
      />
    )
  }

  function handleSave() {
    if (!data) return
    const payload: Record<string, unknown> = {}
    const trimmedLabel = formData.label.trim()
    if (trimmedLabel !== (data.label ?? "")) payload.label = trimmedLabel || null
    if (formData.isActive !== data.isActive) payload.isActive = formData.isActive

    if (Object.keys(payload).length === 0) {
      setEditing(false)
      return
    }

    updateMutation.mutate(payload, {
      onSuccess: () => {
        toast.success("Fax number updated successfully")
        setEditing(false)
      },
    })
  }

  function handleCancel() {
    syncFormFromData()
    setEditing(false)
  }

  function updateField<K extends keyof SettingsFormData>(field: K, value: SettingsFormData[K]) {
    setFormData((prev) => ({ ...prev, [field]: value }))
  }

  return (
    <>
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <div className="flex items-center gap-2">
                <Phone className="h-5 w-5 text-muted-foreground" />
                <CardTitle>Number Info</CardTitle>
              </div>
              <CardDescription>Fax number details, label, and status configuration.</CardDescription>
            </div>
            <div className="flex items-center gap-2">
              {(editing ? formData.isActive : data.isActive) ? (
                <Badge className="gap-1.5 bg-emerald-100 text-emerald-700 hover:bg-emerald-100 dark:bg-emerald-900/30 dark:text-emerald-400">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
                  Active
                </Badge>
              ) : (
                <Badge variant="outline" className="gap-1.5 text-muted-foreground">
                  <span className="h-1.5 w-1.5 rounded-full bg-muted-foreground" />
                  Inactive
                </Badge>
              )}
              {editing ? (
                <>
                  <Button size="sm" variant="outline" onClick={handleCancel} disabled={updateMutation.isPending}>
                    <X className="mr-2 h-4 w-4" /> Cancel
                  </Button>
                  <Button size="sm" onClick={handleSave} disabled={updateMutation.isPending}>
                    {updateMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Save className="mr-2 h-4 w-4" />}
                    {updateMutation.isPending ? "Saving..." : "Save changes"}
                  </Button>
                </>
              ) : (
                <Button size="sm" onClick={() => setEditing(true)}>
                  <Pencil className="mr-2 h-4 w-4" /> Edit
                </Button>
              )}
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-6">
          {editing && formDirty && (
            <div className="flex items-center gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm text-amber-700 dark:text-amber-400">
              <span className="inline-block h-1.5 w-1.5 rounded-full bg-amber-500" />
              You have unsaved changes
            </div>
          )}

          {/* Fax Number (always read-only) */}
          <div className="space-y-2">
            <Label>Fax Number</Label>
            <p className="font-mono text-base font-medium">{formatPhoneNumber(data.number)}</p>
          </div>

          {/* Label */}
          <div className="space-y-2">
            <Label htmlFor="fax-label">Label</Label>
            <p className="text-xs text-muted-foreground">A friendly name to identify this fax number.</p>
            {editing ? (
              <Input
                id="fax-label"
                placeholder="e.g. Main Fax, Billing Dept"
                value={formData.label}
                onChange={(e) => updateField("label", e.target.value)}
                disabled={updateMutation.isPending}
                maxLength={100}
              />
            ) : (
              <p className="text-sm">{data.label || <span className="text-muted-foreground italic">Not set</span>}</p>
            )}
          </div>

          {/* Status */}
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label>Status</Label>
              <p className="text-xs text-muted-foreground">When inactive, this number cannot send or receive faxes.</p>
            </div>
            {editing ? (
              <Switch checked={formData.isActive} onCheckedChange={(v) => updateField("isActive", v)} />
            ) : (
              <Badge
                variant={data.isActive ? "default" : "outline"}
                className={cn(
                  "gap-1.5",
                  data.isActive ? "bg-emerald-100 text-emerald-700 hover:bg-emerald-100 dark:bg-emerald-900/30 dark:text-emerald-400" : "text-muted-foreground",
                )}
              >
                <span className={cn("h-1.5 w-1.5 rounded-full", data.isActive ? "bg-emerald-500" : "bg-muted-foreground")} />
                {data.isActive ? "Active" : "Inactive"}
              </Badge>
            )}
          </div>

          <Separator />

          {/* Read-only info */}
          <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-3">
            <div>
              <p className="text-muted-foreground text-sm">Fax Number ID</p>
              <div className="flex items-center gap-1">
                <p className="font-mono text-xs">{faxNumberId}</p>
                <CopyButton value={faxNumberId} label="fax number ID" />
              </div>
            </div>
            <div>
              <p className="text-muted-foreground text-sm">Assignment</p>
              <p className="text-sm">{data.teamId ? "Team" : "Personal"}</p>
            </div>
            {messageCounts.total > 0 && (
              <div>
                <p className="text-muted-foreground text-sm">Message Summary</p>
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

          <Separator />

          {/* Timestamps */}
          <div className="grid gap-4 text-sm md:grid-cols-2">
            <TimestampField label="Created" value={data.createdAt} />
            <TimestampField label="Last Updated" value={data.updatedAt} />
          </div>
        </CardContent>
      </Card>

      {/* Unsaved changes dialog */}
      <AlertDialog open={blocker.status === "blocked"} onOpenChange={() => blocker.reset?.()}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Unsaved changes</AlertDialogTitle>
            <AlertDialogDescription>You have unsaved changes to fax number settings. Are you sure you want to leave? Your changes will be lost.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => blocker.reset?.()}>Stay on page</AlertDialogCancel>
            <AlertDialogAction onClick={() => blocker.proceed?.()}>Discard changes</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
