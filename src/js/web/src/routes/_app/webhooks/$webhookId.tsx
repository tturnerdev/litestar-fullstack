import { createFileRoute, Link, useBlocker, useRouter } from "@tanstack/react-router"
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  ArrowLeft,
  Check,
  Clock,
  Copy,
  Eye,
  EyeOff,
  Fingerprint,
  Globe,
  Loader2,
  MoreHorizontal,
  Pencil,
  Play,
  Save,
  Trash2,
  X,
  XCircle,
} from "lucide-react"
import { useCallback, useMemo, useRef, useState } from "react"
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
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { CopyButton } from "@/components/ui/copy-button"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { Skeleton } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Textarea } from "@/components/ui/textarea"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useDocumentTitle } from "@/hooks/use-document-title"
import type { WebhookDelivery } from "@/lib/api/hooks/webhooks"
import { useDeleteWebhook, useTestWebhook, useUpdateWebhook, useWebhook, useWebhookDeliveries } from "@/lib/api/hooks/webhooks"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"

export const Route = createFileRoute("/_app/webhooks/$webhookId")({
  component: WebhookDetailPage,
})

// -- Constants ----------------------------------------------------------------

const AVAILABLE_EVENTS = [
  "extension.created",
  "extension.updated",
  "extension.deleted",
  "device.created",
  "device.updated",
  "device.deleted",
  "phone_number.created",
  "phone_number.updated",
  "ticket.created",
  "ticket.updated",
  "ticket.closed",
  "user.created",
  "user.updated",
  "voicemail.received",
] as const

const EVENT_CATEGORIES: { label: string; events: string[] }[] = [
  {
    label: "Extensions",
    events: ["extension.created", "extension.updated", "extension.deleted"],
  },
  {
    label: "Devices",
    events: ["device.created", "device.updated", "device.deleted"],
  },
  {
    label: "Phone Numbers",
    events: ["phone_number.created", "phone_number.updated"],
  },
  {
    label: "Tickets",
    events: ["ticket.created", "ticket.updated", "ticket.closed"],
  },
  {
    label: "Users",
    events: ["user.created", "user.updated"],
  },
  {
    label: "Voicemail",
    events: ["voicemail.received"],
  },
]

// -- Helpers ------------------------------------------------------------------

function statusCodeBadge(code: number | null | undefined): React.ReactNode {
  if (code == null) {
    return (
      <Badge variant="outline" className="text-muted-foreground">
        --
      </Badge>
    )
  }
  if (code >= 200 && code < 300) {
    return <Badge className="bg-emerald-100 text-emerald-700 hover:bg-emerald-100 dark:bg-emerald-900/30 dark:text-emerald-400">{code}</Badge>
  }
  if (code >= 300 && code < 400) {
    return <Badge className="bg-amber-100 text-amber-700 hover:bg-amber-100 dark:bg-amber-900/30 dark:text-amber-400">{code}</Badge>
  }
  return <Badge className="bg-red-100 text-red-700 hover:bg-red-100 dark:bg-red-900/30 dark:text-red-400">{code}</Badge>
}

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
          <p className="cursor-default text-sm">{formatRelativeTimeShort(value)}</p>
        </TooltipTrigger>
        <TooltipContent>{formatDateTime(value)}</TooltipContent>
      </Tooltip>
    </div>
  )
}

// -- Main page ----------------------------------------------------------------

function WebhookDetailPage() {
  const { webhookId } = Route.useParams()
  const router = useRouter()
  const { data, isLoading, isError, refetch } = useWebhook(webhookId)
  const deliveriesQuery = useWebhookDeliveries(webhookId)
  const updateWebhook = useUpdateWebhook(webhookId)
  const deleteWebhook = useDeleteWebhook()
  const testWebhookMutation = useTestWebhook()

  useDocumentTitle(data?.name ? `${data.name} - Webhook` : "Webhook Details")

  const [deleteOpen, setDeleteOpen] = useState(false)
  const [showSecret, setShowSecret] = useState(false)

  // -- Inline editing state ---------------------------------------------------

  const [editing, setEditing] = useState(false)
  const [editName, setEditName] = useState("")
  const [editUrl, setEditUrl] = useState("")
  const [editDescription, setEditDescription] = useState("")
  const [editActive, setEditActive] = useState(true)
  const [editEvents, setEditEvents] = useState<string[]>([])
  const justSavedRef = useRef(false)

  const formDirty = useMemo(() => {
    if (!editing || !data) return false
    return (
      editName !== data.name ||
      editUrl !== data.url ||
      editDescription !== (data.description ?? "") ||
      editActive !== data.isActive ||
      JSON.stringify([...editEvents].sort()) !== JSON.stringify([...data.events].sort())
    )
  }, [editing, data, editName, editUrl, editDescription, editActive, editEvents])

  const blocker = useBlocker({
    shouldBlockFn: () => formDirty && !justSavedRef.current,
    withResolver: true,
  })

  const handleStartEditing = useCallback(() => {
    if (!data) return
    setEditName(data.name)
    setEditUrl(data.url)
    setEditDescription(data.description ?? "")
    setEditActive(data.isActive)
    setEditEvents([...data.events])
    setEditing(true)
  }, [data])

  const handleCancelEditing = useCallback(() => {
    setEditing(false)
  }, [])

  const handleSaveEditing = useCallback(() => {
    if (!data) return
    justSavedRef.current = true
    const payload: Record<string, unknown> = {}
    if (editName !== data.name) payload.name = editName
    if (editUrl !== data.url) payload.url = editUrl
    if (editDescription !== (data.description ?? "")) payload.description = editDescription || undefined
    if (editActive !== data.isActive) payload.isActive = editActive
    if (JSON.stringify([...editEvents].sort()) !== JSON.stringify([...data.events].sort())) {
      payload.events = editEvents
    }
    if (Object.keys(payload).length === 0) {
      setEditing(false)
      justSavedRef.current = false
      return
    }
    updateWebhook.mutate(payload as Parameters<typeof updateWebhook.mutate>[0], {
      onSuccess: () => {
        setEditing(false)
      },
      onSettled: () => {
        justSavedRef.current = false
      },
    })
  }, [data, editName, editUrl, editDescription, editActive, editEvents, updateWebhook])

  const toggleEvent = useCallback((event: string) => {
    setEditEvents((prev) => (prev.includes(event) ? prev.filter((e) => e !== event) : [...prev, event]))
  }, [])

  const selectAllEvents = useCallback(() => {
    setEditEvents([...AVAILABLE_EVENTS])
  }, [])

  const clearAllEvents = useCallback(() => {
    setEditEvents([])
  }, [])

  // -- Loading state ----------------------------------------------------------

  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <div className="space-y-2">
          <Skeleton className="h-4 w-32" />
          <Skeleton className="h-8 w-56" />
          <Skeleton className="h-4 w-40" />
        </div>
        <PageSection>
          <div className="space-y-6">
            <div className="rounded-xl border border-border/60 bg-card/80 p-6 space-y-4">
              <div className="flex items-center gap-2">
                <Skeleton className="h-5 w-5 rounded" />
                <Skeleton className="h-6 w-32" />
              </div>
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                {Array.from({ length: 6 }).map((_, i) => (
                  <div key={i} className="space-y-1.5">
                    <Skeleton className="h-3.5 w-20" />
                    <Skeleton className="h-5 w-32" />
                  </div>
                ))}
              </div>
            </div>
            <div className="rounded-xl border border-border/60 bg-card/80 p-6 space-y-4">
              <div className="flex items-center gap-2">
                <Skeleton className="h-5 w-5 rounded" />
                <Skeleton className="h-6 w-24" />
              </div>
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                {Array.from({ length: 4 }).map((_, i) => (
                  <div key={i} className="space-y-1.5">
                    <Skeleton className="h-3.5 w-20" />
                    <Skeleton className="h-5 w-40" />
                  </div>
                ))}
              </div>
            </div>
            <div className="rounded-xl border border-border/60 bg-card/80 p-6 space-y-4">
              <div className="flex items-center gap-2">
                <Skeleton className="h-5 w-5 rounded" />
                <Skeleton className="h-6 w-36" />
              </div>
              <div className="space-y-2">
                {Array.from({ length: 5 }).map((_, i) => (
                  <Skeleton key={i} className="h-10 w-full rounded-md" />
                ))}
              </div>
            </div>
          </div>
        </PageSection>
      </PageContainer>
    )
  }

  // -- Error state ------------------------------------------------------------

  if (isError || !data) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader
          eyebrow="Webhooks"
          title="Webhook Details"
          actions={
            <Button variant="outline" size="sm" asChild>
              <Link to="/webhooks">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back to webhooks
              </Link>
            </Button>
          }
        />
        <PageSection>
          <EmptyState
            icon={AlertCircle}
            title="Unable to load webhook"
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

  // -- Handlers ---------------------------------------------------------------

  const handleDelete = async () => {
    await deleteWebhook.mutateAsync(webhookId)
    router.navigate({ to: "/webhooks" })
  }

  const handleToggleActive = () => {
    updateWebhook.mutate({ isActive: !data.isActive })
  }

  const handleTest = () => {
    testWebhookMutation.mutate(webhookId)
  }

  const headers = data.headers ?? {}
  const headerEntries = Object.entries(headers)
  const deliveries = deliveriesQuery.data ?? []

  // -- Render -----------------------------------------------------------------

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Webhooks"
        title={data.name}
        description={data.description || undefined}
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
                  <Link to="/webhooks">Webhooks</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbPage>{data.name}</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
        actions={
          <div className="flex items-center gap-3">
            {(editing ? editActive : data.isActive) ? (
              <Badge className="gap-1 bg-emerald-100 text-emerald-700 hover:bg-emerald-100 dark:bg-emerald-900/30 dark:text-emerald-400">
                <Check className="h-3 w-3" />
                Active
              </Badge>
            ) : (
              <Badge variant="outline" className="gap-1 text-muted-foreground">
                <XCircle className="h-3 w-3" />
                Inactive
              </Badge>
            )}
            {editing ? (
              <>
                <Button size="sm" variant="outline" onClick={handleCancelEditing} disabled={updateWebhook.isPending}>
                  <X className="mr-2 h-4 w-4" /> Cancel
                </Button>
                <Button size="sm" onClick={handleSaveEditing} disabled={updateWebhook.isPending}>
                  {updateWebhook.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Save className="mr-2 h-4 w-4" />}
                  {updateWebhook.isPending ? "Saving..." : "Save changes"}
                </Button>
              </>
            ) : (
              <>
                <Button size="sm" onClick={handleStartEditing}>
                  <Pencil className="mr-2 h-4 w-4" /> Edit
                </Button>
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="outline" size="sm">
                      <MoreHorizontal className="h-4 w-4" />
                      <span className="sr-only">Actions</span>
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    <DropdownMenuItem onClick={handleStartEditing}>
                      <Pencil className="mr-2 h-4 w-4" />
                      Edit
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => navigator.clipboard.writeText(webhookId)}>
                      <Copy className="mr-2 h-4 w-4" />
                      Copy Webhook ID
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={handleTest} disabled={testWebhookMutation.isPending}>
                      {testWebhookMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Play className="mr-2 h-4 w-4" />}
                      Send Test
                    </DropdownMenuItem>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem className="text-destructive focus:text-destructive" onClick={() => setDeleteOpen(true)}>
                      <Trash2 className="mr-2 h-4 w-4" />
                      Delete Webhook
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              </>
            )}
          </div>
        }
      />

      {/* Webhook Info */}
      <PageSection>
        <SectionErrorBoundary name="Webhook Info">
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <Globe className="h-5 w-5 text-muted-foreground" />
                <CardTitle>Webhook Info</CardTitle>
              </div>
            </CardHeader>
            <CardContent>
              {editing && formDirty && (
                <div className="mb-4 flex items-center gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm text-amber-700 dark:text-amber-400">
                  <span className="inline-block h-1.5 w-1.5 rounded-full bg-amber-500" />
                  You have unsaved changes
                </div>
              )}

              <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-3">
                {/* Name */}
                <div>
                  <p className="text-muted-foreground">Name</p>
                  {editing ? (
                    <Input value={editName} onChange={(e) => setEditName(e.target.value)} placeholder="Webhook name" className="mt-1" disabled={updateWebhook.isPending} />
                  ) : (
                    <p className="font-medium">{data.name}</p>
                  )}
                </div>

                {/* URL */}
                <div className="md:col-span-2 lg:col-span-2">
                  <p className="text-muted-foreground">URL</p>
                  {editing ? (
                    <Input
                      type="url"
                      value={editUrl}
                      onChange={(e) => setEditUrl(e.target.value)}
                      placeholder="https://example.com/webhook"
                      className="mt-1 font-mono text-xs"
                      disabled={updateWebhook.isPending}
                    />
                  ) : (
                    <div className="flex items-center gap-1">
                      <p className="font-mono text-xs break-all">{data.url}</p>
                      <CopyButton value={data.url} label="URL" />
                    </div>
                  )}
                </div>

                {/* Description */}
                <div className="md:col-span-2 lg:col-span-3">
                  <p className="text-muted-foreground">Description</p>
                  {editing ? (
                    <Textarea
                      value={editDescription}
                      onChange={(e) => setEditDescription(e.target.value)}
                      placeholder="What is this webhook used for?"
                      className="mt-1 resize-none"
                      rows={2}
                      disabled={updateWebhook.isPending}
                    />
                  ) : (
                    <p>{data.description || <span className="text-muted-foreground italic">Not set</span>}</p>
                  )}
                </div>

                {/* Status / Active toggle */}
                <div>
                  <p className="text-muted-foreground">Status</p>
                  {editing ? (
                    <div className="mt-1 flex items-center gap-3">
                      <Switch
                        id="webhook-active-toggle"
                        checked={editActive}
                        onCheckedChange={setEditActive}
                        disabled={updateWebhook.isPending}
                        aria-label={editActive ? "Disable webhook" : "Enable webhook"}
                      />
                      <Label htmlFor="webhook-active-toggle" className="cursor-pointer">
                        {editActive ? "Active" : "Inactive"}
                      </Label>
                    </div>
                  ) : (
                    <div className="mt-1 flex items-center gap-3">
                      <Switch
                        id="webhook-active-toggle"
                        checked={data.isActive}
                        onCheckedChange={handleToggleActive}
                        disabled={updateWebhook.isPending}
                        aria-label={data.isActive ? "Disable webhook" : "Enable webhook"}
                      />
                      <Label htmlFor="webhook-active-toggle" className="cursor-pointer">
                        {data.isActive ? "Active" : "Inactive"}
                      </Label>
                      {updateWebhook.isPending && !editing && <Loader2 className="h-3.5 w-3.5 animate-spin text-muted-foreground" />}
                    </div>
                  )}
                </div>

                {/* Events */}
                <div className="md:col-span-2 lg:col-span-2">
                  <p className="text-muted-foreground">Events</p>
                  {editing ? (
                    <div className="mt-1 space-y-2">
                      <div className="flex items-center gap-2">
                        <Button type="button" variant="ghost" size="sm" className="h-6 px-2 text-xs" onClick={selectAllEvents}>
                          Select all
                        </Button>
                        <Button type="button" variant="ghost" size="sm" className="h-6 px-2 text-xs" onClick={clearAllEvents} disabled={editEvents.length === 0}>
                          Clear
                        </Button>
                      </div>
                      <p className="text-xs text-muted-foreground">Select which events should trigger this webhook. If none are selected, all events will be sent.</p>
                      <div className="space-y-3 rounded-md border p-4">
                        {EVENT_CATEGORIES.map((category) => (
                          <div key={category.label}>
                            <p className="mb-1.5 text-xs font-medium text-muted-foreground uppercase tracking-wider">{category.label}</p>
                            <div className="grid grid-cols-2 gap-1.5">
                              {category.events.map((event) => (
                                <label key={event} className="flex items-center gap-2 cursor-pointer text-sm hover:bg-muted/50 rounded px-2 py-1">
                                  <input
                                    type="checkbox"
                                    checked={editEvents.includes(event)}
                                    onChange={() => toggleEvent(event)}
                                    className="rounded border-input"
                                    disabled={updateWebhook.isPending}
                                  />
                                  <span className="text-xs font-mono">{event}</span>
                                </label>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                      {editEvents.length > 0 && (
                        <p className="text-xs text-muted-foreground">
                          {editEvents.length} event{editEvents.length === 1 ? "" : "s"} selected
                        </p>
                      )}
                    </div>
                  ) : (
                    <div className="mt-1 flex flex-wrap gap-1.5">
                      {data.events.length > 0 ? (
                        data.events.map((event) => (
                          <Badge key={event} variant="secondary" className="font-mono text-xs">
                            {event}
                          </Badge>
                        ))
                      ) : (
                        <span className="text-muted-foreground text-sm">All events</span>
                      )}
                    </div>
                  )}
                </div>
              </div>

              {/* Headers */}
              {headerEntries.length > 0 && (
                <div className="mt-6">
                  <p className="text-muted-foreground text-sm mb-2">Custom Headers</p>
                  <div className="rounded-md border">
                    <div className="grid grid-cols-[minmax(120px,1fr)_2fr] text-sm">
                      {headerEntries.map(([key, value], idx) => (
                        <div key={key} className="contents">
                          <div className={`px-3 py-2 font-mono text-xs text-muted-foreground ${idx !== headerEntries.length - 1 ? "border-b" : ""}`}>{key}</div>
                          <div className={`border-l px-3 py-2 font-mono text-xs ${idx !== headerEntries.length - 1 ? "border-b" : ""}`}>{value}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* Secret */}
              {data.secret != null && (
                <div className="mt-6">
                  <p className="text-muted-foreground text-sm mb-1">Signing Secret</p>
                  <div className="flex items-center gap-2">
                    <code className="rounded bg-muted px-2 py-1 font-mono text-xs">{showSecret ? data.secret : "•".repeat(24)}</code>
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7"
                      onClick={() => setShowSecret(!showSecret)}
                      aria-label={showSecret ? "Hide secret" : "Reveal secret"}
                    >
                      {showSecret ? <EyeOff className="h-3.5 w-3.5 text-muted-foreground" /> : <Eye className="h-3.5 w-3.5 text-muted-foreground" />}
                    </Button>
                    {data.secret && <CopyButton value={data.secret} label="secret" />}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </SectionErrorBoundary>
      </PageSection>

      {/* Metadata */}
      <PageSection delay={0.1}>
        <SectionErrorBoundary name="Metadata">
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <Fingerprint className="h-5 w-5 text-muted-foreground" />
                <CardTitle>Metadata</CardTitle>
              </div>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-4">
                <div>
                  <p className="text-muted-foreground text-sm">Webhook ID</p>
                  <div className="flex items-center gap-1">
                    <p className="font-mono text-xs">{webhookId}</p>
                    <CopyButton value={webhookId} label="webhook ID" />
                  </div>
                </div>
                <TimestampField label="Created" value={data.createdAt} />
                <TimestampField label="Updated" value={data.updatedAt} />
                <TimestampField label="Last Triggered" value={data.lastTriggeredAt} />
                <div>
                  <p className="text-muted-foreground text-sm">Failure Count</p>
                  <p className="text-sm">
                    {(data.failureCount ?? 0) > 0 ? (
                      <Badge variant="destructive" className="gap-1">
                        {data.failureCount}
                      </Badge>
                    ) : (
                      "0"
                    )}
                  </p>
                </div>
                <div>
                  <p className="text-muted-foreground text-sm">Last Status Code</p>
                  <div className="mt-0.5">{statusCodeBadge(data.lastStatusCode)}</div>
                </div>
              </div>
            </CardContent>
          </Card>
        </SectionErrorBoundary>
      </PageSection>

      {/* Delivery Log */}
      <PageSection delay={0.15}>
        <SectionErrorBoundary name="Delivery Log">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <div className="flex items-center gap-2">
                <Activity className="h-5 w-5 text-muted-foreground" />
                <CardTitle>Delivery Log</CardTitle>
              </div>
              <Button variant="outline" size="sm" onClick={() => deliveriesQuery.refetch()} disabled={deliveriesQuery.isRefetching}>
                {deliveriesQuery.isRefetching ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Activity className="mr-2 h-4 w-4" />}
                Refresh
              </Button>
            </CardHeader>
            <CardContent>
              {deliveriesQuery.isLoading ? (
                <div className="space-y-2">
                  {Array.from({ length: 5 }).map((_, i) => (
                    <Skeleton key={i} className="h-10 w-full rounded-md" />
                  ))}
                </div>
              ) : deliveriesQuery.isError ? (
                <EmptyState
                  icon={AlertCircle}
                  title="Failed to load delivery history"
                  description="Something went wrong. Please try again."
                  action={
                    <Button variant="outline" size="sm" onClick={() => deliveriesQuery.refetch()}>
                      Try again
                    </Button>
                  }
                />
              ) : deliveries.length === 0 ? (
                <EmptyState icon={Activity} title="No deliveries yet" description="No delivery attempts have been recorded. Use the Send Test action to send a test payload." />
              ) : (
                <div className="overflow-x-auto rounded-md border border-border/60">
                  <Table aria-label="Webhook deliveries">
                    <TableHeader className="sticky top-0 z-10 bg-background">
                      <TableRow>
                        <TableHead>Event</TableHead>
                        <TableHead>Result</TableHead>
                        <TableHead>HTTP Status</TableHead>
                        <TableHead>Response Time</TableHead>
                        <TableHead>Timestamp</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {deliveries.map((delivery: WebhookDelivery) => (
                        <TableRow key={delivery.id} className="hover:bg-muted/50 transition-colors">
                          <TableCell>
                            <span className="text-sm font-mono">{delivery.event}</span>
                          </TableCell>
                          <TableCell>
                            {delivery.success ? (
                              <Badge className="gap-1 bg-emerald-100 text-emerald-700 hover:bg-emerald-100 dark:bg-emerald-900/30 dark:text-emerald-400">
                                <Check className="h-3 w-3" />
                                Success
                              </Badge>
                            ) : (
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <Badge variant="destructive" className="gap-1 cursor-default">
                                    <XCircle className="h-3 w-3" />
                                    Failed
                                  </Badge>
                                </TooltipTrigger>
                                {delivery.error && <TooltipContent className="max-w-xs">{delivery.error}</TooltipContent>}
                              </Tooltip>
                            )}
                          </TableCell>
                          <TableCell>{statusCodeBadge(delivery.statusCode)}</TableCell>
                          <TableCell>
                            <span className="text-sm text-muted-foreground">{delivery.responseTimeMs}ms</span>
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center gap-1.5">
                              <Clock className="h-3 w-3 text-muted-foreground" />
                              <span className="text-sm text-muted-foreground">{formatDateTime(delivery.createdAt, "--")}</span>
                            </div>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </CardContent>
          </Card>
        </SectionErrorBoundary>
      </PageSection>

      {/* Activity */}
      <PageSection delay={0.2}>
        <SectionErrorBoundary name="Activity">
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <Clock className="h-5 w-5 text-muted-foreground" />
                <CardTitle>Activity</CardTitle>
              </div>
            </CardHeader>
            <CardContent>
              <EntityActivityPanel targetType="webhook" targetId={webhookId} />
            </CardContent>
          </Card>
        </SectionErrorBoundary>
      </PageSection>

      {/* Danger Zone */}
      <PageSection delay={0.25}>
        <SectionErrorBoundary name="Danger Zone">
          <Card className="border-destructive/30">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-destructive">
                <AlertTriangle className="h-4 w-4" />
                Danger Zone
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium text-sm">Delete this webhook</p>
                  <p className="text-sm text-muted-foreground">This action cannot be undone. All delivery history and configuration will be permanently removed.</p>
                </div>
                <Button variant="destructive" size="sm" onClick={() => setDeleteOpen(true)}>
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
              Delete webhook?
            </AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete <strong>{data.name}</strong> and all associated delivery history. This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setDeleteOpen(false)} disabled={deleteWebhook.isPending}>
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              className={buttonVariants({ variant: "destructive" })}
              onClick={() => {
                handleDelete()
                setDeleteOpen(false)
              }}
              disabled={deleteWebhook.isPending}
            >
              {deleteWebhook.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Unsaved changes dialog */}
      <AlertDialog open={blocker.status === "blocked"} onOpenChange={() => blocker.reset?.()}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Unsaved changes</AlertDialogTitle>
            <AlertDialogDescription>You have unsaved changes to this webhook. Are you sure you want to leave? Your changes will be lost.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => blocker.reset?.()}>Stay on page</AlertDialogCancel>
            <AlertDialogAction onClick={() => blocker.proceed?.()}>Discard changes</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </PageContainer>
  )
}
