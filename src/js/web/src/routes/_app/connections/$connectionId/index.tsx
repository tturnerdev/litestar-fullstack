import { createFileRoute, Link, useBlocker, useRouter } from "@tanstack/react-router"
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  ArrowLeft,
  Check,
  CheckCircle2,
  Circle,
  Copy,
  Cpu,
  Globe,
  Headphones,
  Key,
  Loader2,
  Lock,
  MoreHorizontal,
  Network,
  Pencil,
  Phone,
  Plug,
  Server,
  Settings,
  ShieldCheck,
  Trash2,
  Wifi,
  X,
  XCircle,
} from "lucide-react"
import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { toast } from "sonner"
import { DeviceStatusBadge } from "@/components/devices/device-status-badge"
import { EntityActivityPanel } from "@/components/shared/entity-activity-panel"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
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
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { useConnection, useDeleteConnection, useTestConnection, useUpdateConnection } from "@/lib/api/hooks/connections"
import { useDevices } from "@/lib/api/hooks/devices"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"

export const Route = createFileRoute("/_app/connections/$connectionId/")({
  component: ConnectionDetailPage,
  validateSearch: (search: Record<string, unknown>): { tab?: string } => ({
    tab: (search.tab as string) || undefined,
  }),
})

// ── Label maps ──────────────────────────────────────────────────────────

const typeLabels: Record<string, string> = {
  pbx: "PBX",
  helpdesk: "Helpdesk",
  carrier: "Carrier",
  network: "Network",
  other: "Other",
}

const authTypeLabels: Record<string, string> = {
  api_key: "API Key",
  basic: "Basic Auth",
  oauth2: "OAuth 2.0",
  token: "Token",
  none: "None",
}

const deviceTypeLabels: Record<string, string> = {
  desk_phone: "Desk Phone",
  softphone: "Softphone",
  ata: "ATA",
  conference: "Conference",
  gateway: "Gateway",
  other: "Other",
}

// ── Provider display helpers ───────────────────────────────────────────

const providerIcons: Record<string, typeof Plug> = {
  freepbx: Phone,
  telnyx: Globe,
  unifi: Wifi,
}

const providerLabels: Record<string, string> = {
  freepbx: "FreePBX",
  telnyx: "Telnyx",
  unifi: "Unifi Network",
}

const connectionTypeIcons: Record<string, typeof Plug> = {
  pbx: Phone,
  helpdesk: Headphones,
  carrier: Globe,
  network: Network,
  other: Plug,
}

// ── Health status helpers ──────────────────────────────────────────────

type HealthLevel = "healthy" | "degraded" | "error" | "unknown"

function deriveHealthLevel(status: string, lastError: string | null | undefined, isEnabled: boolean): HealthLevel {
  if (!isEnabled) return "unknown"
  if (status === "error" || lastError) return "error"
  if (status === "connected") return "healthy"
  if (status === "disconnected") return "degraded"
  return "unknown"
}

const healthConfig: Record<HealthLevel, { label: string; dotClass: string; bgClass: string; textClass: string }> = {
  healthy: {
    label: "Healthy",
    dotClass: "bg-emerald-500",
    bgClass: "bg-emerald-50 dark:bg-emerald-950/30",
    textClass: "text-emerald-700 dark:text-emerald-400",
  },
  degraded: {
    label: "Degraded",
    dotClass: "bg-yellow-500",
    bgClass: "bg-yellow-50 dark:bg-yellow-950/30",
    textClass: "text-yellow-700 dark:text-yellow-400",
  },
  error: {
    label: "Error",
    dotClass: "bg-red-500",
    bgClass: "bg-red-50 dark:bg-red-950/30",
    textClass: "text-red-700 dark:text-red-400",
  },
  unknown: {
    label: "Unknown",
    dotClass: "bg-gray-400",
    bgClass: "bg-gray-50 dark:bg-gray-900/30",
    textClass: "text-muted-foreground",
  },
}

// ── Status badge ────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  switch (status) {
    case "connected":
      return (
        <Badge className="gap-1 bg-emerald-100 text-emerald-700 hover:bg-emerald-100 dark:bg-emerald-900/30 dark:text-emerald-400">
          <CheckCircle2 className="h-3 w-3" />
          Connected
        </Badge>
      )
    case "disconnected":
      return (
        <Badge variant="outline" className="gap-1">
          <XCircle className="h-3 w-3" />
          Disconnected
        </Badge>
      )
    case "error":
      return (
        <Badge variant="destructive" className="gap-1">
          <AlertCircle className="h-3 w-3" />
          Error
        </Badge>
      )
    default:
      return (
        <Badge variant="outline" className="gap-1 text-muted-foreground">
          <Circle className="h-3 w-3" />
          Unknown
        </Badge>
      )
  }
}

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
          <p className="cursor-default text-sm">{formatRelativeTimeShort(value)}</p>
        </TooltipTrigger>
        <TooltipContent>{formatDateTime(value)}</TooltipContent>
      </Tooltip>
    </div>
  )
}

// ── Main page ───────────────────────────────────────────────────────────

function ConnectionDetailPage() {
  const { connectionId } = Route.useParams()
  const { tab = "overview" } = Route.useSearch()
  const navigate = Route.useNavigate()
  const router = useRouter()
  const { data, isLoading, isError, refetch } = useConnection(connectionId)
  useDocumentTitle(data?.name ? `${data.name} - Connection` : "Connection")
  const deleteConnection = useDeleteConnection()
  const testConnection = useTestConnection(connectionId)
  const updateConnection = useUpdateConnection(connectionId)
  const devicesQuery = useDevices({ pageSize: 200 })
  const managedDevices = (devicesQuery.data?.items ?? []).filter((d) => d.connectionId === connectionId)

  const [deleteOpen, setDeleteOpen] = useState(false)
  const [settingsText, setSettingsText] = useState<string | null>(null)
  const [settingsError, setSettingsError] = useState<string | null>(null)
  const [settingsDirty, setSettingsDirty] = useState(false)

  // ── Inline editing state ───────────────────────────────────────────────
  const [editing, setEditing] = useState(false)
  const [editValues, setEditValues] = useState({
    name: "",
    description: "",
    host: "",
    port: "",
    isEnabled: true,
  })
  const justSavedRef = useRef(false)

  // Populate edit values when entering edit mode or when data changes
  useEffect(() => {
    if (data && editing) {
      setEditValues({
        name: data.name,
        description: data.description ?? "",
        host: data.host ?? "",
        port: data.port != null ? String(data.port) : "",
        isEnabled: data.isEnabled,
      })
    }
  }, [data, editing])

  const editDirty = useMemo(() => {
    if (!data || !editing) return false
    return (
      editValues.name !== data.name ||
      editValues.description !== (data.description ?? "") ||
      editValues.host !== (data.host ?? "") ||
      editValues.port !== (data.port != null ? String(data.port) : "") ||
      editValues.isEnabled !== data.isEnabled
    )
  }, [editValues, data, editing])

  useBlocker({
    shouldBlockFn: () => editDirty && !justSavedRef.current,
    withResolver: true,
  })

  const handleStartEditing = useCallback(() => {
    if (!data) return
    setEditValues({
      name: data.name,
      description: data.description ?? "",
      host: data.host ?? "",
      port: data.port != null ? String(data.port) : "",
      isEnabled: data.isEnabled,
    })
    setEditing(true)
  }, [data])

  const handleCancelEditing = useCallback(() => {
    setEditing(false)
  }, [])

  const handleSaveEditing = useCallback(() => {
    if (!data) return
    const payload: Record<string, unknown> = {}
    if (editValues.name !== data.name) payload.name = editValues.name
    if (editValues.description !== (data.description ?? "")) {
      payload.description = editValues.description || null
    }
    if (editValues.host !== (data.host ?? "")) {
      payload.host = editValues.host || null
    }
    const newPort = editValues.port.trim() === "" ? null : Number(editValues.port)
    const oldPort = data.port ?? null
    if (newPort !== oldPort) payload.port = newPort
    if (editValues.isEnabled !== data.isEnabled) payload.isEnabled = editValues.isEnabled

    if (Object.keys(payload).length === 0) {
      setEditing(false)
      return
    }

    justSavedRef.current = true
    updateConnection.mutate(payload, {
      onSuccess: () => {
        setEditing(false)
        justSavedRef.current = false
      },
      onError: () => {
        justSavedRef.current = false
      },
    })
  }, [data, editValues, updateConnection])

  const updateEditValue = useCallback(<K extends keyof typeof editValues>(key: K, value: (typeof editValues)[K]) => {
    setEditValues((prev) => ({ ...prev, [key]: value }))
  }, [])

  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        {/* Header skeleton */}
        <div className="space-y-2">
          <Skeleton className="h-4 w-32" />
          <Skeleton className="h-8 w-56" />
          <Skeleton className="h-4 w-44" />
        </div>
        {/* Connection Info card */}
        <PageSection>
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
        </PageSection>
        {/* Server Config card */}
        <PageSection delay={0.1}>
          <div className="rounded-xl border border-border/60 bg-card/80 p-6 space-y-4">
            <div className="flex items-center gap-2">
              <Skeleton className="h-5 w-5 rounded" />
              <Skeleton className="h-6 w-40" />
            </div>
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {Array.from({ length: 3 }).map((_, i) => (
                <div key={i} className="space-y-1.5">
                  <Skeleton className="h-3.5 w-16" />
                  <Skeleton className="h-5 w-28" />
                </div>
              ))}
            </div>
          </div>
        </PageSection>
        {/* Authentication card */}
        <PageSection delay={0.15}>
          <div className="rounded-xl border border-border/60 bg-card/80 p-6 space-y-4">
            <div className="flex items-center gap-2">
              <Skeleton className="h-5 w-5 rounded" />
              <Skeleton className="h-6 w-32" />
            </div>
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              <div className="space-y-1.5">
                <Skeleton className="h-3.5 w-20" />
                <Skeleton className="h-5 w-24" />
              </div>
              <div className="md:col-span-2 lg:col-span-2 space-y-1.5">
                <Skeleton className="h-3.5 w-24" />
                <div className="flex gap-2">
                  <Skeleton className="h-6 w-20 rounded-full" />
                  <Skeleton className="h-6 w-24 rounded-full" />
                </div>
              </div>
            </div>
          </div>
        </PageSection>
        {/* Settings card */}
        <PageSection delay={0.2}>
          <div className="rounded-xl border border-border/60 bg-card/80 p-6 space-y-4">
            <div className="flex items-center gap-2">
              <Skeleton className="h-5 w-5 rounded" />
              <Skeleton className="h-6 w-24" />
            </div>
            <Skeleton className="h-32 w-full rounded-md" />
          </div>
        </PageSection>
      </PageContainer>
    )
  }

  if (isError || !data) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader
          eyebrow="Connections"
          title="Connection Details"
          actions={
            <Button variant="outline" size="sm" asChild>
              <Link to="/connections">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back to connections
              </Link>
            </Button>
          }
        />
        <PageSection>
          <EmptyState
            icon={AlertCircle}
            title="Unable to load connection"
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

  const handleDelete = async () => {
    await deleteConnection.mutateAsync(connectionId)
    router.navigate({ to: "/connections" })
  }

  const currentSettingsText = settingsText ?? (data.settings ? JSON.stringify(data.settings, null, 2) : "")

  const handleSaveSettings = () => {
    const text = currentSettingsText.trim()
    if (text) {
      try {
        const parsed = JSON.parse(text)
        setSettingsError(null)
        updateConnection.mutate({ settings: parsed }, { onSuccess: () => setSettingsDirty(false) })
      } catch {
        setSettingsError("Invalid JSON")
        return
      }
    } else {
      updateConnection.mutate({ settings: null }, { onSuccess: () => setSettingsDirty(false) })
    }
  }

  const settingsEntries = data.settings ? Object.entries(data.settings) : []

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Connections"
        title={data.name}
        description={`${typeLabels[data.connectionType] ?? data.connectionType} · ${data.provider}`}
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
                  <Link to="/connections">Connections</Link>
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
            <StatusBadge status={data.status} />
            {!editing && !data.isEnabled && (
              <Badge variant="outline" className="border-muted-foreground/30 text-muted-foreground">
                Disabled
              </Badge>
            )}
            <Button size="sm" variant="outline" onClick={() => testConnection.mutate()} disabled={testConnection.isPending || editing}>
              {testConnection.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Plug className="mr-2 h-4 w-4" />}
              Test
            </Button>
            {editing ? (
              <>
                <Button variant="ghost" size="sm" onClick={handleCancelEditing} disabled={updateConnection.isPending}>
                  <X className="mr-2 h-4 w-4" /> Cancel
                </Button>
                <Button size="sm" onClick={handleSaveEditing} disabled={!editDirty || updateConnection.isPending}>
                  {updateConnection.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Check className="mr-2 h-4 w-4" />}
                  Save
                </Button>
              </>
            ) : (
              <Button variant="outline" size="sm" onClick={handleStartEditing}>
                <Pencil className="mr-2 h-4 w-4" /> Edit
              </Button>
            )}
            <Button variant="outline" size="sm" asChild>
              <Link to="/connections">
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
                <DropdownMenuItem
                  onClick={() => {
                    navigator.clipboard.writeText(connectionId)
                    toast.success("Connection ID copied to clipboard")
                  }}
                >
                  <Copy className="mr-2 h-4 w-4" />
                  Copy Connection ID
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem className="text-destructive focus:text-destructive" onClick={() => setDeleteOpen(true)}>
                  <Trash2 className="mr-2 h-4 w-4" />
                  Delete Connection
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        }
      />

      {/* Test result inline feedback */}
      {testConnection.isSuccess && (
        <Alert variant="success">
          <CheckCircle2 className="h-4 w-4" />
          <AlertTitle>Connection test passed</AlertTitle>
          <AlertDescription>{testConnection.data.message}</AlertDescription>
        </Alert>
      )}
      {testConnection.isError && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Connection test failed</AlertTitle>
          <AlertDescription>{testConnection.error instanceof Error ? testConnection.error.message : "An unexpected error occurred"}</AlertDescription>
        </Alert>
      )}

      {/* Connection Health */}
      <PageSection>
        {(() => {
          const health = deriveHealthLevel(data.status, data.lastError, data.isEnabled)
          const config = healthConfig[health]
          const ProviderIcon = providerIcons[data.provider.toLowerCase()] ?? connectionTypeIcons[data.connectionType] ?? Plug
          const providerDisplayName = providerLabels[data.provider.toLowerCase()] ?? data.provider

          return (
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Activity className="h-5 w-5 text-muted-foreground" />
                    <CardTitle>Connection Health</CardTitle>
                  </div>
                  <Button size="sm" variant="outline" onClick={() => testConnection.mutate()} disabled={testConnection.isPending || editing}>
                    {testConnection.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Plug className="mr-2 h-4 w-4" />}
                    Test Connection
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
                  {/* Health status indicator */}
                  <div className="space-y-1.5">
                    <p className="text-muted-foreground text-sm">Status</p>
                    <div className={`inline-flex items-center gap-2 rounded-md px-3 py-1.5 ${config.bgClass}`}>
                      <span className={`inline-block h-2.5 w-2.5 rounded-full ${config.dotClass} ${health === "healthy" ? "animate-pulse" : ""}`} />
                      <span className={`text-sm font-medium ${config.textClass}`}>{config.label}</span>
                    </div>
                  </div>

                  {/* Provider badge */}
                  <div className="space-y-1.5">
                    <p className="text-muted-foreground text-sm">Provider</p>
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className="gap-1.5 text-sm">
                        <ProviderIcon className="h-3.5 w-3.5" />
                        {providerDisplayName}
                      </Badge>
                      <Badge variant="secondary" className="text-xs">
                        {typeLabels[data.connectionType] ?? data.connectionType}
                      </Badge>
                    </div>
                  </div>

                  {/* Last health check */}
                  <div className="space-y-1.5">
                    <p className="text-muted-foreground text-sm">Last Health Check</p>
                    {data.lastHealthCheck ? (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <p className="cursor-default text-sm">{formatRelativeTimeShort(data.lastHealthCheck)}</p>
                        </TooltipTrigger>
                        <TooltipContent>{formatDateTime(data.lastHealthCheck)}</TooltipContent>
                      </Tooltip>
                    ) : (
                      <p className="text-sm text-muted-foreground">Never checked</p>
                    )}
                  </div>

                  {/* Enabled / Disabled */}
                  <div className="space-y-1.5">
                    <p className="text-muted-foreground text-sm">Enabled</p>
                    <div className="flex items-center gap-1.5">
                      {data.isEnabled ? (
                        <>
                          <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                          <span className="text-sm">Active</span>
                        </>
                      ) : (
                        <>
                          <XCircle className="h-4 w-4 text-muted-foreground" />
                          <span className="text-sm text-muted-foreground">Disabled</span>
                        </>
                      )}
                    </div>
                  </div>
                </div>

                {/* Last error display */}
                {data.lastError && (
                  <div className="mt-4">
                    <Alert variant="destructive">
                      <AlertCircle className="h-4 w-4" />
                      <AlertTitle>Last Error</AlertTitle>
                      <AlertDescription className="font-mono text-xs">{data.lastError}</AlertDescription>
                    </Alert>
                  </div>
                )}
              </CardContent>
            </Card>
          )
        })()}
      </PageSection>

      <PageSection>
        <Tabs value={tab} onValueChange={(value) => navigate({ search: () => ({ tab: value }), replace: true })}>
          <TabsList>
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="activity">Activity</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="mt-6 space-y-6">
            {/* Connection Info */}
            <Card>
              <CardHeader>
                <div className="flex items-center gap-2">
                  <Globe className="h-5 w-5 text-muted-foreground" />
                  <CardTitle>Connection Info</CardTitle>
                </div>
              </CardHeader>
              <CardContent>
                <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-3">
                  <div>
                    <p className="text-muted-foreground">Name</p>
                    {editing ? (
                      <Input value={editValues.name} onChange={(e) => updateEditValue("name", e.target.value)} className="mt-1 h-8" autoFocus />
                    ) : (
                      <p className="font-medium">{data.name}</p>
                    )}
                  </div>
                  <div>
                    <p className="text-muted-foreground">Type</p>
                    <p>{typeLabels[data.connectionType] ?? data.connectionType}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Provider</p>
                    <p>{data.provider}</p>
                  </div>
                  <div className="md:col-span-2 lg:col-span-3">
                    <p className="text-muted-foreground">Description</p>
                    {editing ? (
                      <Textarea
                        value={editValues.description}
                        onChange={(e) => updateEditValue("description", e.target.value)}
                        className="mt-1"
                        rows={2}
                        placeholder="Optional description"
                      />
                    ) : (
                      <p>{data.description || "---"}</p>
                    )}
                  </div>
                  <div>
                    <p className="text-muted-foreground">Status</p>
                    <div className="mt-0.5">
                      <StatusBadge status={data.status} />
                    </div>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Enabled</p>
                    {editing ? (
                      <div className="mt-1 flex items-center gap-2">
                        <Switch checked={editValues.isEnabled} onCheckedChange={(checked) => updateEditValue("isEnabled", checked)} aria-label="Toggle enabled" />
                        <span className="text-sm">{editValues.isEnabled ? "Yes" : "No"}</span>
                      </div>
                    ) : (
                      <p>{data.isEnabled ? "Yes" : "No"}</p>
                    )}
                  </div>
                  <div>
                    <p className="text-muted-foreground">Connection ID</p>
                    <div className="flex items-center gap-1">
                      <p className="font-mono text-xs">{connectionId}</p>
                      <CopyButton value={connectionId} label="connection ID" />
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Server Configuration */}
            <Card>
              <CardHeader>
                <div className="flex items-center gap-2">
                  <Server className="h-5 w-5 text-muted-foreground" />
                  <CardTitle>Server Configuration</CardTitle>
                </div>
              </CardHeader>
              <CardContent>
                <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-3">
                  <div>
                    <p className="text-muted-foreground">Host</p>
                    {editing ? (
                      <Input
                        value={editValues.host}
                        onChange={(e) => updateEditValue("host", e.target.value)}
                        className="mt-1 h-8 font-mono text-xs"
                        placeholder="e.g. 192.168.1.1 or example.com"
                      />
                    ) : (
                      <div className="flex items-center gap-1">
                        <p className="font-mono text-xs">{data.host || "---"}</p>
                        {data.host && <CopyButton value={data.host} label="host" />}
                      </div>
                    )}
                  </div>
                  <div>
                    <p className="text-muted-foreground">Port</p>
                    {editing ? (
                      <Input
                        type="number"
                        value={editValues.port}
                        onChange={(e) => updateEditValue("port", e.target.value)}
                        className="mt-1 h-8 font-mono text-xs"
                        placeholder="e.g. 443"
                        min={1}
                        max={65535}
                      />
                    ) : (
                      <p className="font-mono text-xs">{data.port != null ? String(data.port) : "---"}</p>
                    )}
                  </div>
                  <div>
                    <p className="text-muted-foreground">SSL / TLS</p>
                    <div className="flex items-center gap-1.5">
                      {(editing ? editValues.port === "443" : data.port === 443) ? (
                        <>
                          <ShieldCheck className="h-3.5 w-3.5 text-emerald-500" />
                          <span>Likely (port 443)</span>
                        </>
                      ) : (
                        <span className="text-muted-foreground">Not determined</span>
                      )}
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Authentication */}
            <Card>
              <CardHeader>
                <div className="flex items-center gap-2">
                  <Key className="h-5 w-5 text-muted-foreground" />
                  <CardTitle>Authentication</CardTitle>
                </div>
              </CardHeader>
              <CardContent>
                <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-3">
                  <div>
                    <p className="text-muted-foreground">Auth Type</p>
                    <p>{authTypeLabels[data.authType] ?? data.authType}</p>
                  </div>
                  {data.credentialFields.length > 0 && (
                    <div className="md:col-span-2 lg:col-span-3">
                      <p className="text-muted-foreground">Credentials</p>
                      <div className="mt-1.5 flex flex-wrap gap-2">
                        {data.credentialFields.map((field) => (
                          <Badge key={field} variant="outline" className="gap-1.5 font-mono text-xs">
                            <Lock className="h-3 w-3 text-muted-foreground" />
                            {field}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Settings */}
            <Card>
              <CardHeader>
                <div className="flex items-center gap-2">
                  <Settings className="h-5 w-5 text-muted-foreground" />
                  <CardTitle>Settings</CardTitle>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Key-value display */}
                {settingsEntries.length > 0 && (
                  <div className="rounded-md border">
                    <div className="grid grid-cols-[minmax(120px,1fr)_2fr] text-sm">
                      {settingsEntries.map(([key, value], idx) => (
                        <div key={key} className="contents">
                          <div className={`px-3 py-2 font-mono text-xs text-muted-foreground ${idx !== settingsEntries.length - 1 ? "border-b" : ""}`}>{key}</div>
                          <div className={`border-l px-3 py-2 font-mono text-xs ${idx !== settingsEntries.length - 1 ? "border-b" : ""}`}>
                            {typeof value === "object" ? JSON.stringify(value) : String(value ?? "---")}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {settingsEntries.length === 0 && !settingsDirty && <p className="text-sm text-muted-foreground">No settings configured.</p>}

                <Separator />

                {/* Raw JSON editor */}
                <div className="space-y-2">
                  <Label htmlFor="settings-json">Configuration JSON</Label>
                  <Textarea
                    id="settings-json"
                    value={currentSettingsText}
                    onChange={(e) => {
                      setSettingsText(e.target.value)
                      setSettingsError(null)
                      setSettingsDirty(true)
                    }}
                    rows={8}
                    className="font-mono text-xs"
                    placeholder='{"key": "value"}'
                  />
                  {settingsError && <p className="text-destructive text-sm">{settingsError}</p>}
                </div>
                <div className="flex items-center justify-end gap-2">
                  <Button
                    variant="ghost"
                    onClick={() => {
                      setSettingsText(null)
                      setSettingsError(null)
                      setSettingsDirty(false)
                    }}
                    disabled={!settingsDirty || updateConnection.isPending}
                  >
                    Reset
                  </Button>
                  <Button onClick={handleSaveSettings} disabled={!settingsDirty || updateConnection.isPending}>
                    {updateConnection.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                    Save Settings
                  </Button>
                </div>
              </CardContent>
            </Card>

            {/* Managed Devices */}
            <Card>
              <CardHeader>
                <div className="flex items-center gap-2">
                  <Cpu className="h-5 w-5 text-muted-foreground" />
                  <CardTitle>Managed Devices</CardTitle>
                </div>
              </CardHeader>
              <CardContent>
                {devicesQuery.isLoading ? (
                  <div className="space-y-2">
                    {Array.from({ length: 3 }).map((_, i) => (
                      <Skeleton key={i} className="h-8 w-full" />
                    ))}
                  </div>
                ) : managedDevices.length === 0 ? (
                  <EmptyState icon={Cpu} title="No devices managed by this connection" description="Devices linked to this connection will appear here." />
                ) : (
                  <Table aria-label="Connection devices">
                    <TableHeader>
                      <TableRow>
                        <TableHead>Name</TableHead>
                        <TableHead>Type</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>IP Address</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {managedDevices.map((device) => (
                        <TableRow key={device.id}>
                          <TableCell>
                            <Link to="/devices/$deviceId" params={{ deviceId: device.id }} className="font-medium text-primary hover:underline">
                              {device.name}
                            </Link>
                          </TableCell>
                          <TableCell>{deviceTypeLabels[device.deviceType] ?? device.deviceType}</TableCell>
                          <TableCell>
                            <DeviceStatusBadge status={device.status} />
                          </TableCell>
                          <TableCell className="font-mono text-xs">{device.ipAddress || "---"}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </CardContent>
            </Card>

            {/* Metadata */}
            <Card>
              <CardHeader>
                <CardTitle>Metadata</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-4">
                  <TimestampField label="Created" value={data.createdAt} />
                  <TimestampField label="Updated" value={data.updatedAt} />
                  <TimestampField label="Last Health Check" value={data.lastHealthCheck} />
                  <div>
                    <p className="text-muted-foreground text-sm">Team</p>
                    <div className="flex items-center gap-1">
                      <Link to="/teams/$teamId" params={{ teamId: data.teamId }} className="font-mono text-xs text-primary hover:underline">
                        {data.teamId.slice(0, 8)}...
                      </Link>
                      <CopyButton value={data.teamId} label="team ID" />
                    </div>
                  </div>
                </div>
                {data.lastError && (
                  <div className="mt-4">
                    <Alert variant="destructive">
                      <AlertCircle className="h-4 w-4" />
                      <AlertTitle>Last Error</AlertTitle>
                      <AlertDescription className="font-mono text-xs">{data.lastError}</AlertDescription>
                    </Alert>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="activity" className="mt-6">
            <Card>
              <CardHeader>
                <CardTitle>Activity Log</CardTitle>
              </CardHeader>
              <CardContent>
                <EntityActivityPanel targetType="connection" targetId={connectionId} enabled={tab === "activity"} />
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
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
                <p className="font-medium text-sm">Delete this connection</p>
                <p className="text-sm text-muted-foreground">This action cannot be undone. All configuration and credentials will be permanently removed.</p>
              </div>
              <Button variant="destructive" size="sm" onClick={() => setDeleteOpen(true)}>
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
              Delete connection?
            </AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete <strong>{data.name}</strong> and all associated configuration. This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setDeleteOpen(false)} disabled={deleteConnection.isPending}>
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              className={buttonVariants({ variant: "destructive" })}
              onClick={() => {
                handleDelete()
                setDeleteOpen(false)
              }}
              disabled={deleteConnection.isPending}
            >
              {deleteConnection.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </PageContainer>
  )
}
