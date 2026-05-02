import { createFileRoute, Link, useRouter } from "@tanstack/react-router"
import { useEffect, useState } from "react"
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  ArrowLeft,
  ClipboardList,
  Cpu,
  Eye,
  EyeOff,
  Fingerprint,
  Loader2,
  MapPin,
  Network,
  Pencil,
  Phone,
  Settings,
  Shield,
  Wrench,
} from "lucide-react"
import { EntityActivityPanel } from "@/components/shared/entity-activity-panel"
import { TaskStatusBadge } from "@/components/tasks/task-status-badge"
import { RebootButton, ReprovisionButton, ToggleActiveButton, DeleteButton } from "@/components/devices/device-actions"
import { DeviceLineConfig } from "@/components/devices/device-line-config"
import { DeviceStatusBadge } from "@/components/devices/device-status-badge"
import { Badge } from "@/components/ui/badge"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { CopyButton } from "@/components/ui/copy-button"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"
import {
  useDeleteDevice,
  useDevice,
  useDeviceLines,
  useRebootDevice,
  useReprovisionDevice,
  useUpdateDevice,
} from "@/lib/api/hooks/devices"
import { useConnections } from "@/lib/api/hooks/connections"
import { useTasks } from "@/lib/api/hooks/tasks"
import { useGatewayLookupDevice } from "@/lib/api/hooks/gateway"
import { useLocations } from "@/lib/api/hooks/locations"
import { useAuthStore } from "@/lib/auth"
import { ExternalDataTab } from "@/components/gateway/external-data-tab"
import { DeviceDiagnosticTab } from "@/components/devices/device-diagnostic-tab"
import type { Device } from "@/lib/generated/api"

export const Route = createFileRoute("/_app/devices/$deviceId/")({
  component: DeviceDetailPage,
  validateSearch: (search: Record<string, unknown>): { tab?: string; edit?: boolean } => ({
    tab: (search.tab as string) || undefined,
    edit: search.edit === true || search.edit === "true" || undefined,
  }),
})

// ── Label maps ──────────────────────────────────────────────────────────

const deviceTypeLabels: Record<string, string> = {
  desk_phone: "Desk Phone",
  softphone: "Softphone",
  ata: "ATA",
  conference: "Conference",
  other: "Other",
}

// ── Task helpers ───────────────────────────────────────────────────────

function formatTaskType(taskType: string): string {
  return taskType
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase())
}

function formatDuration(startedAt: string | null | undefined, completedAt: string | null | undefined): string {
  if (!startedAt) return "--"
  const start = new Date(startedAt).getTime()
  const end = completedAt ? new Date(completedAt).getTime() : Date.now()
  const seconds = Math.max(0, Math.round((end - start) / 1000))
  if (seconds < 60) return `${seconds}s`
  const minutes = Math.floor(seconds / 60)
  const remainingSeconds = seconds % 60
  if (minutes < 60) return `${minutes}m ${remainingSeconds}s`
  const hours = Math.floor(minutes / 60)
  const remainingMinutes = minutes % 60
  return `${hours}h ${remainingMinutes}m`
}

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
          <p className="cursor-default text-sm">{formatRelativeTimeShort(value)}</p>
        </TooltipTrigger>
        <TooltipContent>{formatDateTime(value)}</TooltipContent>
      </Tooltip>
    </div>
  )
}

// ── Main page ───────────────────────────────────────────────────────────

function DeviceDetailPage() {
  const { deviceId } = Route.useParams()
  const { tab = "overview", edit: editParam } = Route.useSearch()
  const navigate = Route.useNavigate()
  const router = useRouter()
  const { currentTeam } = useAuthStore()
  const teamId = currentTeam?.id ?? ""
  const { data, isLoading, isError, refetch } = useDevice(deviceId)
  useDocumentTitle(data?.name ?? "Device Details")
  const updateDevice = useUpdateDevice(deviceId)
  const deleteDevice = useDeleteDevice()
  const rebootDevice = useRebootDevice(deviceId)
  const reprovisionDevice = useReprovisionDevice(deviceId)
  const linesQuery = useDeviceLines(deviceId)
  const gatewayQuery = useGatewayLookupDevice(data?.macAddress ?? "", tab === "external")
  const locationsQuery = useLocations({ teamId, pageSize: 100 })
  const connectionsQuery = useConnections({ teamId, pageSize: 100 })
  const tasksQuery = useTasks({
    entityType: "device",
    entityId: deviceId,
    pageSize: 5,
    orderBy: "created_at",
    sortOrder: "desc",
  })

  const [editing, setEditing] = useState(false)
  const [editName, setEditName] = useState("")
  const [editManufacturer, setEditManufacturer] = useState("")
  const [editModel, setEditModel] = useState("")
  const [editMacAddress, setEditMacAddress] = useState("")
  const [editIpAddress, setEditIpAddress] = useState("")
  const [editLocationId, setEditLocationId] = useState<string | null>(null)
  const [editConnectionId, setEditConnectionId] = useState<string | null>(null)

  useEffect(() => {
    if (editParam && data && !editing) {
      startEditing(data)
      navigate({ search: (prev: Record<string, unknown>) => ({ ...prev, edit: undefined }), replace: true })
    }
  }, [editParam, data])

  function startEditing(device: Device) {
    setEditName(device.name)
    setEditManufacturer(device.manufacturer ?? "")
    setEditModel(device.deviceModel ?? "")
    setEditMacAddress(device.macAddress ?? "")
    setEditIpAddress(device.ipAddress ?? "")
    setEditLocationId(device.locationId ?? null)
    setEditConnectionId(device.connectionId ?? null)
    setEditing(true)
  }

  function handleInfoSave() {
    const payload: Record<string, unknown> = {}
    if (editName !== data?.name) payload.name = editName
    if (editManufacturer !== (data?.manufacturer ?? "")) payload.manufacturer = editManufacturer || null
    if (editModel !== (data?.deviceModel ?? "")) payload.deviceModel = editModel || null
    if (editMacAddress !== (data?.macAddress ?? "")) payload.macAddress = editMacAddress || null
    if (editIpAddress !== (data?.ipAddress ?? "")) payload.ipAddress = editIpAddress || null
    if (editLocationId !== (data?.locationId ?? null)) payload.locationId = editLocationId || null
    if (editConnectionId !== (data?.connectionId ?? null)) payload.connectionId = editConnectionId || null
    updateDevice.mutate(payload, {
      onSuccess: () => setEditing(false),
    })
  }

  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        {/* Header skeleton */}
        <div className="space-y-2">
          <Skeleton className="h-4 w-32" />
          <Skeleton className="h-8 w-56" />
          <Skeleton className="h-4 w-40" />
        </div>
        {/* Tabs skeleton */}
        <PageSection>
          <Skeleton className="h-10 w-72 rounded-lg" />
          <div className="mt-6 space-y-6">
            {/* Device Info card */}
            <div className="rounded-xl border border-border/60 bg-card/80 p-6 space-y-4">
              <div className="flex items-center gap-2">
                <Skeleton className="h-5 w-5 rounded" />
                <Skeleton className="h-6 w-28" />
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
            {/* Network card */}
            <div className="rounded-xl border border-border/60 bg-card/80 p-6 space-y-4">
              <div className="flex items-center gap-2">
                <Skeleton className="h-5 w-5 rounded" />
                <Skeleton className="h-6 w-24" />
              </div>
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                {Array.from({ length: 5 }).map((_, i) => (
                  <div key={i} className="space-y-1.5">
                    <Skeleton className="h-3.5 w-24" />
                    <Skeleton className="h-5 w-36" />
                  </div>
                ))}
              </div>
            </div>
            {/* Lines card */}
            <div className="rounded-xl border border-border/60 bg-card/80 p-6 space-y-4">
              <div className="flex items-center gap-2">
                <Skeleton className="h-5 w-5 rounded" />
                <Skeleton className="h-6 w-36" />
              </div>
              <div className="space-y-2">
                {Array.from({ length: 2 }).map((_, i) => (
                  <Skeleton key={i} className="h-12 w-full rounded-md" />
                ))}
              </div>
            </div>
            {/* Metadata card */}
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
          </div>
        </PageSection>
      </PageContainer>
    )
  }

  if (isError || !data) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader
          eyebrow="Devices"
          title="Device Details"
          actions={
            <Button variant="outline" size="sm" asChild>
              <Link to="/devices">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back to devices
              </Link>
            </Button>
          }
        />
        <PageSection>
          <EmptyState
            icon={AlertCircle}
            title="Unable to load device"
            description="Something went wrong. Please try again."
            action={<Button variant="outline" size="sm" onClick={() => refetch()}>Try again</Button>}
          />
        </PageSection>
      </PageContainer>
    )
  }

  const handleDelete = async () => {
    await deleteDevice.mutateAsync(deviceId)
    router.navigate({ to: "/devices" })
  }

  const lines = linesQuery.data?.items ?? []

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Devices"
        title={data.name}
        description={`${deviceTypeLabels[data.deviceType] ?? data.deviceType}${data.isActive === false ? " (Disabled)" : ""}`}
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
                  <Link to="/devices">Devices</Link>
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
            <DeviceStatusBadge status={data.status} />
            {!data.isActive && (
              <Badge
                variant="outline"
                className="border-muted-foreground/30 text-muted-foreground"
              >
                Disabled
              </Badge>
            )}
            {!editing && (
              <Button variant="outline" size="sm" onClick={() => startEditing(data)}>
                <Pencil className="mr-2 h-4 w-4" /> Edit
              </Button>
            )}
            <RebootButton
              onReboot={() => rebootDevice.mutate()}
              isPending={rebootDevice.isPending}
              size="sm"
            />
            <ReprovisionButton
              onReprovision={() => reprovisionDevice.mutate()}
              isPending={reprovisionDevice.isPending}
              size="sm"
            />
            <DeleteButton
              deviceName={data.name}
              onDelete={handleDelete}
              isPending={deleteDevice.isPending}
              size="sm"
            />
          </div>
        }
      />

      <PageSection>
        <Tabs value={tab} onValueChange={(value) => navigate({ search: () => ({ tab: value }), replace: true })}>
          <TabsList>
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="lines">Lines</TabsTrigger>
            <TabsTrigger value="settings">Settings</TabsTrigger>
            <TabsTrigger value="external">External Data</TabsTrigger>
            <TabsTrigger value="remote" className="gap-1.5">
              <Wrench className="h-4 w-4" />
              Remote
            </TabsTrigger>
            <TabsTrigger value="activity" className="gap-1.5">
              <Activity className="h-4 w-4" />
              Activity
            </TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="mt-6 space-y-6">
            {/* Device Info */}
            <Card>
              <CardHeader className="flex flex-row items-center justify-between">
                <CardTitle className="flex items-center gap-2">
                  <Cpu className="h-5 w-5 text-muted-foreground" />
                  Device Info
                </CardTitle>
                {editing && (
                  <div className="flex gap-2">
                    <Button variant="ghost" size="sm" onClick={() => setEditing(false)}>
                      Cancel
                    </Button>
                    <Button size="sm" onClick={handleInfoSave} disabled={updateDevice.isPending}>
                      {updateDevice.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                      Save
                    </Button>
                  </div>
                )}
              </CardHeader>
              <CardContent>
                {editing ? (
                  <div className="space-y-4">
                    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                      <div className="space-y-2">
                        <Label>Name</Label>
                        <Input value={editName} onChange={(e) => setEditName(e.target.value)} />
                      </div>
                      <div className="space-y-2">
                        <Label>Manufacturer</Label>
                        <Input value={editManufacturer} onChange={(e) => setEditManufacturer(e.target.value)} placeholder="e.g. Polycom" />
                      </div>
                      <div className="space-y-2">
                        <Label>Model</Label>
                        <Input value={editModel} onChange={(e) => setEditModel(e.target.value)} placeholder="e.g. VVX 450" />
                      </div>
                      <div className="space-y-2">
                        <Label>MAC Address</Label>
                        <Input value={editMacAddress} onChange={(e) => setEditMacAddress(e.target.value)} placeholder="AA:BB:CC:DD:EE:FF" />
                      </div>
                      <div className="space-y-2">
                        <Label>IP Address</Label>
                        <Input value={editIpAddress} onChange={(e) => setEditIpAddress(e.target.value)} placeholder="192.168.1.100" />
                      </div>
                      <div className="space-y-2">
                        <Label>Location</Label>
                        <Select
                          value={editLocationId ?? "__none__"}
                          onValueChange={(v) => setEditLocationId(v === "__none__" ? null : v)}
                        >
                          <SelectTrigger>
                            <SelectValue placeholder="Select a location" />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="__none__">None</SelectItem>
                            {(locationsQuery.data?.items ?? []).map((loc) => (
                              <SelectItem key={loc.id} value={loc.id}>
                                {loc.name}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="space-y-2">
                        <Label>Connection</Label>
                        <Select
                          value={editConnectionId ?? "__none__"}
                          onValueChange={(v) => setEditConnectionId(v === "__none__" ? null : v)}
                        >
                          <SelectTrigger>
                            <SelectValue placeholder="Select a connection" />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="__none__">None</SelectItem>
                            {(connectionsQuery.data?.items ?? []).map((conn) => (
                              <SelectItem key={conn.id} value={conn.id}>
                                {conn.name}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-3">
                    <div>
                      <p className="text-muted-foreground">Name</p>
                      <p className="font-medium">{data.name}</p>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Type</p>
                      <p>{deviceTypeLabels[data.deviceType] ?? data.deviceType}</p>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Status</p>
                      <div className="mt-0.5">
                        <DeviceStatusBadge status={data.status} />
                      </div>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Model</p>
                      <p>{data.deviceModel || "---"}</p>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Manufacturer</p>
                      <p>{data.manufacturer || "---"}</p>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Active</p>
                      <div className="mt-0.5 flex items-center gap-2">
                        <p>{data.isActive ? "Yes" : "No"}</p>
                        <ToggleActiveButton
                          isActive={data.isActive ?? true}
                          onToggle={() => updateDevice.mutate({ isActive: !data.isActive })}
                          isPending={updateDevice.isPending}
                          size="sm"
                        />
                      </div>
                    </div>
                    <div>
                      <p className="text-muted-foreground flex items-center gap-1">
                        <MapPin className="h-3.5 w-3.5" />
                        Location
                      </p>
                      {data.locationId && data.locationName ? (
                        <Link
                          to="/locations/$locationId"
                          params={{ locationId: data.locationId }}
                          className="font-medium text-primary hover:underline"
                        >
                          {data.locationName}
                        </Link>
                      ) : (
                        <p className="text-muted-foreground">None</p>
                      )}
                    </div>
                    <div>
                      <p className="text-muted-foreground flex items-center gap-1">
                        <Network className="h-3.5 w-3.5" />
                        Connection
                      </p>
                      {data.connectionId && data.connectionName ? (
                        <Link
                          to="/connections/$connectionId"
                          params={{ connectionId: data.connectionId }}
                          className="font-medium text-primary hover:underline"
                        >
                          {data.connectionName}
                        </Link>
                      ) : (
                        <p className="text-muted-foreground">None</p>
                      )}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Network */}
            <Card>
              <CardHeader>
                <div className="flex items-center gap-2">
                  <Network className="h-5 w-5 text-muted-foreground" />
                  <CardTitle>Network</CardTitle>
                </div>
              </CardHeader>
              <CardContent>
                <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-3">
                  <div>
                    <p className="text-muted-foreground">MAC Address</p>
                    <div className="flex items-center gap-1">
                      <p className="font-mono text-xs">{data.macAddress || "---"}</p>
                      {data.macAddress && (
                        <CopyButton value={data.macAddress} label="MAC address" />
                      )}
                    </div>
                  </div>
                  <div>
                    <p className="text-muted-foreground">IP Address</p>
                    <div className="flex items-center gap-1">
                      <p className="font-mono text-xs">{data.ipAddress || "---"}</p>
                      {data.ipAddress && (
                        <CopyButton value={data.ipAddress} label="IP address" />
                      )}
                    </div>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Firmware Version</p>
                    <p className="font-mono text-xs">{data.firmwareVersion || "---"}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">SIP Username</p>
                    <p className="font-mono text-xs">{data.sipUsername}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">SIP Server</p>
                    <p className="font-mono text-xs">{data.sipServer}</p>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Lines / Extensions */}
            <Card>
              <CardHeader>
                <div className="flex items-center gap-2">
                  <Phone className="h-5 w-5 text-muted-foreground" />
                  <CardTitle>Lines / Extensions</CardTitle>
                </div>
              </CardHeader>
              <CardContent>
                {linesQuery.isLoading ? (
                  <p className="text-sm text-muted-foreground">Loading lines...</p>
                ) : lines.length === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    No lines assigned. Go to the Lines tab to configure line assignments.
                  </p>
                ) : (
                  <div className="space-y-2">
                    {lines.map((line) => (
                      <div
                        key={line.id}
                        className="flex items-center justify-between rounded-md border px-3 py-2"
                      >
                        <div className="flex items-center gap-3">
                          <span className="flex h-6 w-6 items-center justify-center rounded-full bg-muted font-mono text-xs font-medium">
                            {line.lineNumber}
                          </span>
                          <span className="text-sm font-medium">{line.label}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge variant="outline" className="text-xs">
                            {line.lineType}
                          </Badge>
                          {line.isActive === false && (
                            <Badge variant="outline" className="border-muted-foreground/30 text-xs text-muted-foreground">
                              Inactive
                            </Badge>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Recent Tasks */}
            <Card>
              <CardHeader className="flex flex-row items-center justify-between">
                <div className="flex items-center gap-2">
                  <ClipboardList className="h-5 w-5 text-muted-foreground" />
                  <CardTitle>Recent Tasks</CardTitle>
                </div>
                <Button variant="ghost" size="sm" asChild>
                  <Link to="/tasks">View all</Link>
                </Button>
              </CardHeader>
              <CardContent>
                {tasksQuery.isLoading ? (
                  <div className="space-y-2">
                    {Array.from({ length: 3 }).map((_, i) => (
                      <Skeleton key={i} className="h-10 w-full rounded-md" />
                    ))}
                  </div>
                ) : !tasksQuery.data?.items?.length ? (
                  <p className="text-sm text-muted-foreground py-4 text-center">
                    No background tasks have been run for this device yet.
                  </p>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Type</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead className="hidden sm:table-cell">Progress</TableHead>
                        <TableHead className="hidden md:table-cell">Started</TableHead>
                        <TableHead className="hidden md:table-cell">Duration</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {tasksQuery.data.items.map((task) => (
                        <TableRow key={task.id} className="hover:bg-muted/50 transition-colors">
                          <TableCell>
                            <Link
                              to="/tasks/$taskId"
                              params={{ taskId: task.id }}
                              className="font-medium text-sm hover:underline"
                            >
                              {formatTaskType(task.taskType)}
                            </Link>
                          </TableCell>
                          <TableCell>
                            <TaskStatusBadge status={task.status} />
                          </TableCell>
                          <TableCell className="hidden sm:table-cell">
                            {task.progress != null && task.progress > 0 ? (
                              <div className="flex items-center gap-2 min-w-[80px]">
                                <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted">
                                  <div
                                    className={`h-full rounded-full transition-all duration-300 ${
                                      task.status === "failed"
                                        ? "bg-red-500"
                                        : task.status === "completed"
                                          ? "bg-green-500"
                                          : "bg-blue-500"
                                    }`}
                                    style={{ width: `${Math.min(task.progress, 100)}%` }}
                                  />
                                </div>
                                <span className="text-xs font-medium text-muted-foreground w-8 text-right">
                                  {Math.round(task.progress)}%
                                </span>
                              </div>
                            ) : (
                              <span className="text-xs text-muted-foreground">--</span>
                            )}
                          </TableCell>
                          <TableCell className="hidden md:table-cell">
                            {task.startedAt ? (
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <span className="cursor-default text-xs text-muted-foreground">
                                    {formatRelativeTimeShort(task.startedAt)}
                                  </span>
                                </TooltipTrigger>
                                <TooltipContent>{formatDateTime(task.startedAt)}</TooltipContent>
                              </Tooltip>
                            ) : (
                              <span className="text-xs text-muted-foreground">--</span>
                            )}
                          </TableCell>
                          <TableCell className="hidden md:table-cell">
                            <span className="text-xs text-muted-foreground">
                              {formatDuration(task.startedAt, task.completedAt)}
                            </span>
                          </TableCell>
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
                <div className="flex items-center gap-2">
                  <Fingerprint className="h-5 w-5 text-muted-foreground" />
                  <CardTitle>Metadata</CardTitle>
                </div>
              </CardHeader>
              <CardContent>
                <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-4">
                  <div>
                    <p className="text-muted-foreground text-sm">Device ID</p>
                    <div className="flex items-center gap-1">
                      <p className="font-mono text-xs">{deviceId}</p>
                      <CopyButton value={deviceId} label="device ID" />
                    </div>
                  </div>
                  <TimestampField label="Last Seen" value={data.lastSeenAt} />
                  <TimestampField label="Provisioned" value={data.provisionedAt} />
                  {data.teamId && (
                    <div>
                      <p className="text-muted-foreground text-sm">Team ID</p>
                      <div className="flex items-center gap-1">
                        <p className="font-mono text-xs">{data.teamId}</p>
                        <CopyButton value={data.teamId} label="team ID" />
                      </div>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="lines" className="mt-6">
            <DeviceLineConfig deviceId={deviceId} />
          </TabsContent>

          <TabsContent value="settings" className="mt-6">
            <SettingsTab deviceId={deviceId} data={data} />
          </TabsContent>

          <TabsContent value="external" className="mt-6">
            <ExternalDataTab
              hasIdentifier={!!data.macAddress}
              noIdentifierMessage="This device has no MAC address configured. A MAC address is required to look up external provisioning data."
              sources={gatewayQuery.data?.sources}
              isLoading={gatewayQuery.isLoading}
              isRefetching={gatewayQuery.isRefetching}
              isError={gatewayQuery.isError}
              onRefresh={() => gatewayQuery.refetch()}
            />
          </TabsContent>

          <TabsContent value="remote" className="mt-6">
            <DeviceDiagnosticTab
              deviceId={deviceId}
              manufacturer={data.manufacturer}
              deviceModel={data.deviceModel}
              macAddress={data.macAddress}
              sipUsername={data.sipUsername}
              sipServer={data.sipServer}
              ipAddress={data.ipAddress}
              deviceName={data.name}
            />
          </TabsContent>

          <TabsContent value="activity" className="mt-6">
            <EntityActivityPanel
              targetType="device"
              targetId={deviceId}
              enabled={tab === "activity"}
            />
          </TabsContent>
        </Tabs>
      </PageSection>

      {/* Danger Zone */}
      <PageSection delay={0.25}>
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
                <p className="font-medium text-sm">Delete this device</p>
                <p className="text-sm text-muted-foreground">
                  This action cannot be undone. All line assignments and configuration will be
                  permanently removed.
                </p>
              </div>
              <DeleteButton
                deviceName={data.name}
                onDelete={handleDelete}
                isPending={deleteDevice.isPending}
                size="sm"
              />
            </div>
          </CardContent>
        </Card>
      </PageSection>

    </PageContainer>
  )
}

// ---------------------------------------------------------------------------
// Settings Tab
// ---------------------------------------------------------------------------

interface SettingsTabProps {
  deviceId: string
  data: {
    name: string
    sipUsername: string
    sipServer: string
    configJson?: Record<string, unknown> | null
  }
}

function SettingsTab({ deviceId, data }: SettingsTabProps) {
  const updateDevice = useUpdateDevice(deviceId)
  const phoneAuth = (data.configJson?.phoneAuth ?? {}) as { username?: string; password?: string }
  const [name, setName] = useState(data.name)
  const [phoneUser, setPhoneUser] = useState(phoneAuth.username ?? "admin")
  const [phonePass, setPhonePass] = useState(phoneAuth.password ?? "admin")
  const [showPass, setShowPass] = useState(false)
  const [configText, setConfigText] = useState(() => {
    if (!data.configJson) return ""
    const { phoneAuth: _strip, ...rest } = data.configJson
    return Object.keys(rest).length > 0 ? JSON.stringify(rest, null, 2) : ""
  })
  const [configError, setConfigError] = useState<string | null>(null)
  const [dirty, setDirty] = useState(false)

  function handleSave() {
    const payload: Record<string, unknown> = {}

    if (name !== data.name) {
      payload.name = name
    }

    let extraConfig: Record<string, unknown> = {}
    if (configText.trim()) {
      try {
        extraConfig = JSON.parse(configText)
        setConfigError(null)
      } catch {
        setConfigError("Invalid JSON")
        return
      }
    }

    payload.configJson = {
      ...extraConfig,
      phoneAuth: { username: phoneUser, password: phonePass },
    }

    updateDevice.mutate(payload, {
      onSuccess: () => setDirty(false),
    })
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Settings className="h-5 w-5 text-muted-foreground" />
            <CardTitle>SIP Configuration</CardTitle>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="device-name">Device Name</Label>
            <Input
              id="device-name"
              value={name}
              onChange={(e) => {
                setName(e.target.value)
                setDirty(true)
              }}
            />
          </div>
          <div className="space-y-2">
            <Label>SIP Username</Label>
            <Input value={data.sipUsername} disabled />
          </div>
          <div className="space-y-2">
            <Label>SIP Server</Label>
            <Input value={data.sipServer} disabled />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-muted-foreground" />
            <CardTitle>Phone Authentication</CardTitle>
          </div>
          <p className="text-sm text-muted-foreground">
            Credentials used for Live View screenshot capture and device management.
          </p>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="phone-username">Username</Label>
            <Input
              id="phone-username"
              value={phoneUser}
              onChange={(e) => {
                setPhoneUser(e.target.value)
                setDirty(true)
              }}
              placeholder="admin"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="phone-password">Password</Label>
            <div className="relative">
              <Input
                id="phone-password"
                type={showPass ? "text" : "password"}
                value={phonePass}
                onChange={(e) => {
                  setPhonePass(e.target.value)
                  setDirty(true)
                }}
                placeholder="admin"
                className="pr-10"
              />
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="absolute right-0 top-0 h-full w-10 hover:bg-transparent"
                onClick={() => setShowPass(!showPass)}
                tabIndex={-1}
                aria-label={showPass ? "Hide password" : "Show password"}
              >
                {showPass ? <EyeOff className="h-4 w-4 text-muted-foreground" /> : <Eye className="h-4 w-4 text-muted-foreground" />}
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Wrench className="h-5 w-5 text-muted-foreground" />
            <CardTitle>Advanced Configuration</CardTitle>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="config-json">Configuration JSON</Label>
            <Textarea
              id="config-json"
              value={configText}
              onChange={(e) => {
                setConfigText(e.target.value)
                setConfigError(null)
                setDirty(true)
              }}
              rows={10}
              className="font-mono text-xs"
              placeholder='{"key": "value"}'
            />
            {configError && <p className="text-destructive text-sm">{configError}</p>}
          </div>
        </CardContent>
      </Card>

      <div className="flex items-center justify-end gap-2">
        <Button
          variant="ghost"
          onClick={() => {
            setName(data.name)
            setPhoneUser(phoneAuth.username ?? "admin")
            setPhonePass(phoneAuth.password ?? "admin")
            setShowPass(false)
            const { phoneAuth: _strip, ...rest } = data.configJson ?? {}
            setConfigText(Object.keys(rest).length > 0 ? JSON.stringify(rest, null, 2) : "")
            setConfigError(null)
            setDirty(false)
          }}
          disabled={!dirty || updateDevice.isPending}
        >
          Reset
        </Button>
        <Button onClick={handleSave} disabled={!dirty || updateDevice.isPending}>
          {updateDevice.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
          Save Settings
        </Button>
      </div>
    </div>
  )
}
