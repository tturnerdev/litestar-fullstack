import { createFileRoute, Link, useRouter } from "@tanstack/react-router"
import { useEffect, useState } from "react"
import {
  AlertTriangle,
  ArrowLeft,
  Cpu,
  Fingerprint,
  Loader2,
  Network,
  Pencil,
  Phone,
  Settings,
  Wrench,
} from "lucide-react"
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
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Skeleton } from "@/components/ui/skeleton"
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
  const { data, isLoading, isError } = useDevice(deviceId)
  useDocumentTitle(data?.name ?? "Device Details")
  const updateDevice = useUpdateDevice(deviceId)
  const deleteDevice = useDeleteDevice()
  const rebootDevice = useRebootDevice(deviceId)
  const reprovisionDevice = useReprovisionDevice(deviceId)
  const linesQuery = useDeviceLines(deviceId)

  const [editing, setEditing] = useState(false)
  const [editName, setEditName] = useState("")
  const [editManufacturer, setEditManufacturer] = useState("")
  const [editModel, setEditModel] = useState("")
  const [editMacAddress, setEditMacAddress] = useState("")
  const [editIpAddress, setEditIpAddress] = useState("")

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
    setEditing(true)
  }

  function handleInfoSave() {
    const payload: Record<string, unknown> = {}
    if (editName !== data?.name) payload.name = editName
    if (editManufacturer !== (data?.manufacturer ?? "")) payload.manufacturer = editManufacturer || null
    if (editModel !== (data?.deviceModel ?? "")) payload.deviceModel = editModel || null
    if (editMacAddress !== (data?.macAddress ?? "")) payload.macAddress = editMacAddress || null
    if (editIpAddress !== (data?.ipAddress ?? "")) payload.ipAddress = editIpAddress || null
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
          <Card>
            <CardHeader>
              <CardTitle>Device detail</CardTitle>
            </CardHeader>
            <CardContent className="text-muted-foreground">We could not load this device.</CardContent>
          </Card>
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
  const [name, setName] = useState(data.name)
  const [configText, setConfigText] = useState(data.configJson ? JSON.stringify(data.configJson, null, 2) : "")
  const [configError, setConfigError] = useState<string | null>(null)
  const [dirty, setDirty] = useState(false)

  function handleSave() {
    const payload: Record<string, unknown> = {}

    if (name !== data.name) {
      payload.name = name
    }

    if (configText.trim()) {
      try {
        payload.configJson = JSON.parse(configText)
        setConfigError(null)
      } catch {
        setConfigError("Invalid JSON")
        return
      }
    } else {
      payload.configJson = null
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
          <div className="flex items-center justify-end gap-2">
            <Button
              variant="ghost"
              onClick={() => {
                setName(data.name)
                setConfigText(data.configJson ? JSON.stringify(data.configJson, null, 2) : "")
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
        </CardContent>
      </Card>
    </div>
  )
}
