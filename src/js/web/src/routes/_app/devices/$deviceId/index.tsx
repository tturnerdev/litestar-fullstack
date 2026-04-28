import { createFileRoute, Link, useRouter } from "@tanstack/react-router"
import { useState } from "react"
import { ArrowLeft, Loader2 } from "lucide-react"
import { DeviceActions } from "@/components/devices/device-actions"
import { DeviceLineConfig } from "@/components/devices/device-line-config"
import { DeviceStatusBadge } from "@/components/devices/device-status-badge"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { useDeleteDevice, useDevice, useRebootDevice, useReprovisionDevice, useUpdateDevice } from "@/lib/api/hooks/devices"

export const Route = createFileRoute("/_app/devices/$deviceId/")({
  component: DeviceDetailPage,
})

const deviceTypeLabels: Record<string, string> = {
  desk_phone: "Desk Phone",
  softphone: "Softphone",
  ata: "ATA",
  conference: "Conference",
  other: "Other",
}

function formatDateTime(value: string | null | undefined): string {
  if (!value) return "---"
  return new Date(value).toLocaleString()
}

function DeviceDetailPage() {
  const { deviceId } = Route.useParams()
  const router = useRouter()
  const { data, isLoading, isError } = useDevice(deviceId)
  const updateDevice = useUpdateDevice(deviceId)
  const deleteDevice = useDeleteDevice()
  const rebootDevice = useRebootDevice(deviceId)
  const reprovisionDevice = useReprovisionDevice(deviceId)

  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader eyebrow="Devices" title="Device Details" />
        <PageSection>
          <SkeletonCard />
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

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Devices"
        title={data.name}
        description={`${deviceTypeLabels[data.deviceType] ?? data.deviceType}${data.isActive === false ? " (Disabled)" : ""}`}
        actions={
          <div className="flex items-center gap-3">
            <DeviceStatusBadge status={data.status} />
            {!data.isActive && (
              <Badge variant="outline" className="border-muted-foreground/30 text-muted-foreground">
                Disabled
              </Badge>
            )}
            <Button variant="outline" size="sm" asChild>
              <Link to="/devices">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back to devices
              </Link>
            </Button>
          </div>
        }
      />
      <PageSection>
        <Tabs defaultValue="overview">
          <TabsList>
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="lines">Lines</TabsTrigger>
            <TabsTrigger value="settings">Settings</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="mt-6">
            <OverviewTab
              data={data}
              onReboot={() => rebootDevice.mutate()}
              onReprovision={() => reprovisionDevice.mutate()}
              onToggleActive={() => updateDevice.mutate({ isActive: !data.isActive })}
              onDelete={handleDelete}
              rebootPending={rebootDevice.isPending}
              reprovisionPending={reprovisionDevice.isPending}
              togglePending={updateDevice.isPending}
              deletePending={deleteDevice.isPending}
            />
          </TabsContent>

          <TabsContent value="lines" className="mt-6">
            <DeviceLineConfig deviceId={deviceId} />
          </TabsContent>

          <TabsContent value="settings" className="mt-6">
            <SettingsTab deviceId={deviceId} data={data} />
          </TabsContent>
        </Tabs>
      </PageSection>
    </PageContainer>
  )
}

// ---------------------------------------------------------------------------
// Overview Tab
// ---------------------------------------------------------------------------

interface OverviewTabProps {
  data: {
    name: string
    deviceType: string
    status: string
    isActive?: boolean
    macAddress?: string | null
    deviceModel?: string | null
    manufacturer?: string | null
    firmwareVersion?: string | null
    ipAddress?: string | null
    sipUsername: string
    sipServer: string
    lastSeenAt?: string | null
    provisionedAt?: string | null
  }
  onReboot: () => void
  onReprovision: () => void
  onToggleActive: () => void
  onDelete: () => void
  rebootPending?: boolean
  reprovisionPending?: boolean
  togglePending?: boolean
  deletePending?: boolean
}

function OverviewTab({ data, onReboot, onReprovision, onToggleActive, onDelete, rebootPending, reprovisionPending, togglePending, deletePending }: OverviewTabProps) {
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Device Information</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-3">
            <InfoField label="Name" value={data.name} />
            <InfoField label="Type" value={deviceTypeLabels[data.deviceType] ?? data.deviceType} />
            <InfoField label="Status">
              <DeviceStatusBadge status={data.status} />
            </InfoField>
            <InfoField label="Active" value={data.isActive ? "Yes" : "No"} />
            <InfoField label="MAC Address" value={data.macAddress} mono />
            <InfoField label="Model" value={data.deviceModel} />
            <InfoField label="Manufacturer" value={data.manufacturer} />
            <InfoField label="Firmware" value={data.firmwareVersion} />
            <InfoField label="IP Address" value={data.ipAddress} mono />
            <InfoField label="SIP Username" value={data.sipUsername} mono />
            <InfoField label="SIP Server" value={data.sipServer} mono />
            <InfoField label="Last Seen" value={formatDateTime(data.lastSeenAt)} />
            <InfoField label="Provisioned" value={formatDateTime(data.provisionedAt)} />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Actions</CardTitle>
        </CardHeader>
        <CardContent>
          <DeviceActions
            deviceName={data.name}
            isActive={data.isActive ?? true}
            onReboot={onReboot}
            onReprovision={onReprovision}
            onToggleActive={onToggleActive}
            onDelete={onDelete}
            rebootPending={rebootPending}
            reprovisionPending={reprovisionPending}
            togglePending={togglePending}
            deletePending={deletePending}
          />
        </CardContent>
      </Card>
    </div>
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
          <CardTitle>SIP Configuration</CardTitle>
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
          <CardTitle>Advanced Configuration</CardTitle>
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

// ---------------------------------------------------------------------------
// Info Field helper
// ---------------------------------------------------------------------------

function InfoField({
  label,
  value,
  mono,
  children,
}: {
  label: string
  value?: string | null
  mono?: boolean
  children?: React.ReactNode
}) {
  return (
    <div>
      <p className="text-muted-foreground">{label}</p>
      {children ?? <p className={mono ? "font-mono text-xs" : ""}>{value ?? "---"}</p>}
    </div>
  )
}
