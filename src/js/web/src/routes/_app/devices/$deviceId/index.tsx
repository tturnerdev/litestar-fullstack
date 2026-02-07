import { createFileRoute, Link, useRouter } from "@tanstack/react-router"
import { ArrowLeft, Power, RefreshCw, Trash2 } from "lucide-react"
import { DeviceStatusBadge } from "@/components/devices/device-status-badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonCard } from "@/components/ui/skeleton"
import { useDeleteDevice, useDevice, useUpdateDevice } from "@/lib/api/hooks/devices"

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
  if (!value) return "—"
  return new Date(value).toLocaleString()
}

function DeviceDetailPage() {
  const { deviceId } = Route.useParams()
  const router = useRouter()
  const { data, isLoading, isError } = useDevice(deviceId)
  const updateDevice = useUpdateDevice(deviceId)
  const deleteDevice = useDeleteDevice()

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
        description="View and manage device settings."
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
          <CardContent className="space-y-6">
            <div className="grid gap-3 text-sm md:grid-cols-2">
              <div>
                <p className="text-muted-foreground">Name</p>
                <p>{data.name}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Type</p>
                <p>{deviceTypeLabels[data.deviceType] ?? data.deviceType}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Status</p>
                <DeviceStatusBadge status={data.status} />
              </div>
              <div>
                <p className="text-muted-foreground">Active</p>
                <p>{data.isActive ? "Yes" : "No"}</p>
              </div>
              <div>
                <p className="text-muted-foreground">MAC Address</p>
                <p className="font-mono text-xs">{data.macAddress ?? "—"}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Model</p>
                <p>{data.model ?? "—"}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Manufacturer</p>
                <p>{data.manufacturer ?? "—"}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Firmware</p>
                <p>{data.firmwareVersion ?? "—"}</p>
              </div>
              <div>
                <p className="text-muted-foreground">IP Address</p>
                <p className="font-mono text-xs">{data.ipAddress ?? "—"}</p>
              </div>
              <div>
                <p className="text-muted-foreground">SIP Username</p>
                <p className="font-mono text-xs">{data.sipUsername}</p>
              </div>
              <div>
                <p className="text-muted-foreground">SIP Server</p>
                <p className="font-mono text-xs">{data.sipServer}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Last Seen</p>
                <p>{formatDateTime(data.lastSeenAt)}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Provisioned</p>
                <p>{formatDateTime(data.provisionedAt)}</p>
              </div>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button variant="outline" onClick={() => updateDevice.mutate({ is_active: !data.isActive })} disabled={updateDevice.isPending}>
                <Power className="mr-2 h-4 w-4" />
                {data.isActive ? "Deactivate" : "Activate"}
              </Button>
              <Button variant="outline" disabled>
                <RefreshCw className="mr-2 h-4 w-4" />
                Reboot
              </Button>
              <Button variant="destructive" onClick={handleDelete} disabled={deleteDevice.isPending}>
                <Trash2 className="mr-2 h-4 w-4" />
                Delete
              </Button>
            </div>
          </CardContent>
        </Card>
      </PageSection>
    </PageContainer>
  )
}
