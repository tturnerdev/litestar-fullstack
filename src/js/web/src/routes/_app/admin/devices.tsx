import { useState } from "react"
import { createFileRoute } from "@tanstack/react-router"
import { AdminNav } from "@/components/admin/admin-nav"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"

export const Route = createFileRoute("/_app/admin/devices")({
  component: AdminDevicesPage,
})

// Placeholder data until backend aggregation endpoints are available
const stats = [
  { label: "Total devices", value: 0 },
  { label: "Active devices", value: 0 },
  { label: "Offline devices", value: 0 },
  { label: "Needs provisioning", value: 0 },
]

interface DeviceRow {
  id: string
  name: string
  macAddress: string
  model: string
  teamName: string
  status: "active" | "offline" | "provisioning"
  lastSeen: string
}

// Placeholder — will be replaced by API data
const placeholderDevices: DeviceRow[] = []

const PAGE_SIZE = 25

const statusVariant: Record<DeviceRow["status"], "default" | "secondary" | "outline" | "destructive"> = {
  active: "default",
  offline: "destructive",
  provisioning: "secondary",
}

function AdminDevicesPage() {
  const [page, setPage] = useState(1)

  // TODO: replace with useAdminDevices() hook once backend endpoint exists
  const devices = placeholderDevices
  const total = devices.length
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const paged = devices.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader eyebrow="Administration" title="Devices" description="Manage all devices across the organization." />
      <AdminNav />

      <PageSection>
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          {stats.map((item) => (
            <Card key={item.label}>
              <CardHeader>
                <CardTitle className="text-sm text-muted-foreground">{item.label}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-semibold">{item.value}</div>
              </CardContent>
            </Card>
          ))}
        </div>
      </PageSection>

      <PageSection delay={0.1}>
        <Card>
          <CardHeader>
            <CardTitle>All devices</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>MAC address</TableHead>
                  <TableHead>Model</TableHead>
                  <TableHead>Team</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Last seen</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {paged.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center text-muted-foreground">
                      No devices found. Devices will appear here once the device management backend is connected.
                    </TableCell>
                  </TableRow>
                )}
                {paged.map((device) => (
                  <TableRow key={device.id}>
                    <TableCell className="font-medium">{device.name}</TableCell>
                    <TableCell className="font-mono text-muted-foreground text-sm">{device.macAddress}</TableCell>
                    <TableCell className="text-muted-foreground">{device.model}</TableCell>
                    <TableCell className="text-muted-foreground">{device.teamName}</TableCell>
                    <TableCell>
                      <Badge variant={statusVariant[device.status]}>{device.status}</Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground">{new Date(device.lastSeen).toLocaleString()}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            {total > PAGE_SIZE && (
              <div className="flex items-center justify-between">
                <p className="text-xs text-muted-foreground">
                  Page {page} of {totalPages}
                </p>
                <div className="flex gap-2">
                  <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page <= 1}>
                    Previous
                  </Button>
                  <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page >= totalPages}>
                    Next
                  </Button>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </PageSection>
    </PageContainer>
  )
}
