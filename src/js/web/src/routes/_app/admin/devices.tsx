import { useState } from "react"
import { createFileRoute } from "@tanstack/react-router"
import { AdminBreadcrumbs } from "@/components/admin/admin-breadcrumbs"
import { AdminNav } from "@/components/admin/admin-nav"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useAdminDevices, useAdminDeviceStats } from "@/lib/api/hooks/admin"
import { Search } from "lucide-react"

export const Route = createFileRoute("/_app/admin/devices")({
  component: AdminDevicesPage,
})

const PAGE_SIZE = 25

const statusVariant: Record<string, "default" | "secondary" | "outline" | "destructive"> = {
  online: "default",
  offline: "destructive",
  provisioning: "secondary",
  error: "destructive",
}

function AdminDevicesPage() {
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState("")

  const { data: stats, isLoading: statsLoading } = useAdminDeviceStats()
  const { data, isLoading } = useAdminDevices(page, PAGE_SIZE, search || undefined)

  const devices = data?.items ?? []
  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  const statCards = [
    { label: "Total devices", value: stats?.total ?? 0 },
    { label: "Active devices", value: stats?.active ?? 0 },
    { label: "Online", value: stats?.online ?? 0 },
    { label: "Offline", value: stats?.offline ?? 0 },
  ]

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader eyebrow="Administration" title="Devices" description="Manage all devices across the organization." breadcrumbs={<AdminBreadcrumbs />} />
      <AdminNav />

      <PageSection>
        {statsLoading ? (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <SkeletonCard key={i} />
            ))}
          </div>
        ) : (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            {statCards.map((item) => (
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
        )}
      </PageSection>

      <PageSection delay={0.1}>
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between gap-4">
              <CardTitle>All devices</CardTitle>
              <div className="relative max-w-sm">
                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  placeholder="Search devices..."
                  value={search}
                  onChange={(e) => {
                    setSearch(e.target.value)
                    setPage(1)
                  }}
                  className="pl-9"
                />
              </div>
            </div>
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
                {isLoading ? (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center py-8">
                      <div className="flex items-center justify-center">
                        <div className="h-5 w-5 animate-spin rounded-full border-2 border-muted-foreground border-t-transparent" />
                      </div>
                    </TableCell>
                  </TableRow>
                ) : devices.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center text-muted-foreground">
                      {search ? "No devices match your search." : "No devices found."}
                    </TableCell>
                  </TableRow>
                ) : (
                  devices.map((device) => (
                    <TableRow key={device.id}>
                      <TableCell className="font-medium">{device.name}</TableCell>
                      <TableCell className="font-mono text-muted-foreground text-sm">{device.macAddress ?? "—"}</TableCell>
                      <TableCell className="text-muted-foreground">{device.model ?? "—"}</TableCell>
                      <TableCell className="text-muted-foreground">{device.teamName ?? "—"}</TableCell>
                      <TableCell>
                        <Badge variant={statusVariant[device.status] ?? "outline"}>{device.status}</Badge>
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {device.lastSeenAt ? new Date(device.lastSeenAt).toLocaleString() : "Never"}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
            {totalPages > 1 && (
              <div className="flex items-center justify-between">
                <p className="text-xs text-muted-foreground">
                  Page {page} of {totalPages} ({total} total)
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
