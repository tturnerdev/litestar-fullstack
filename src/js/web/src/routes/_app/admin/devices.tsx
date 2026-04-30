import { useState } from "react"
import { createFileRoute, Link } from "@tanstack/react-router"
import {
  AlertCircle,
  ArrowRight,
  HardDrive,
  Monitor,
  Search,
  Signal,
  SignalZero,
  Wifi,
} from "lucide-react"
import { AdminBreadcrumbs } from "@/components/admin/admin-breadcrumbs"
import { AdminNav } from "@/components/admin/admin-nav"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Skeleton, SkeletonTable } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useAdminDevices, useAdminDeviceStats } from "@/lib/api/hooks/admin"

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

const statConfig = [
  {
    key: "total" as const,
    label: "Total Devices",
    subtitle: "All registered devices",
    icon: HardDrive,
    color: "text-blue-600 dark:text-blue-400",
    bg: "bg-blue-500/10",
    hoverBg: "group-hover:bg-blue-500",
    to: "/devices" as const,
  },
  {
    key: "active" as const,
    label: "Active Devices",
    subtitle: "Currently provisioned",
    icon: Monitor,
    color: "text-emerald-600 dark:text-emerald-400",
    bg: "bg-emerald-500/10",
    hoverBg: "group-hover:bg-emerald-500",
    to: "/devices" as const,
  },
  {
    key: "online" as const,
    label: "Online",
    subtitle: "Connected right now",
    icon: Wifi,
    color: "text-green-600 dark:text-green-400",
    bg: "bg-green-500/10",
    hoverBg: "group-hover:bg-green-500",
    to: "/devices" as const,
  },
  {
    key: "offline" as const,
    label: "Offline",
    subtitle: "Not responding",
    icon: SignalZero,
    color: "text-red-600 dark:text-red-400",
    bg: "bg-red-500/10",
    hoverBg: "group-hover:bg-red-500",
    to: "/devices" as const,
  },
]

function StatsCardSkeleton() {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <Skeleton className="h-4 w-24" />
        <Skeleton className="h-9 w-9 rounded-lg" />
      </CardHeader>
      <CardContent>
        <Skeleton className="h-8 w-16" />
        <Skeleton className="mt-2 h-3 w-32" />
      </CardContent>
    </Card>
  )
}

function AdminDevicesPage() {
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState("")

  const { data: stats, isLoading: statsLoading, isError: statsError } = useAdminDeviceStats()
  const { data, isLoading, isError } = useAdminDevices(page, PAGE_SIZE, search || undefined)

  const devices = data?.items ?? []
  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  const recentDevices = devices.slice(0, 8)

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader eyebrow="Administration" title="Devices" description="Manage all devices across the organization." breadcrumbs={<AdminBreadcrumbs />} />
      <AdminNav />

      {/* Stat cards */}
      <PageSection>
        {statsLoading ? (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            {Array.from({ length: 4 }).map((_, i) => (
              // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
              <StatsCardSkeleton key={`device-stat-skeleton-${i}`} />
            ))}
          </div>
        ) : statsError ? (
          <Card>
            <CardContent className="flex items-center gap-3 py-6 text-muted-foreground">
              <AlertCircle className="h-5 w-5 text-destructive" />
              <span>Unable to load device statistics. Please try again later.</span>
            </CardContent>
          </Card>
        ) : (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            {statConfig.map((stat) => {
              const Icon = stat.icon
              const value = stats?.[stat.key] ?? 0
              return (
                <Link key={stat.key} to={stat.to} className="group">
                  <Card className="transition-all duration-200 group-hover:shadow-md group-hover:border-primary/30 group-hover:-translate-y-0.5">
                    <CardHeader className="flex flex-row items-center justify-between pb-2">
                      <CardTitle className="text-sm font-medium text-muted-foreground">{stat.label}</CardTitle>
                      <div
                        className={`flex h-9 w-9 items-center justify-center rounded-lg ${stat.bg} ${stat.color} transition-colors ${stat.hoverBg} group-hover:text-white`}
                      >
                        <Icon className="h-4 w-4" />
                      </div>
                    </CardHeader>
                    <CardContent>
                      <span className="text-3xl font-semibold tracking-tight">{value}</span>
                      <p className="mt-1.5 text-xs text-muted-foreground">{stat.subtitle}</p>
                    </CardContent>
                  </Card>
                </Link>
              )
            })}
          </div>
        )}
      </PageSection>

      {/* Recent devices */}
      <PageSection delay={0.1}>
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-500/10">
                  <Signal className="h-4 w-4 text-blue-600 dark:text-blue-400" />
                </div>
                <div>
                  <CardTitle>Recent Devices</CardTitle>
                  <CardDescription>Latest registered devices across all teams</CardDescription>
                </div>
              </div>
              <Link to="/devices">
                <Button variant="outline" size="sm" className="gap-1.5">
                  View all
                  <ArrowRight className="h-3.5 w-3.5" />
                </Button>
              </Link>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            {isLoading ? (
              <SkeletonTable rows={5} />
            ) : isError ? (
              <div className="flex items-center gap-3 py-8 justify-center text-muted-foreground">
                <AlertCircle className="h-5 w-5 text-destructive" />
                <span>Unable to load devices.</span>
              </div>
            ) : recentDevices.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                <HardDrive className="h-10 w-10 mb-3 opacity-40" />
                <p className="font-medium">No devices found</p>
                <p className="text-sm mt-1">Devices will appear here once registered.</p>
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>MAC Address</TableHead>
                    <TableHead>Model</TableHead>
                    <TableHead>Team</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Last Seen</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {recentDevices.map((device) => (
                    <TableRow key={device.id} className="hover:bg-muted/50 transition-colors">
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
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </PageSection>

      {/* Full device list */}
      <PageSection delay={0.2}>
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-violet-500/10">
                  <HardDrive className="h-4 w-4 text-violet-600 dark:text-violet-400" />
                </div>
                <div>
                  <CardTitle>All Devices</CardTitle>
                  <CardDescription>{total} device{total !== 1 ? "s" : ""} total</CardDescription>
                </div>
              </div>
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
            {isLoading ? (
              <SkeletonTable rows={8} />
            ) : isError ? (
              <div className="flex items-center gap-3 py-8 justify-center text-muted-foreground">
                <AlertCircle className="h-5 w-5 text-destructive" />
                <span>Unable to load devices.</span>
              </div>
            ) : devices.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                <Search className="h-10 w-10 mb-3 opacity-40" />
                <p className="font-medium">{search ? "No devices match your search" : "No devices found"}</p>
                <p className="text-sm mt-1">{search ? "Try a different search term." : "Devices will appear here once registered."}</p>
              </div>
            ) : (
              <>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>MAC Address</TableHead>
                      <TableHead>Model</TableHead>
                      <TableHead>Team</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Last Seen</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {devices.map((device) => (
                      <TableRow key={device.id} className="hover:bg-muted/50 transition-colors">
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
                    ))}
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
              </>
            )}
          </CardContent>
        </Card>
      </PageSection>
    </PageContainer>
  )
}
