import { useCallback, useEffect, useState } from "react"
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router"
import { cn } from "@/lib/utils"
import {
  AlertCircle,
  ArrowRight,
  Download,
  HardDrive,
  Monitor,
  Search,
  Signal,
  SignalZero,
  Wifi,
  X,
} from "lucide-react"
import { useDebouncedValue } from "@/hooks/use-debounced-value"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { AdminBreadcrumbs } from "@/components/admin/admin-breadcrumbs"
import { AdminNav } from "@/components/admin/admin-nav"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Skeleton, SkeletonTable } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { EmptyState } from "@/components/ui/empty-state"
import { useAdminDevices, useAdminDeviceStats } from "@/lib/api/hooks/admin"
import { exportToCsv, type CsvHeader } from "@/lib/csv-export"
import { formatDateTime } from "@/lib/date-utils"
import type { AdminDeviceSummary } from "@/lib/generated/api"

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

const csvHeaders: CsvHeader<AdminDeviceSummary>[] = [
  { label: "Name", accessor: (d) => d.name },
  { label: "Type", accessor: (d) => d.deviceType },
  { label: "Status", accessor: (d) => d.status },
  { label: "Active", accessor: (d) => (d.isActive ? "Yes" : "No") },
  { label: "MAC Address", accessor: (d) => d.macAddress ?? "" },
  { label: "IP Address", accessor: (d) => d.ipAddress ?? "" },
  { label: "SIP Username", accessor: (d) => d.sipUsername },
  { label: "Owner", accessor: (d) => d.ownerEmail ?? "" },
  { label: "Team", accessor: (d) => d.teamName ?? "" },
  { label: "Created At", accessor: (d) => d.createdAt },
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
  useDocumentTitle("Admin Devices")
  const navigate = useNavigate()
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState("")
  const debouncedSearch = useDebouncedValue(search)

  // Reset page when debounced search changes
  useEffect(() => {
    setPage(1)
  }, [debouncedSearch])

  const { data: stats, isLoading: statsLoading, isError: statsError, refetch: refetchStats } = useAdminDeviceStats()
  const { data, isLoading, isError, refetch } = useAdminDevices(page, PAGE_SIZE, debouncedSearch || undefined)

  const devices = data?.items ?? []
  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  const handleExport = useCallback(() => {
    exportToCsv("admin-devices", csvHeaders, devices)
  }, [devices])

  const recentDevices = devices.slice(0, 8)

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Administration"
        title="Devices"
        description="Manage all devices across the organization."
        breadcrumbs={<AdminBreadcrumbs />}
        actions={
          <Button variant="outline" size="sm" onClick={handleExport} disabled={!devices.length}>
            <Download className="mr-2 h-4 w-4" />
            Export
          </Button>
        }
      />
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
            <CardContent className="py-6">
              <EmptyState
                icon={AlertCircle}
                title="Unable to load device statistics"
                description="Something went wrong. Please try again."
                action={<Button variant="outline" size="sm" onClick={() => refetchStats()}>Try again</Button>}
              />
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
                        className={`flex h-9 w-9 items-center justify-center rounded-lg ${stat.bg} ${stat.color} transition-colors ${stat.hoverBg} group-hover:text-primary-foreground`}
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
              <EmptyState
                icon={AlertCircle}
                title="Unable to load devices"
                description="Something went wrong. Please try again."
                action={<Button variant="outline" size="sm" onClick={() => refetch()}>Try again</Button>}
              />
            ) : recentDevices.length === 0 ? (
              <EmptyState
                icon={HardDrive}
                title="No recent devices"
                description="Devices will appear here once registered."
              />
            ) : (
              <Table aria-label="Recent devices">
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
                  {recentDevices.map((device, index) => (
                    <TableRow key={device.id} className={cn("cursor-pointer hover:bg-muted/50 transition-colors", index % 2 === 1 && "bg-muted/20")} onClick={() => navigate({ to: "/devices/$deviceId", params: { deviceId: device.id } })}>
                      <TableCell className="font-medium">{device.name}</TableCell>
                      <TableCell className="font-mono text-muted-foreground text-sm">{device.macAddress ?? "—"}</TableCell>
                      <TableCell className="text-muted-foreground">{device.model ?? "—"}</TableCell>
                      <TableCell className="text-muted-foreground">{device.teamName ?? "—"}</TableCell>
                      <TableCell>
                        <Badge variant={statusVariant[device.status] ?? "outline"} className="gap-1.5">
                          <span className={cn("h-1.5 w-1.5 rounded-full", {
                            "bg-emerald-500": device.status === "online",
                            "bg-red-500": device.status === "offline" || device.status === "error",
                            "bg-amber-500": device.status === "provisioning",
                          })} />
                          {device.status}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {formatDateTime(device.lastSeenAt, "Never")}
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
                  onChange={(e) => setSearch(e.target.value)}
                  className="pl-9 pr-8"
                />
                {search && (
                  <button
                    type="button"
                    onClick={() => setSearch("")}
                    className="absolute right-2 top-1/2 -translate-y-1/2 rounded-sm p-0.5 text-muted-foreground hover:text-foreground"
                  >
                    <X className="h-3.5 w-3.5" />
                    <span className="sr-only">Clear search</span>
                  </button>
                )}
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            {isLoading ? (
              <SkeletonTable rows={8} />
            ) : isError ? (
              <EmptyState
                icon={AlertCircle}
                title="Unable to load devices"
                description="Something went wrong. Please try again."
                action={<Button variant="outline" size="sm" onClick={() => refetch()}>Try again</Button>}
              />
            ) : devices.length === 0 ? (
              <EmptyState
                icon={Search}
                variant="no-results"
                title="No devices found"
                description="No devices match your search. Try a different search term."
                action={
                  <Button variant="outline" size="sm" onClick={() => setSearch("")}>
                    Clear search
                  </Button>
                }
              />
            ) : (
              <>
                <Table aria-label="All devices">
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
                    {devices.map((device, index) => (
                      <TableRow key={device.id} className={cn("cursor-pointer hover:bg-muted/50 transition-colors", index % 2 === 1 && "bg-muted/20")} onClick={() => navigate({ to: "/devices/$deviceId", params: { deviceId: device.id } })}>
                        <TableCell className="font-medium">{device.name}</TableCell>
                        <TableCell className="font-mono text-muted-foreground text-sm">{device.macAddress ?? "—"}</TableCell>
                        <TableCell className="text-muted-foreground">{device.model ?? "—"}</TableCell>
                        <TableCell className="text-muted-foreground">{device.teamName ?? "—"}</TableCell>
                        <TableCell>
                          <Badge variant={statusVariant[device.status] ?? "outline"} className="gap-1.5">
                          <span className={cn("h-1.5 w-1.5 rounded-full", {
                            "bg-emerald-500": device.status === "online",
                            "bg-red-500": device.status === "offline" || device.status === "error",
                            "bg-amber-500": device.status === "provisioning",
                          })} />
                          {device.status}
                        </Badge>
                        </TableCell>
                        <TableCell className="text-muted-foreground">
                          {formatDateTime(device.lastSeenAt, "Never")}
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
