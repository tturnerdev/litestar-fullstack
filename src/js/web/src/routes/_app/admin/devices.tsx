import { createFileRoute } from "@tanstack/react-router"
import { AlertCircle, Download, HardDrive, Monitor, Search, Signal, SignalZero, SlidersHorizontal, Wifi, X } from "lucide-react"
import { useCallback, useEffect, useMemo, useState } from "react"
import { AdminBreadcrumbs } from "@/components/admin/admin-breadcrumbs"
import { AdminNav } from "@/components/admin/admin-nav"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { DataFreshness } from "@/components/ui/data-freshness"
import { DropdownMenu, DropdownMenuCheckboxItem, DropdownMenuContent, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { Skeleton, SkeletonTable } from "@/components/ui/skeleton"
import { nextSortDirection, SortableHeader, type SortDirection } from "@/components/ui/sortable-header"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useDebouncedValue } from "@/hooks/use-debounced-value"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { useAdminDeviceStats, useAdminDevices } from "@/lib/api/hooks/admin"
import { type CsvHeader, exportToCsv } from "@/lib/csv-export"
import { formatDateTime } from "@/lib/date-utils"
import type { AdminDeviceSummary } from "@/lib/generated/api/types.gen"
import { cn } from "@/lib/utils"

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
  },
  {
    key: "active" as const,
    label: "Active Devices",
    subtitle: "Currently provisioned",
    icon: Monitor,
    color: "text-emerald-600 dark:text-emerald-400",
    bg: "bg-emerald-500/10",
    hoverBg: "group-hover:bg-emerald-500",
  },
  {
    key: "online" as const,
    label: "Online",
    subtitle: "Connected right now",
    icon: Wifi,
    color: "text-green-600 dark:text-green-400",
    bg: "bg-green-500/10",
    hoverBg: "group-hover:bg-green-500",
  },
  {
    key: "offline" as const,
    label: "Offline",
    subtitle: "Not responding",
    icon: SignalZero,
    color: "text-red-600 dark:text-red-400",
    bg: "bg-red-500/10",
    hoverBg: "group-hover:bg-red-500",
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

// -- Column visibility --------------------------------------------------------

const COLUMN_VISIBILITY_KEY = "admin-devices-columns"

const TOGGLEABLE_COLUMNS = [
  { key: "macAddress", label: "MAC Address" },
  { key: "model", label: "Model" },
  { key: "team", label: "Team" },
  { key: "status", label: "Status" },
  { key: "lastSeen", label: "Last Seen" },
] as const

type ColumnVisibility = Record<string, boolean>

function loadColumnVisibility(): ColumnVisibility {
  try {
    return JSON.parse(localStorage.getItem(COLUMN_VISIBILITY_KEY) ?? "{}")
  } catch {
    return {}
  }
}

// -----------------------------------------------------------------------------

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
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState("")
  const debouncedSearch = useDebouncedValue(search)

  // Sort state
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<SortDirection>(null)

  const handleSort = useCallback(
    (key: string) => {
      const next = nextSortDirection(sortKey, sortDir, key)
      setSortKey(next.sort)
      setSortDir(next.direction)
    },
    [sortKey, sortDir],
  )

  // Column visibility
  const [columnVisibility, setColumnVisibility] = useState<ColumnVisibility>(loadColumnVisibility)
  const isColumnVisible = useCallback((col: string) => columnVisibility[col] !== false, [columnVisibility])
  const toggleColumn = useCallback((col: string) => {
    setColumnVisibility((prev) => {
      const updated = { ...prev, [col]: prev[col] === false }
      localStorage.setItem(COLUMN_VISIBILITY_KEY, JSON.stringify(updated))
      return updated
    })
  }, [])

  // biome-ignore lint/correctness/useExhaustiveDependencies: intentional — reset page when search changes
  useEffect(() => {
    setPage(1)
  }, [debouncedSearch])

  const { data: stats, isLoading: statsLoading, isError: statsError, refetch: refetchStats } = useAdminDeviceStats()
  const { data, isLoading, isError, refetch, dataUpdatedAt, isRefetching } = useAdminDevices(page, PAGE_SIZE, debouncedSearch || undefined)

  const devices = data?.items ?? []
  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  // Client-side sorting for the "All Devices" table
  const sortedDevices = useMemo(() => {
    if (!sortKey || !sortDir) return devices
    const sorted = [...devices]
    sorted.sort((a, b) => {
      switch (sortKey) {
        case "name": {
          const aVal = a.name.toLowerCase()
          const bVal = b.name.toLowerCase()
          return sortDir === "asc" ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal)
        }
        case "macAddress": {
          const aVal = (a.macAddress ?? "").toLowerCase()
          const bVal = (b.macAddress ?? "").toLowerCase()
          return sortDir === "asc" ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal)
        }
        case "model": {
          const aVal = (a.model ?? "").toLowerCase()
          const bVal = (b.model ?? "").toLowerCase()
          return sortDir === "asc" ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal)
        }
        case "team": {
          const aVal = (a.teamName ?? "").toLowerCase()
          const bVal = (b.teamName ?? "").toLowerCase()
          return sortDir === "asc" ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal)
        }
        case "status": {
          const aVal = a.status.toLowerCase()
          const bVal = b.status.toLowerCase()
          return sortDir === "asc" ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal)
        }
        case "lastSeen": {
          const aVal = a.lastSeenAt ?? ""
          const bVal = b.lastSeenAt ?? ""
          if (aVal < bVal) return sortDir === "asc" ? -1 : 1
          if (aVal > bVal) return sortDir === "asc" ? 1 : -1
          return 0
        }
        default:
          return 0
      }
    })
    return sorted
  }, [devices, sortKey, sortDir])

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
          <div className="flex items-center gap-2">
            <DataFreshness dataUpdatedAt={dataUpdatedAt} onRefresh={() => refetch()} isRefreshing={isRefetching} />
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm">
                  <SlidersHorizontal className="mr-1.5 h-3.5 w-3.5" />
                  Columns
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-44">
                <DropdownMenuLabel>Toggle columns</DropdownMenuLabel>
                <DropdownMenuSeparator />
                {TOGGLEABLE_COLUMNS.map((col) => (
                  <DropdownMenuCheckboxItem key={col.key} checked={isColumnVisible(col.key)} onCheckedChange={() => toggleColumn(col.key)}>
                    {col.label}
                  </DropdownMenuCheckboxItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
            <Button variant="outline" size="sm" onClick={handleExport} disabled={!devices.length}>
              <Download className="mr-2 h-4 w-4" />
              Export
            </Button>
          </div>
        }
      />
      <AdminNav />

      {/* Stat cards */}
      <PageSection>
        <SectionErrorBoundary name="Device Statistics">
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
                  action={
                    <Button variant="outline" size="sm" onClick={() => refetchStats()}>
                      Try again
                    </Button>
                  }
                />
              </CardContent>
            </Card>
          ) : (
            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              {statConfig.map((stat) => {
                const Icon = stat.icon
                const value = stats?.[stat.key] ?? 0
                return (
                  <Card key={stat.key} className="transition-all duration-200 hover:shadow-md hover:border-primary/30 hover:-translate-y-0.5">
                    <CardHeader className="flex flex-row items-center justify-between pb-2">
                      <CardTitle className="text-sm font-medium text-muted-foreground">{stat.label}</CardTitle>
                      <div className={`flex h-9 w-9 items-center justify-center rounded-lg ${stat.bg} ${stat.color}`}>
                        <Icon className="h-4 w-4" />
                      </div>
                    </CardHeader>
                    <CardContent>
                      <span className="text-3xl font-semibold tracking-tight">{value}</span>
                      <p className="mt-1.5 text-xs text-muted-foreground">{stat.subtitle}</p>
                    </CardContent>
                  </Card>
                )
              })}
            </div>
          )}
        </SectionErrorBoundary>
      </PageSection>

      {/* Recent devices */}
      <PageSection delay={0.1}>
        <SectionErrorBoundary name="Recent Devices">
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
                  action={
                    <Button variant="outline" size="sm" onClick={() => refetch()}>
                      Try again
                    </Button>
                  }
                />
              ) : recentDevices.length === 0 ? (
                <EmptyState icon={HardDrive} title="No recent devices" description="Devices will appear here once registered." />
              ) : (
                <div className="overflow-x-auto">
                  <Table aria-label="Recent devices" aria-busy={isLoading || isRefetching}>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Name</TableHead>
                        {isColumnVisible("macAddress") && <TableHead>MAC Address</TableHead>}
                        {isColumnVisible("model") && <TableHead>Model</TableHead>}
                        {isColumnVisible("team") && <TableHead>Team</TableHead>}
                        {isColumnVisible("status") && <TableHead>Status</TableHead>}
                        {isColumnVisible("lastSeen") && <TableHead>Last Seen</TableHead>}
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {recentDevices.map((device, index) => (
                        <TableRow key={device.id} className={cn("cursor-pointer hover:bg-muted/50 transition-colors", index % 2 === 1 && "bg-muted/20")}>
                          <TableCell className="font-medium">{device.name}</TableCell>
                          {isColumnVisible("macAddress") && <TableCell className="font-mono text-muted-foreground text-sm">{device.macAddress ?? "—"}</TableCell>}
                          {isColumnVisible("model") && <TableCell className="text-muted-foreground">{device.model ?? "—"}</TableCell>}
                          {isColumnVisible("team") && <TableCell className="text-muted-foreground">{device.teamName ?? "—"}</TableCell>}
                          {isColumnVisible("status") && (
                            <TableCell>
                              <Badge variant={statusVariant[device.status] ?? "outline"} className="gap-1.5">
                                <span
                                  className={cn("h-1.5 w-1.5 rounded-full", {
                                    "bg-emerald-500": device.status === "online",
                                    "bg-red-500": device.status === "offline" || device.status === "error",
                                    "bg-amber-500": device.status === "provisioning",
                                  })}
                                />
                                {device.status}
                              </Badge>
                            </TableCell>
                          )}
                          {isColumnVisible("lastSeen") && <TableCell className="text-muted-foreground">{formatDateTime(device.lastSeenAt, "Never")}</TableCell>}
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

      {/* Full device list */}
      <PageSection delay={0.2}>
        <SectionErrorBoundary name="All Devices">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between gap-4">
                <div className="flex items-center gap-3">
                  <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-violet-500/10">
                    <HardDrive className="h-4 w-4 text-violet-600 dark:text-violet-400" />
                  </div>
                  <div>
                    <CardTitle>All Devices</CardTitle>
                    <CardDescription>
                      {total} device{total !== 1 ? "s" : ""} total
                    </CardDescription>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <div className="relative max-w-sm">
                    <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                    <Input placeholder="Search devices..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-9 pr-8" />
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
                  <Button variant="outline" size="sm" onClick={handleExport} disabled={!devices.length}>
                    <Download className="mr-2 h-4 w-4" />
                    Export
                  </Button>
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
                  action={
                    <Button variant="outline" size="sm" onClick={() => refetch()}>
                      Try again
                    </Button>
                  }
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
                  <div className="overflow-x-auto">
                    <Table aria-label="All devices" aria-busy={isLoading || isRefetching}>
                      <TableHeader>
                        <TableRow>
                          <SortableHeader label="Name" sortKey="name" currentSort={sortKey} currentDirection={sortDir} onSort={handleSort} />
                          {isColumnVisible("macAddress") && (
                            <SortableHeader label="MAC Address" sortKey="macAddress" currentSort={sortKey} currentDirection={sortDir} onSort={handleSort} />
                          )}
                          {isColumnVisible("model") && <SortableHeader label="Model" sortKey="model" currentSort={sortKey} currentDirection={sortDir} onSort={handleSort} />}
                          {isColumnVisible("team") && <SortableHeader label="Team" sortKey="team" currentSort={sortKey} currentDirection={sortDir} onSort={handleSort} />}
                          {isColumnVisible("status") && <SortableHeader label="Status" sortKey="status" currentSort={sortKey} currentDirection={sortDir} onSort={handleSort} />}
                          {isColumnVisible("lastSeen") && (
                            <SortableHeader label="Last Seen" sortKey="lastSeen" currentSort={sortKey} currentDirection={sortDir} onSort={handleSort} />
                          )}
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {sortedDevices.map((device, index) => (
                          <TableRow key={device.id} className={cn("cursor-pointer hover:bg-muted/50 transition-colors", index % 2 === 1 && "bg-muted/20")}>
                            <TableCell className="font-medium">{device.name}</TableCell>
                            {isColumnVisible("macAddress") && <TableCell className="font-mono text-muted-foreground text-sm">{device.macAddress ?? "—"}</TableCell>}
                            {isColumnVisible("model") && <TableCell className="text-muted-foreground">{device.model ?? "—"}</TableCell>}
                            {isColumnVisible("team") && <TableCell className="text-muted-foreground">{device.teamName ?? "—"}</TableCell>}
                            {isColumnVisible("status") && (
                              <TableCell>
                                <Badge variant={statusVariant[device.status] ?? "outline"} className="gap-1.5">
                                  <span
                                    className={cn("h-1.5 w-1.5 rounded-full", {
                                      "bg-emerald-500": device.status === "online",
                                      "bg-red-500": device.status === "offline" || device.status === "error",
                                      "bg-amber-500": device.status === "provisioning",
                                    })}
                                  />
                                  {device.status}
                                </Badge>
                              </TableCell>
                            )}
                            {isColumnVisible("lastSeen") && <TableCell className="text-muted-foreground">{formatDateTime(device.lastSeenAt, "Never")}</TableCell>}
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
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
        </SectionErrorBoundary>
      </PageSection>
    </PageContainer>
  )
}
