import { createFileRoute, Link } from "@tanstack/react-router"
import { useCallback, useMemo, useState } from "react"
import {
  AlertCircle,
  Download,
  Home,
  Loader2,
  Monitor,
  Plus,
  RefreshCw,
  RotateCcw,
  Search,
  X,
} from "lucide-react"
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
import { BulkActionBar, createBulkDeleteAction, createExportAction } from "@/components/ui/bulk-action-bar"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { EmptyState } from "@/components/ui/empty-state"
import { FilterDropdown, type FilterOption } from "@/components/ui/filter-dropdown"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonCard } from "@/components/ui/skeleton"
import { nextSortDirection, SortableHeader, type SortDirection } from "@/components/ui/sortable-header"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import {
  useDevices,
  useDeleteDevice,
  useRebootDevice,
  useReprovisionDevice,
} from "@/lib/api/hooks/devices"
import { deleteDevice, type Device } from "@/lib/generated/api"
import { exportToCsv, type CsvHeader } from "@/lib/csv-export"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"

export const Route = createFileRoute("/_app/devices/")({
  component: DevicesPage,
})

// -- Constants ----------------------------------------------------------------

const deviceTypeLabels: Record<string, string> = {
  desk_phone: "Desk Phone",
  softphone: "Softphone",
  ata: "ATA",
  conference: "Conference",
  gateway: "Gateway",
  other: "Other",
}

const deviceTypeOptions: FilterOption[] = [
  { value: "desk_phone", label: "Desk Phone" },
  { value: "softphone", label: "Softphone" },
  { value: "ata", label: "ATA" },
  { value: "conference", label: "Conference" },
  { value: "gateway", label: "Gateway" },
  { value: "other", label: "Other" },
]

const statusOptions: FilterOption[] = [
  { value: "online", label: "Online" },
  { value: "offline", label: "Offline" },
  { value: "ringing", label: "Ringing" },
  { value: "in_use", label: "In Use" },
  { value: "provisioning", label: "Provisioning" },
  { value: "error", label: "Error" },
]

const csvHeaders: CsvHeader<Device>[] = [
  { label: "Name", accessor: (d) => d.name },
  { label: "Type", accessor: (d) => deviceTypeLabels[d.deviceType] ?? d.deviceType },
  { label: "Status", accessor: (d) => d.status },
  { label: "MAC Address", accessor: (d) => d.macAddress ?? "" },
  { label: "Model", accessor: (d) => d.deviceModel ?? "" },
  { label: "IP Address", accessor: (d) => d.ipAddress ?? "" },
  { label: "Last Seen", accessor: (d) => d.lastSeenAt ?? "Never" },
  { label: "Active", accessor: (d) => (d.isActive === false ? "No" : "Yes") },
]

// -- Helpers ------------------------------------------------------------------


// -- Per-row action buttons ---------------------------------------------------

function RebootButton({ deviceId }: { deviceId: string }) {
  const rebootMutation = useRebootDevice(deviceId)
  const isPending = rebootMutation.isPending

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          variant="ghost"
          size="sm"
          className="h-7 gap-1.5 px-2 text-xs"
          disabled={isPending}
          onClick={(e) => {
            e.preventDefault()
            e.stopPropagation()
            rebootMutation.mutate()
          }}
        >
          {isPending ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : (
            <RefreshCw className="h-3.5 w-3.5" />
          )}
          Reboot
        </Button>
      </TooltipTrigger>
      <TooltipContent>Send reboot command to this device</TooltipContent>
    </Tooltip>
  )
}

function ReprovisionButton({ deviceId }: { deviceId: string }) {
  const reprovisionMutation = useReprovisionDevice(deviceId)
  const isPending = reprovisionMutation.isPending

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          variant="ghost"
          size="sm"
          className="h-7 gap-1.5 px-2 text-xs"
          disabled={isPending}
          onClick={(e) => {
            e.preventDefault()
            e.stopPropagation()
            reprovisionMutation.mutate()
          }}
        >
          {isPending ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : (
            <RotateCcw className="h-3.5 w-3.5" />
          )}
          Reprovision
        </Button>
      </TooltipTrigger>
      <TooltipContent>Regenerate config and push to device</TooltipContent>
    </Tooltip>
  )
}

// -- Main page ----------------------------------------------------------------

function DevicesPage() {
  // Filter & search state
  const [search, setSearch] = useState("")
  const [typeFilter, setTypeFilter] = useState<string[]>([])
  const [statusFilter, setStatusFilter] = useState<string[]>([])

  // Sort state
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<SortDirection>(null)

  // Selection state
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())

  // Queries & mutations
  const { data, isLoading, isError } = useDevices({
    search: search || undefined,
    orderBy: sortKey ?? undefined,
    sortOrder: sortDir ?? undefined,
  })
  const deleteMutation = useDeleteDevice()

  // Apply client-side type & status filters
  const filteredItems = useMemo(() => {
    if (!data?.items) return []
    return data.items.filter((device) => {
      if (typeFilter.length > 0 && !typeFilter.includes(device.deviceType)) return false
      if (statusFilter.length > 0 && !statusFilter.includes(device.status)) return false
      return true
    })
  }, [data?.items, typeFilter, statusFilter])

  // Selection helpers
  const allVisibleIds = useMemo(() => filteredItems.map((d) => d.id), [filteredItems])
  const allSelected = filteredItems.length > 0 && filteredItems.every((d) => selectedIds.has(d.id))
  const someSelected = filteredItems.some((d) => selectedIds.has(d.id))

  const toggleAll = useCallback(() => {
    if (allSelected) {
      setSelectedIds(new Set())
    } else {
      setSelectedIds(new Set(allVisibleIds))
    }
  }, [allSelected, allVisibleIds])

  const toggleOne = useCallback((id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) {
        next.delete(id)
      } else {
        next.add(id)
      }
      return next
    })
  }, [])

  // Sort handler
  const handleSort = useCallback(
    (key: string) => {
      const next = nextSortDirection(sortKey, sortDir, key)
      setSortKey(next.sort)
      setSortDir(next.direction)
    },
    [sortKey, sortDir],
  )

  // Bulk actions
  const bulkActions = useMemo(
    () => [
      createBulkDeleteAction(
        async (id) => {
          await deleteDevice({ path: { device_id: id } })
        },
        () => {
          setSelectedIds(new Set())
          deleteMutation.reset()
        },
      ),
      createExportAction<Device>(
        "devices-selected",
        csvHeaders,
        (ids) => filteredItems.filter((d) => ids.includes(d.id)),
      ),
    ],
    [filteredItems, deleteMutation],
  )

  // Export all visible
  const handleExportAll = useCallback(() => {
    if (!filteredItems.length) return
    exportToCsv("devices", csvHeaders, filteredItems)
  }, [filteredItems])

  // Active filter count for display
  const activeFilterCount = typeFilter.length + statusFilter.length

  const hasData = filteredItems.length > 0
  const hasAnyDevices = (data?.items.length ?? 0) > 0

  const breadcrumbs = (
    <Breadcrumb>
      <BreadcrumbList>
        <BreadcrumbItem>
          <BreadcrumbLink asChild>
            <Link to="/">
              <Home className="h-3.5 w-3.5" />
            </Link>
          </BreadcrumbLink>
        </BreadcrumbItem>
        <BreadcrumbSeparator />
        <BreadcrumbItem>
          <BreadcrumbPage>Devices</BreadcrumbPage>
        </BreadcrumbItem>
      </BreadcrumbList>
    </Breadcrumb>
  )

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Workspace"
        title="Devices"
        description="Manage your phones, softphones, and other SIP devices."
        breadcrumbs={breadcrumbs}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={handleExportAll} disabled={!hasData}>
              <Download className="mr-2 h-4 w-4" />
              Export
            </Button>
            <Button size="sm" asChild>
              <Link to="/devices/new">
                <Plus className="mr-2 h-4 w-4" /> Add device
              </Link>
            </Button>
          </div>
        }
      />

      {/* Search & filters */}
      <PageSection>
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative max-w-sm flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search by name, MAC address, or model..."
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
          <FilterDropdown
            label="Type"
            options={deviceTypeOptions}
            selected={typeFilter}
            onChange={setTypeFilter}
          />
          <FilterDropdown
            label="Status"
            options={statusOptions}
            selected={statusFilter}
            onChange={setStatusFilter}
          />
          {activeFilterCount > 0 && (
            <Button
              variant="ghost"
              size="sm"
              className="text-xs text-muted-foreground"
              onClick={() => {
                setTypeFilter([])
                setStatusFilter([])
              }}
            >
              Clear all filters
            </Button>
          )}
        </div>
      </PageSection>

      {/* Content */}
      <PageSection delay={0.1}>
        {isLoading ? (
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            {Array.from({ length: 3 }).map((_, i) => (
              <SkeletonCard key={i} />
            ))}
          </div>
        ) : isError ? (
          <EmptyState
            icon={AlertCircle}
            title="Unable to load devices"
            description="Something went wrong while fetching your devices. Please try refreshing the page."
            action={
              <Button variant="outline" size="sm" onClick={() => window.location.reload()}>
                Refresh page
              </Button>
            }
          />
        ) : !hasAnyDevices && !search ? (
          <EmptyState
            icon={Monitor}
            title="No devices yet"
            description="Add your first device to start managing phones, ATAs, and other SIP endpoints."
            action={
              <Button size="sm" asChild>
                <Link to="/devices/new">
                  <Plus className="mr-2 h-4 w-4" /> Add device
                </Link>
              </Button>
            }
          />
        ) : !hasData ? (
          <EmptyState
            icon={Monitor}
            variant="no-results"
            title="No results found"
            description="No devices match your current filters. Try adjusting your search or filters."
            action={
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setSearch("")
                  setTypeFilter([])
                  setStatusFilter([])
                }}
              >
                Clear all filters
              </Button>
            }
          />
        ) : (
          <div className="space-y-3">
            {/* Result count */}
            <div className="flex items-center justify-between">
              <p className="text-xs text-muted-foreground">
                {filteredItems.length === (data?.items.length ?? 0)
                  ? `${filteredItems.length} device${filteredItems.length !== 1 ? "s" : ""}`
                  : `${filteredItems.length} of ${data?.items.length ?? 0} devices`}
              </p>
            </div>

            {/* Table */}
            <div className="rounded-md border border-border/60 bg-card/80">
              <Table aria-label="Devices">
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-10">
                      <Checkbox
                        checked={allSelected}
                        indeterminate={someSelected && !allSelected}
                        onChange={toggleAll}
                        aria-label="Select all devices"
                      />
                    </TableHead>
                    <SortableHeader
                      label="Name"
                      sortKey="name"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <SortableHeader
                      label="Type"
                      sortKey="device_type"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <SortableHeader
                      label="Status"
                      sortKey="status"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <TableHead>MAC Address</TableHead>
                    <SortableHeader
                      label="IP Address"
                      sortKey="ip_address"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <SortableHeader
                      label="Last Seen"
                      sortKey="last_seen_at"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <TableHead className="w-40 text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredItems.map((device) => (
                    <DeviceRow
                      key={device.id}
                      device={device}
                      selected={selectedIds.has(device.id)}
                      onToggle={() => toggleOne(device.id)}
                    />
                  ))}
                </TableBody>
              </Table>
            </div>
          </div>
        )}
      </PageSection>

      {/* Bulk action bar */}
      <BulkActionBar
        selectedCount={selectedIds.size}
        selectedIds={Array.from(selectedIds)}
        onClearSelection={() => setSelectedIds(new Set())}
        actions={bulkActions}
      />
    </PageContainer>
  )
}

// -- Table row ----------------------------------------------------------------

function DeviceRow({
  device,
  selected,
  onToggle,
}: {
  device: Device
  selected: boolean
  onToggle: () => void
}) {
  return (
    <TableRow data-state={selected ? "selected" : undefined}>
      <TableCell>
        <Checkbox
          checked={selected}
          onChange={(e) => {
            e.stopPropagation()
            onToggle()
          }}
          aria-label={`Select ${device.name}`}
        />
      </TableCell>
      <TableCell>
        <Link
          to="/devices/$deviceId"
          params={{ deviceId: device.id }}
          className="group flex flex-col gap-0.5"
        >
          <span className="font-medium group-hover:underline">{device.name}</span>
          {device.deviceModel && (
            <span className="text-xs text-muted-foreground">
              {device.manufacturer ? `${device.manufacturer} ` : ""}
              {device.deviceModel}
            </span>
          )}
        </Link>
        {device.isActive === false && (
          <Badge variant="outline" className="ml-2 border-muted-foreground/30 text-muted-foreground text-[10px]">
            Disabled
          </Badge>
        )}
      </TableCell>
      <TableCell>
        <Badge variant="outline">
          {deviceTypeLabels[device.deviceType] ?? device.deviceType}
        </Badge>
      </TableCell>
      <TableCell>
        <DeviceStatusBadge status={device.status} />
      </TableCell>
      <TableCell>
        {device.macAddress ? (
          <span className="font-mono text-xs text-muted-foreground">{device.macAddress}</span>
        ) : (
          <span className="text-xs text-muted-foreground">--</span>
        )}
      </TableCell>
      <TableCell>
        {device.ipAddress ? (
          <span className="font-mono text-xs text-muted-foreground">{device.ipAddress}</span>
        ) : (
          <span className="text-xs text-muted-foreground">--</span>
        )}
      </TableCell>
      <TableCell>
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="cursor-default text-xs text-muted-foreground">
              {formatRelativeTimeShort(device.lastSeenAt)}
            </span>
          </TooltipTrigger>
          <TooltipContent>{formatDateTime(device.lastSeenAt)}</TooltipContent>
        </Tooltip>
      </TableCell>
      <TableCell className="text-right">
        <div className="flex items-center justify-end gap-0.5">
          <RebootButton deviceId={device.id} />
          <ReprovisionButton deviceId={device.id} />
        </div>
      </TableCell>
    </TableRow>
  )
}
