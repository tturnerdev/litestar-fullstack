import { Link, useNavigate } from "@tanstack/react-router"
import { useCallback, useEffect, useMemo, useState } from "react"
import { Columns3, Download, Monitor, MoreVertical, Pencil, Power, RefreshCw, Search, Trash2, X } from "lucide-react"
import { useQueryClient } from "@tanstack/react-query"
import { DeviceStatusBadge } from "@/components/devices/device-status-badge"
import { Badge } from "@/components/ui/badge"
import { BulkActionBar, createBulkDeleteAction, createExportAction } from "@/components/ui/bulk-action-bar"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { DropdownMenu, DropdownMenuCheckboxItem, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { SkeletonTable } from "@/components/ui/skeleton"
import { nextSortDirection, SortableHeader, type SortDirection } from "@/components/ui/sortable-header"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useDebouncedValue } from "@/hooks/use-debounced-value"
import { useDevices, useRebootDevice, useUpdateDevice } from "@/lib/api/hooks/devices"
import { deleteDevice } from "@/lib/generated/api"
import { exportToCsv, type CsvHeader } from "@/lib/csv-export"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"

const PAGE_SIZE = 25

const deviceTypeLabels: Record<string, string> = {
  desk_phone: "Desk Phone",
  softphone: "Softphone",
  ata: "ATA",
  conference: "Conference",
  other: "Other",
}

const deviceTypes = [
  { value: "all", label: "All Types" },
  { value: "desk_phone", label: "Desk Phone" },
  { value: "softphone", label: "Softphone" },
  { value: "ata", label: "ATA" },
  { value: "conference", label: "Conference" },
  { value: "other", label: "Other" },
]

const statusOptions = [
  { value: "all", label: "All Status" },
  { value: "online", label: "Online" },
  { value: "offline", label: "Offline" },
  { value: "ringing", label: "Ringing" },
  { value: "in_use", label: "In Use" },
  { value: "error", label: "Error" },
]

type DeviceItem = {
  id: string
  name: string
  deviceType: string
  status: string
  macAddress?: string | null
  lastSeenAt?: string | null
  isActive?: boolean
}

const csvHeaders: CsvHeader<DeviceItem>[] = [
  { label: "Name", accessor: (d) => d.name },
  { label: "Type", accessor: (d) => deviceTypeLabels[d.deviceType] ?? d.deviceType },
  { label: "Status", accessor: (d) => d.status },
  { label: "MAC Address", accessor: (d) => d.macAddress ?? "" },
  { label: "Last Seen", accessor: (d) => d.lastSeenAt ?? "Never" },
  { label: "Active", accessor: (d) => (d.isActive === false ? "No" : "Yes") },
]

type ColumnKey = "name" | "type" | "status" | "macAddress" | "lastSeen" | "actions"

const defaultColumnVisibility: Record<ColumnKey, boolean> = {
  name: true,
  type: true,
  status: true,
  macAddress: true,
  lastSeen: true,
  actions: true,
}

const columnLabels: Record<ColumnKey, string> = {
  name: "Name",
  type: "Type",
  status: "Status",
  macAddress: "MAC Address",
  lastSeen: "Last Seen",
  actions: "Actions",
}

export function DeviceTable() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  const [search, setSearch] = useState("")
  const debouncedSearch = useDebouncedValue(search)
  const [typeFilter, setTypeFilter] = useState("all")
  const [statusFilter, setStatusFilter] = useState("all")
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<SortDirection>(null)
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [page, setPage] = useState(1)
  const [columnVisibility, setColumnVisibility] = useState(defaultColumnVisibility)

  useEffect(() => {
    setPage(1)
  }, [debouncedSearch])

  const { data, isLoading, isError, refetch } = useDevices({
    page,
    pageSize: PAGE_SIZE,
    search: debouncedSearch || undefined,
    orderBy: sortKey ?? undefined,
    sortOrder: sortDir ?? undefined,
  })

  const devices: DeviceItem[] = useMemo(() => {
    if (!data) return []
    return data.items.filter((device) => {
      if (typeFilter !== "all" && device.deviceType !== typeFilter) return false
      if (statusFilter !== "all" && device.status !== statusFilter) return false
      return true
    })
  }, [data, typeFilter, statusFilter])

  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  const allSelected = devices.length > 0 && devices.every((d) => selectedIds.has(d.id))
  const someSelected = devices.some((d) => selectedIds.has(d.id))

  const toggleAll = useCallback(() => {
    if (allSelected) {
      setSelectedIds(new Set())
    } else {
      setSelectedIds(new Set(devices.map((d) => d.id)))
    }
  }, [allSelected, devices])

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

  const handleSort = useCallback(
    (key: string) => {
      const next = nextSortDirection(sortKey, sortDir, key)
      setSortKey(next.sort)
      setSortDir(next.direction)
    },
    [sortKey, sortDir],
  )

  const toggleColumn = useCallback((key: ColumnKey) => {
    setColumnVisibility((prev) => ({ ...prev, [key]: !prev[key] }))
  }, [])

  const bulkActions = useMemo(
    () => [
      createBulkDeleteAction(
        async (id) => {
          await deleteDevice({ path: { device_id: id } })
        },
        () => {
          queryClient.invalidateQueries({ queryKey: ["devices"] })
          setSelectedIds(new Set())
        },
      ),
      createExportAction<DeviceItem>(
        "devices-selected",
        csvHeaders,
        (ids) => devices.filter((d) => ids.includes(d.id)),
      ),
    ],
    [devices, queryClient],
  )

  const handleExportAll = useCallback(() => {
    if (!devices.length) return
    exportToCsv("devices", csvHeaders, devices)
  }, [devices])

  const handleRowClick = useCallback(
    (deviceId: string) => {
      navigate({ to: "/devices/$deviceId", params: { deviceId } })
    },
    [navigate],
  )

  if (isLoading) {
    return <SkeletonTable rows={6} />
  }

  if (isError) {
    return (
      <EmptyState
        icon={Monitor}
        title="Unable to load devices"
        description="Something went wrong while fetching your devices. Please try again."
        action={
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            Try again
          </Button>
        }
      />
    )
  }

  if (devices.length === 0 && !search && typeFilter === "all" && statusFilter === "all") {
    return (
      <EmptyState
        icon={Monitor}
        title="No devices yet"
        description="Devices will appear here once they are registered. Add your first device to get started."
        action={
          <Button size="sm" asChild>
            <Link to="/devices/new">Add device</Link>
          </Button>
        }
      />
    )
  }

  const hasActiveFilters = search !== "" || typeFilter !== "all" || statusFilter !== "all"

  return (
    <>
      <div className="space-y-4">
        {/* Search & filter bar */}
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
          <div className="relative max-w-md flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search devices..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-10 pr-8"
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
          <Select value={typeFilter} onValueChange={(v) => { setTypeFilter(v); setPage(1) }}>
            <SelectTrigger className="w-full sm:w-[160px]">
              <SelectValue placeholder="All Types" />
            </SelectTrigger>
            <SelectContent>
              {deviceTypes.map((t) => (
                <SelectItem key={t.value} value={t.value}>
                  {t.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={statusFilter} onValueChange={(v) => { setStatusFilter(v); setPage(1) }}>
            <SelectTrigger className="w-full sm:w-[160px]">
              <SelectValue placeholder="All Status" />
            </SelectTrigger>
            <SelectContent>
              {statusOptions.map((s) => (
                <SelectItem key={s.value} value={s.value}>
                  {s.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm">
                <Columns3 className="mr-1 h-3.5 w-3.5" />
                Columns
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-40">
              <DropdownMenuLabel>Toggle columns</DropdownMenuLabel>
              <DropdownMenuSeparator />
              {(Object.keys(columnLabels) as ColumnKey[]).map((key) => (
                <DropdownMenuCheckboxItem
                  key={key}
                  checked={columnVisibility[key]}
                  onCheckedChange={() => toggleColumn(key)}
                >
                  {columnLabels[key]}
                </DropdownMenuCheckboxItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
          <Button variant="outline" size="sm" onClick={handleExportAll} disabled={devices.length === 0}>
            <Download className="mr-2 h-4 w-4" />
            Export
          </Button>
        </div>

        {/* Result count & pagination info */}
        {devices.length > 0 && (
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">
              {total} device{total === 1 ? "" : "s"}
              {hasActiveFilters && " (filtered)"}
            </p>
            <div className="flex items-center gap-3">
              {hasActiveFilters && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="text-xs text-muted-foreground"
                  onClick={() => {
                    setSearch("")
                    setTypeFilter("all")
                    setStatusFilter("all")
                    setPage(1)
                  }}
                >
                  Clear filters
                </Button>
              )}
              {totalPages > 1 && (
                <p className="text-xs text-muted-foreground">
                  Page {page} of {totalPages}
                </p>
              )}
            </div>
          </div>
        )}

        {/* Table */}
        {devices.length > 0 ? (
          <div className="rounded-md border border-border/60 bg-card/80">
            <Table>
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
                  {columnVisibility.name && (
                    <SortableHeader
                      label="Name"
                      sortKey="name"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                  )}
                  {columnVisibility.type && (
                    <SortableHeader
                      label="Type"
                      sortKey="device_type"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                  )}
                  {columnVisibility.status && (
                    <SortableHeader
                      label="Status"
                      sortKey="status"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                  )}
                  {columnVisibility.macAddress && (
                    <SortableHeader
                      label="MAC Address"
                      sortKey="mac_address"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                  )}
                  {columnVisibility.lastSeen && (
                    <SortableHeader
                      label="Last Seen"
                      sortKey="last_seen_at"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                  )}
                  {columnVisibility.actions && <TableHead className="w-16 text-right">Actions</TableHead>}
                </TableRow>
              </TableHeader>
              <TableBody>
                {devices.map((device, index) => (
                  <DeviceRow
                    key={device.id}
                    device={device}
                    index={index}
                    selected={selectedIds.has(device.id)}
                    onToggle={() => toggleOne(device.id)}
                    onRowClick={() => handleRowClick(device.id)}
                    columnVisibility={columnVisibility}
                  />
                ))}
              </TableBody>
            </Table>
          </div>
        ) : (
          <EmptyState
            icon={Monitor}
            variant="no-results"
            title="No results found"
            description={`No devices match ${search ? `"${search}"` : "the selected filters"}. Try adjusting your search or filter criteria.`}
            action={
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setSearch("")
                  setTypeFilter("all")
                  setStatusFilter("all")
                }}
              >
                Clear filters
              </Button>
            }
          />
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-end gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
            >
              Previous
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
            >
              Next
            </Button>
          </div>
        )}
      </div>

      {/* Bulk action bar */}
      <BulkActionBar
        selectedCount={selectedIds.size}
        selectedIds={Array.from(selectedIds)}
        onClearSelection={() => setSelectedIds(new Set())}
        actions={bulkActions}
      />
    </>
  )
}

// ---------------------------------------------------------------------------
// Device Row
// ---------------------------------------------------------------------------

function DeviceRow({
  device,
  index,
  selected,
  onToggle,
  onRowClick,
  columnVisibility,
}: {
  device: DeviceItem
  index: number
  selected: boolean
  onToggle: () => void
  onRowClick: () => void
  columnVisibility: Record<ColumnKey, boolean>
}) {
  const rebootMutation = useRebootDevice(device.id)
  const updateMutation = useUpdateDevice(device.id)

  return (
    <TableRow
      data-state={selected ? "selected" : undefined}
      className={`cursor-pointer hover:bg-muted/50 transition-colors ${index % 2 === 1 ? "bg-muted/20" : ""}`}
      onClick={(e) => {
        const target = e.target as HTMLElement
        if (target.closest("[role=checkbox]") || target.closest("[data-slot=dropdown]") || target.closest("button") || target.closest("a")) {
          return
        }
        onRowClick()
      }}
    >
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
      {columnVisibility.name && (
        <TableCell>
          <Link
            to="/devices/$deviceId"
            params={{ deviceId: device.id }}
            className="font-medium hover:underline"
            onClick={(e) => e.stopPropagation()}
          >
            {device.name}
          </Link>
          {device.isActive === false && (
            <Badge variant="outline" className="ml-2 border-muted-foreground/30 text-muted-foreground text-[10px]">
              Disabled
            </Badge>
          )}
        </TableCell>
      )}
      {columnVisibility.type && (
        <TableCell>{deviceTypeLabels[device.deviceType] ?? device.deviceType}</TableCell>
      )}
      {columnVisibility.status && (
        <TableCell>
          <DeviceStatusBadge status={device.status} />
        </TableCell>
      )}
      {columnVisibility.macAddress && (
        <TableCell className="font-mono text-muted-foreground text-xs">{device.macAddress ?? "—"}</TableCell>
      )}
      {columnVisibility.lastSeen && (
        <TableCell className="text-muted-foreground">
          {device.lastSeenAt ? (
            <Tooltip>
              <TooltipTrigger asChild>
                <span>{formatRelativeTimeShort(device.lastSeenAt)}</span>
              </TooltipTrigger>
              <TooltipContent>{formatDateTime(device.lastSeenAt)}</TooltipContent>
            </Tooltip>
          ) : (
            "Never"
          )}
        </TableCell>
      )}
      {columnVisibility.actions && (
        <TableCell className="text-right">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                size="sm"
                className="h-8 w-8 p-0"
                data-slot="dropdown"
                onClick={(e) => e.stopPropagation()}
              >
                <MoreVertical className="h-4 w-4" />
                <span className="sr-only">Actions for {device.name}</span>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem asChild>
                <Link to="/devices/$deviceId" params={{ deviceId: device.id }}>
                  <Monitor className="mr-2 h-4 w-4" />
                  View details
                </Link>
              </DropdownMenuItem>
              <DropdownMenuItem asChild>
                <Link to="/devices/$deviceId" params={{ deviceId: device.id }} search={{ edit: true }}>
                  <Pencil className="mr-2 h-4 w-4" />
                  Edit
                </Link>
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                onClick={() => rebootMutation.mutate()}
                disabled={rebootMutation.isPending}
              >
                <RefreshCw className="mr-2 h-4 w-4" />
                Reboot
              </DropdownMenuItem>
              <DropdownMenuItem
                onClick={() => updateMutation.mutate({ isActive: !device.isActive })}
                disabled={updateMutation.isPending}
              >
                <Power className="mr-2 h-4 w-4" />
                {device.isActive ? "Disable" : "Enable"}
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                className="text-destructive focus:text-destructive"
                onClick={() => {
                  if (confirm(`Delete ${device.name}?`)) {
                    deleteDevice({ path: { device_id: device.id } })
                  }
                }}
              >
                <Trash2 className="mr-2 h-4 w-4" />
                Delete
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </TableCell>
      )}
    </TableRow>
  )
}
