import { Link } from "@tanstack/react-router"
import { useCallback, useMemo, useState } from "react"
import { Download, MoreVertical, Power, RefreshCw, Search, X } from "lucide-react"
import { useQueryClient } from "@tanstack/react-query"
import { DeviceStatusBadge } from "@/components/devices/device-status-badge"
import { Badge } from "@/components/ui/badge"
import { BulkActionBar, createBulkDeleteAction, createExportAction } from "@/components/ui/bulk-action-bar"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { SkeletonTable } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useTableSelection } from "@/hooks/use-table-selection"
import { useDevices, useRebootDevice, useUpdateDevice } from "@/lib/api/hooks/devices"
import { deleteDevice } from "@/lib/generated/api"
import { exportToCsv, type CsvHeader } from "@/lib/csv-export"

const PAGE_SIZE = 20

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

const getId = (d: DeviceItem) => d.id

function formatLastSeen(value: string | null | undefined): string {
  if (!value) return "Never"
  const date = new Date(value)
  return date.toLocaleDateString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })
}

export function DeviceTable() {
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState("")
  const [searchInput, setSearchInput] = useState("")
  const [typeFilter, setTypeFilter] = useState("all")
  const [statusFilter, setStatusFilter] = useState("all")
  const queryClient = useQueryClient()

  const { data, isLoading, isError } = useDevices({
    page,
    pageSize: PAGE_SIZE,
    search: search || undefined,
  })

  // Client-side filtering for type and status (server search handles name)
  const filteredItems: DeviceItem[] = useMemo(() => {
    if (!data) return []
    return data.items.filter((device) => {
      if (typeFilter !== "all" && device.deviceType !== typeFilter) return false
      if (statusFilter !== "all" && device.status !== statusFilter) return false
      return true
    })
  }, [data, typeFilter, statusFilter])

  const selection = useTableSelection(filteredItems, getId)

  const handleSearch = () => {
    setSearch(searchInput)
    setPage(1)
  }

  const clearSearch = () => {
    setSearchInput("")
    setSearch("")
    setPage(1)
  }

  const clearFilters = () => {
    setTypeFilter("all")
    setStatusFilter("all")
    setSearchInput("")
    setSearch("")
    setPage(1)
  }

  const handleExportAll = useCallback(() => {
    if (!filteredItems.length) return
    exportToCsv("devices", csvHeaders, filteredItems)
  }, [filteredItems])

  const handleSelectAllToggle = useCallback(() => {
    if (selection.allSelected) {
      selection.deselectAll()
    } else {
      selection.selectAll()
    }
  }, [selection])

  const bulkActions = useMemo(() => [
    createBulkDeleteAction(
      async (id) => {
        await deleteDevice({ path: { device_id: id } })
      },
      () => queryClient.invalidateQueries({ queryKey: ["devices"] }),
    ),
    createExportAction<DeviceItem>(
      "devices-selected",
      csvHeaders,
      (ids) => filteredItems.filter((d) => ids.includes(d.id)),
    ),
  ], [filteredItems, queryClient])

  if (isLoading) {
    return <SkeletonTable rows={6} />
  }

  if (isError || !data) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Devices</CardTitle>
        </CardHeader>
        <CardContent className="text-muted-foreground">We could not load devices.</CardContent>
      </Card>
    )
  }

  const totalPages = Math.max(1, Math.ceil(data.total / PAGE_SIZE))
  const hasActiveFilters = typeFilter !== "all" || statusFilter !== "all" || search !== ""

  return (
    <>
      <Card>
        <CardHeader className="space-y-4">
          <div className="flex items-center justify-between">
            <CardTitle>Devices</CardTitle>
            <div className="flex items-center gap-2">
              {hasActiveFilters && (
                <Button variant="ghost" size="sm" onClick={clearFilters} className="text-muted-foreground">
                  <X className="mr-1 h-3 w-3" />
                  Clear filters
                </Button>
              )}
              <Button variant="outline" size="sm" onClick={handleExportAll} disabled={filteredItems.length === 0}>
                <Download className="mr-1 h-3.5 w-3.5" />
                Export All
              </Button>
            </div>
          </div>
          <div className="flex flex-col gap-3 sm:flex-row">
            <div className="relative flex-1">
              <Search className="absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search by name..."
                value={searchInput}
                onChange={(e) => setSearchInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleSearch()
                }}
                className="pl-9 pr-8"
              />
              {searchInput && (
                <button
                  type="button"
                  onClick={clearSearch}
                  className="absolute top-1/2 right-3 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                >
                  <X className="h-3 w-3" />
                </button>
              )}
            </div>
            <Select value={typeFilter} onValueChange={(v) => { setTypeFilter(v); setPage(1) }}>
              <SelectTrigger className="w-full sm:w-40">
                <SelectValue placeholder="Type" />
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
              <SelectTrigger className="w-full sm:w-40">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                {statusOptions.map((s) => (
                  <SelectItem key={s.value} value={s.value}>
                    {s.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-10">
                  <Checkbox
                    checked={selection.allSelected}
                    indeterminate={selection.someSelected}
                    onChange={handleSelectAllToggle}
                    aria-label="Select all devices"
                  />
                </TableHead>
                <TableHead>Name</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>MAC Address</TableHead>
                <TableHead>Last Seen</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredItems.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-muted-foreground">
                    {hasActiveFilters ? "No devices match your filters." : "No devices found."}
                  </TableCell>
                </TableRow>
              )}
              {filteredItems.map((device) => (
                <DeviceRow
                  key={device.id}
                  device={device}
                  isSelected={selection.isSelected(device.id)}
                  onToggleSelect={() => selection.toggle(device.id)}
                />
              ))}
            </TableBody>
          </Table>
          <div className="flex items-center justify-between">
            <p className="text-xs text-muted-foreground">
              {hasActiveFilters
                ? `Showing ${filteredItems.length} of ${data.total} devices`
                : `Page ${page} of ${totalPages}`}
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
        </CardContent>
      </Card>

      <BulkActionBar
        selectedCount={selection.selectedCount}
        selectedIds={[...selection.selectedIds]}
        onClearSelection={selection.deselectAll}
        actions={bulkActions}
      />
    </>
  )
}

// ---------------------------------------------------------------------------
// Device Row (with quick actions)
// ---------------------------------------------------------------------------

function DeviceRow({
  device,
  isSelected,
  onToggleSelect,
}: {
  device: DeviceItem
  isSelected: boolean
  onToggleSelect: () => void
}) {
  const rebootMutation = useRebootDevice(device.id)
  const updateMutation = useUpdateDevice(device.id)

  return (
    <TableRow data-state={isSelected ? "selected" : undefined}>
      <TableCell>
        <Checkbox
          checked={isSelected}
          onChange={onToggleSelect}
          aria-label={`Select ${device.name}`}
        />
      </TableCell>
      <TableCell>
        <Link to="/devices/$deviceId" params={{ deviceId: device.id }} className="font-medium hover:underline">
          {device.name}
        </Link>
        {device.isActive === false && (
          <Badge variant="outline" className="ml-2 border-muted-foreground/30 text-muted-foreground text-[10px]">
            Disabled
          </Badge>
        )}
      </TableCell>
      <TableCell>{deviceTypeLabels[device.deviceType] ?? device.deviceType}</TableCell>
      <TableCell>
        <DeviceStatusBadge status={device.status} />
      </TableCell>
      <TableCell className="font-mono text-muted-foreground text-xs">{device.macAddress ?? "—"}</TableCell>
      <TableCell className="text-muted-foreground">{formatLastSeen(device.lastSeenAt)}</TableCell>
      <TableCell className="text-right">
        <div className="flex items-center justify-end gap-1">
          <Button asChild variant="outline" size="sm">
            <Link to="/devices/$deviceId" params={{ deviceId: device.id }}>
              View
            </Link>
          </Button>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
                <MoreVertical className="h-4 w-4" />
                <span className="sr-only">Quick actions</span>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem
                onClick={() => rebootMutation.mutate()}
                disabled={rebootMutation.isPending}
              >
                <RefreshCw className="mr-2 h-4 w-4" />
                Reboot
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                onClick={() => updateMutation.mutate({ isActive: !device.isActive })}
                disabled={updateMutation.isPending}
              >
                <Power className="mr-2 h-4 w-4" />
                {device.isActive ? "Disable" : "Enable"}
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </TableCell>
    </TableRow>
  )
}
