import {
  AlertCircle,
  Calendar,
  ChevronDown,
  ChevronRight,
  Clock,
  Download,
  FileSpreadsheet,
  FileText,
  Globe,
  Loader2,
  Monitor,
  Search,
  User,
  X,
} from "lucide-react"
import { Fragment, useCallback, useMemo, useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { EmptyState } from "@/components/ui/empty-state"
import { FilterDropdown, type FilterOption } from "@/components/ui/filter-dropdown"
import { Input } from "@/components/ui/input"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { SkeletonTable } from "@/components/ui/skeleton"
import {
  nextSortDirection,
  SortableHeader,
  type SortDirection,
} from "@/components/ui/sortable-header"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useAdminAuditLogs, useAdminAuditLogsExport } from "@/lib/api/hooks/admin"
import type { AuditLogEntry } from "@/lib/generated/api"

// ── Constants ──────────────────────────────────────────────────────────────

const PAGE_SIZE = 50

/** Flat list of all known action types for the FilterDropdown. */
const ACTION_FILTER_OPTIONS: FilterOption[] = [
  // Account
  { value: "account.created", label: "Account Created" },
  { value: "account.updated", label: "Account Updated" },
  { value: "account.deleted", label: "Account Deleted" },
  { value: "login.success", label: "Login Success" },
  { value: "login.failed", label: "Login Failed" },
  { value: "password.changed", label: "Password Changed" },
  { value: "mfa.enabled", label: "MFA Enabled" },
  { value: "mfa.disabled", label: "MFA Disabled" },
  // Team
  { value: "team.created", label: "Team Created" },
  { value: "team.updated", label: "Team Updated" },
  { value: "team.deleted", label: "Team Deleted" },
  { value: "team.member_added", label: "Member Added" },
  { value: "team.member_removed", label: "Member Removed" },
  { value: "team.invite_sent", label: "Invite Sent" },
  // User
  { value: "user.created", label: "User Created" },
  { value: "user.updated", label: "User Updated" },
  { value: "user.deleted", label: "User Deleted" },
  { value: "user.role_changed", label: "Role Changed" },
  // Device
  { value: "device.created", label: "Device Created" },
  { value: "device.updated", label: "Device Updated" },
  { value: "device.deleted", label: "Device Deleted" },
  // Voice
  { value: "extension.created", label: "Extension Created" },
  { value: "extension.updated", label: "Extension Updated" },
  { value: "extension.deleted", label: "Extension Deleted" },
  { value: "phone_number.created", label: "Phone # Created" },
  { value: "phone_number.updated", label: "Phone # Updated" },
  { value: "phone_number.deleted", label: "Phone # Deleted" },
  // System
  { value: "system.config_changed", label: "Config Changed" },
  { value: "system.maintenance", label: "Maintenance" },
]

/** Target / resource type options. */
const TARGET_TYPE_OPTIONS: FilterOption[] = [
  { value: "user", label: "User" },
  { value: "team", label: "Team" },
  { value: "device", label: "Device" },
  { value: "extension", label: "Extension" },
  { value: "phone_number", label: "Phone Number" },
  { value: "role", label: "Role" },
  { value: "organization", label: "Organization" },
  { value: "location", label: "Location" },
  { value: "connection", label: "Connection" },
  { value: "fax_number", label: "Fax Number" },
  { value: "ticket", label: "Ticket" },
]

/** Date preset definitions. */
const DATE_PRESETS = [
  { label: "Today", days: 0 },
  { label: "Last 7 days", days: 7 },
  { label: "Last 30 days", days: 30 },
  { label: "Last 90 days", days: 90 },
  { label: "All time", days: -1 },
] as const

// ── Helpers ────────────────────────────────────────────────────────────────

function formatDateForInput(date: Date): string {
  return date.toISOString().split("T")[0]
}

function getPresetDates(days: number): { start: string; end: string } {
  const now = new Date()
  const end = formatDateForInput(now)
  if (days < 0) return { start: "", end: "" }
  if (days === 0) return { start: end, end }
  const start = new Date(now)
  start.setDate(start.getDate() - days)
  return { start: formatDateForInput(start), end }
}

function getPresetLabel(startDate: string, endDate: string): string | null {
  if (!startDate && !endDate) return null
  const now = new Date()
  const todayStr = formatDateForInput(now)
  if (startDate === todayStr && endDate === todayStr) return "Today"
  for (const preset of DATE_PRESETS) {
    if (preset.days <= 0) continue
    const { start, end } = getPresetDates(preset.days)
    if (startDate === start && endDate === end) return preset.label
  }
  return "Custom"
}

/** Return a human-readable relative time string. */
function relativeTime(dateStr: string): string {
  const date = new Date(dateStr)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffSec = Math.floor(diffMs / 1000)
  if (diffSec < 60) return "just now"
  const diffMin = Math.floor(diffSec / 60)
  if (diffMin < 60) return `${diffMin}m ago`
  const diffHr = Math.floor(diffMin / 60)
  if (diffHr < 24) return `${diffHr}h ago`
  const diffDays = Math.floor(diffHr / 24)
  if (diffDays < 30) return `${diffDays}d ago`
  const diffMonths = Math.floor(diffDays / 30)
  return `${diffMonths}mo ago`
}

/** Derive the verb from an action string (e.g., "user.created" -> "created"). */
function getActionVerb(action: string): string {
  const parts = action.split(".")
  return parts[parts.length - 1] ?? action
}

/** Map action verbs to badge styling. */
function getActionBadgeClasses(action: string): string {
  const verb = getActionVerb(action)
  switch (verb) {
    case "created":
    case "success":
    case "enabled":
    case "member_added":
    case "invite_sent":
      return "border-green-200 bg-green-50 text-green-700 dark:border-green-800 dark:bg-green-950 dark:text-green-300"
    case "updated":
    case "changed":
    case "role_changed":
    case "config_changed":
      return "border-yellow-200 bg-yellow-50 text-yellow-700 dark:border-yellow-800 dark:bg-yellow-950 dark:text-yellow-300"
    case "deleted":
    case "failed":
    case "disabled":
    case "member_removed":
      return "border-red-200 bg-red-50 text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-300"
    default:
      return "border-zinc-200 bg-zinc-50 text-zinc-700 dark:border-zinc-800 dark:bg-zinc-950 dark:text-zinc-300"
  }
}

// ── CSV Export ──────────────────────────────────────────────────────────────

function escapeCsvField(value: string): string {
  if (value.includes(",") || value.includes('"') || value.includes("\n")) {
    return `"${value.replace(/"/g, '""')}"`
  }
  return value
}

function generateBasicCsv(items: AuditLogEntry[]): string {
  const headers = [
    "timestamp",
    "action",
    "actor_name",
    "actor_email",
    "target_type",
    "target_id",
    "target_label",
    "ip_address",
    "user_agent",
  ]
  const rows = items.map((entry) =>
    [
      new Date(entry.createdAt).toISOString(),
      entry.action,
      entry.actorName ?? "",
      entry.actorEmail ?? "",
      entry.targetType ?? "",
      entry.targetId ?? "",
      entry.targetLabel ?? "",
      entry.ipAddress ?? "",
      entry.userAgent ?? "",
    ]
      .map(escapeCsvField)
      .join(","),
  )
  return [headers.join(","), ...rows].join("\n")
}

function flattenDetails(
  details: Record<string, unknown> | null | undefined,
): Record<string, string> {
  if (!details) return {}
  const flat: Record<string, string> = {}
  for (const [key, value] of Object.entries(details)) {
    if (value === null || value === undefined) {
      flat[key] = ""
    } else if (typeof value === "object") {
      flat[key] = JSON.stringify(value)
    } else {
      flat[key] = String(value)
    }
  }
  return flat
}

function generateExtendedCsv(items: AuditLogEntry[]): string {
  const detailKeys = new Set<string>()
  const flatDetailsList = items.map((entry) => {
    const flat = flattenDetails(entry.details)
    for (const key of Object.keys(flat)) detailKeys.add(key)
    return flat
  })
  const sortedDetailKeys = [...detailKeys].sort()

  const headers = [
    "id",
    "timestamp",
    "action",
    "actor_id",
    "actor_name",
    "actor_email",
    "target_type",
    "target_id",
    "target_label",
    "ip_address",
    "user_agent",
    "details_json",
    ...sortedDetailKeys.map((k) => `detail_${k}`),
  ]

  const rows = items.map((entry, i) => {
    const flat = flatDetailsList[i]
    return [
      entry.id,
      new Date(entry.createdAt).toISOString(),
      entry.action,
      entry.actorId ?? "",
      entry.actorName ?? "",
      entry.actorEmail ?? "",
      entry.targetType ?? "",
      entry.targetId ?? "",
      entry.targetLabel ?? "",
      entry.ipAddress ?? "",
      entry.userAgent ?? "",
      entry.details ? JSON.stringify(entry.details) : "",
      ...sortedDetailKeys.map((k) => flat[k] ?? ""),
    ]
      .map(escapeCsvField)
      .join(",")
  })

  return [headers.join(","), ...rows].join("\n")
}

function downloadCsv(csv: string, mode: "basic" | "extended" = "basic") {
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" })
  const url = URL.createObjectURL(blob)
  const link = document.createElement("a")
  const date = new Date().toISOString().split("T")[0]
  link.href = url
  link.download = `audit-log-${mode === "extended" ? "extended-" : ""}${date}.csv`
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(url)
}

// ── Date Range Picker ──────────────────────────────────────────────────────

function DateRangeFilter({
  startDate,
  endDate,
  onStartDateChange,
  onEndDateChange,
  onPreset,
}: {
  startDate: string
  endDate: string
  onStartDateChange: (v: string) => void
  onEndDateChange: (v: string) => void
  onPreset: (days: number) => void
}) {
  const presetLabel = getPresetLabel(startDate, endDate)
  const hasDateFilter = Boolean(startDate || endDate)

  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="outline" size="sm" className="gap-1.5">
          <Calendar className="size-3.5" />
          {presetLabel ?? "Date range"}
          {hasDateFilter && (
            <Badge
              variant="secondary"
              className="ml-1 size-5 justify-center rounded-full px-0 text-[10px]"
            >
              1
            </Badge>
          )}
        </Button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-72 space-y-3 p-3">
        <div className="flex flex-wrap gap-1">
          {DATE_PRESETS.map((preset) => (
            <Button
              key={preset.label}
              variant={presetLabel === preset.label ? "secondary" : "ghost"}
              size="sm"
              className="h-7 text-xs"
              onClick={() => onPreset(preset.days)}
            >
              {preset.label}
            </Button>
          ))}
        </div>
        <div className="-mx-3 h-px bg-border" />
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <label className="w-12 text-xs text-muted-foreground">From</label>
            <Input
              type="date"
              className="h-8 text-xs"
              value={startDate}
              onChange={(e) => onStartDateChange(e.target.value)}
              aria-label="From date"
            />
          </div>
          <div className="flex items-center gap-2">
            <label className="w-12 text-xs text-muted-foreground">To</label>
            <Input
              type="date"
              className="h-8 text-xs"
              value={endDate}
              onChange={(e) => onEndDateChange(e.target.value)}
              aria-label="To date"
            />
          </div>
        </div>
        {hasDateFilter && (
          <>
            <div className="-mx-3 h-px bg-border" />
            <Button
              variant="ghost"
              size="sm"
              className="w-full justify-center text-xs"
              onClick={() => onPreset(-1)}
            >
              Clear dates
            </Button>
          </>
        )}
      </PopoverContent>
    </Popover>
  )
}

// ── Detail Row ─────────────────────────────────────────────────────────────

function AuditDetailRow({ entry, colSpan }: { entry: AuditLogEntry; colSpan: number }) {
  const hasDetails = entry.details && Object.keys(entry.details).length > 0

  return (
    <TableRow className="bg-muted/30 hover:bg-muted/30">
      <TableCell colSpan={colSpan} className="px-4 py-3">
        <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-3">
          {/* Metadata */}
          <div className="space-y-2">
            <h4 className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              <User className="h-3.5 w-3.5" />
              Actor
            </h4>
            <DetailField label="Name" value={entry.actorName} />
            <DetailField label="Email" value={entry.actorEmail} mono />
            <DetailField label="ID" value={entry.actorId} mono />
          </div>
          <div className="space-y-2">
            <h4 className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              <Globe className="h-3.5 w-3.5" />
              Request
            </h4>
            <DetailField label="IP Address" value={entry.ipAddress} mono />
            <DetailField
              label="User Agent"
              value={entry.userAgent}
              className="max-w-xs truncate"
            />
            <DetailField
              label="Timestamp"
              value={new Date(entry.createdAt).toLocaleString()}
            />
          </div>
          <div className="space-y-2">
            <h4 className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              <Monitor className="h-3.5 w-3.5" />
              Target
            </h4>
            <DetailField label="Type" value={entry.targetType} />
            <DetailField label="Label" value={entry.targetLabel} />
            <DetailField label="ID" value={entry.targetId} mono />
          </div>
        </div>

        {/* Details JSON */}
        {hasDetails && (
          <div className="mt-4">
            <h4 className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              <FileText className="h-3.5 w-3.5" />
              Change Details
            </h4>
            <pre className="max-h-56 overflow-auto rounded-md border bg-muted/50 p-3 font-mono text-xs leading-relaxed">
              {JSON.stringify(entry.details, null, 2)}
            </pre>
          </div>
        )}
      </TableCell>
    </TableRow>
  )
}

function DetailField({
  label,
  value,
  mono,
  className,
}: {
  label: string
  value: string | null | undefined
  mono?: boolean
  className?: string
}) {
  return (
    <p className="flex items-baseline gap-2">
      <span className="min-w-[5rem] shrink-0 text-xs text-muted-foreground">{label}</span>
      <span
        className={`text-xs ${mono ? "font-mono" : ""} ${className ?? ""} ${!value ? "text-muted-foreground/50" : ""}`}
      >
        {value ?? "N/A"}
      </span>
    </p>
  )
}

// ── Main Component ─────────────────────────────────────────────────────────

export function AuditLogTable() {
  // Pagination
  const [page, setPage] = useState(1)

  // Filters
  const [search, setSearch] = useState("")
  const [selectedActions, setSelectedActions] = useState<string[]>([])
  const [selectedTargetTypes, setSelectedTargetTypes] = useState<string[]>([])
  const [startDate, setStartDate] = useState("")
  const [endDate, setEndDate] = useState("")

  // Sort
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<SortDirection>(null)

  // Expand
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set())

  // Export
  const [isExporting, setIsExporting] = useState(false)

  const resetPage = useCallback(() => setPage(1), [])

  // Data query
  const { data, isLoading, isError } = useAdminAuditLogs({
    page,
    pageSize: PAGE_SIZE,
    search: search || undefined,
    actions: selectedActions.length > 0 ? selectedActions : undefined,
    targetTypes: selectedTargetTypes.length > 0 ? selectedTargetTypes : undefined,
    startDate: startDate ? new Date(startDate).toISOString() : undefined,
    endDate: endDate ? new Date(`${endDate}T23:59:59`).toISOString() : undefined,
    orderBy: sortKey ?? undefined,
    sortOrder: sortDir ?? undefined,
  })

  // Export query (disabled until triggered)
  const { refetch: fetchExport } = useAdminAuditLogsExport({
    search: search || undefined,
    actions: selectedActions.length > 0 ? selectedActions : undefined,
    targetTypes: selectedTargetTypes.length > 0 ? selectedTargetTypes : undefined,
    startDate: startDate ? new Date(startDate).toISOString() : undefined,
    endDate: endDate ? new Date(`${endDate}T23:59:59`).toISOString() : undefined,
    enabled: false,
  })

  const totalPages = useMemo(
    () => Math.max(1, Math.ceil((data?.total ?? 0) / PAGE_SIZE)),
    [data?.total],
  )

  // Handlers
  const toggleRow = useCallback((id: string) => {
    setExpandedRows((prev) => {
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
      resetPage()
    },
    [sortKey, sortDir, resetPage],
  )

  const handleExport = useCallback(
    async (mode: "basic" | "extended") => {
      setIsExporting(true)
      try {
        const result = await fetchExport()
        if (result.data?.items) {
          const csv =
            mode === "extended"
              ? generateExtendedCsv(result.data.items)
              : generateBasicCsv(result.data.items)
          downloadCsv(csv, mode)
        }
      } finally {
        setIsExporting(false)
      }
    },
    [fetchExport],
  )

  const handleDatePreset = useCallback(
    (days: number) => {
      const { start, end } = getPresetDates(days)
      setStartDate(start)
      setEndDate(end)
      resetPage()
    },
    [resetPage],
  )

  const handleActionsChange = useCallback(
    (actions: string[]) => {
      setSelectedActions(actions)
      resetPage()
    },
    [resetPage],
  )

  const handleTargetTypesChange = useCallback(
    (types: string[]) => {
      setSelectedTargetTypes(types)
      resetPage()
    },
    [resetPage],
  )

  const handleSearchChange = useCallback(
    (value: string) => {
      setSearch(value)
      resetPage()
    },
    [resetPage],
  )

  const activeFilterCount =
    (selectedActions.length > 0 ? 1 : 0) +
    (selectedTargetTypes.length > 0 ? 1 : 0) +
    (startDate || endDate ? 1 : 0) +
    (search ? 1 : 0)

  const handleClearAll = useCallback(() => {
    setSearch("")
    setSelectedActions([])
    setSelectedTargetTypes([])
    setStartDate("")
    setEndDate("")
    setSortKey(null)
    setSortDir(null)
    resetPage()
  }, [resetPage])

  const items = data?.items ?? []
  const totalCount = data?.total ?? 0
  const hasData = items.length > 0

  // The table has 6 columns: expand chevron + action + actor + target + resource type + time
  const colSpan = 6

  return (
    <div className="space-y-4">
      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-3">
        {/* Search */}
        <div className="relative max-w-sm flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search by actor, action, or target..."
            value={search}
            onChange={(e) => handleSearchChange(e.target.value)}
            className="pl-9"
          />
        </div>

        {/* Action type filter */}
        <FilterDropdown
          label="Action"
          options={ACTION_FILTER_OPTIONS}
          selected={selectedActions}
          onChange={handleActionsChange}
        />

        {/* Resource type filter */}
        <FilterDropdown
          label="Resource"
          options={TARGET_TYPE_OPTIONS}
          selected={selectedTargetTypes}
          onChange={handleTargetTypesChange}
        />

        {/* Date range picker */}
        <DateRangeFilter
          startDate={startDate}
          endDate={endDate}
          onStartDateChange={(v) => {
            setStartDate(v)
            resetPage()
          }}
          onEndDateChange={(v) => {
            setEndDate(v)
            resetPage()
          }}
          onPreset={handleDatePreset}
        />

        {/* Export */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="outline"
              size="sm"
              disabled={isExporting || totalCount === 0}
              className="gap-1.5"
            >
              {isExporting ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Download className="h-3.5 w-3.5" />
              )}
              Export
              <ChevronDown className="ml-0.5 h-3 w-3" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem onClick={() => handleExport("basic")}>
              <Download className="mr-2 h-4 w-4" />
              Basic CSV
              <span className="ml-2 text-xs text-muted-foreground">Core fields</span>
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => handleExport("extended")}>
              <FileSpreadsheet className="mr-2 h-4 w-4" />
              Extended CSV
              <span className="ml-2 text-xs text-muted-foreground">
                All fields + details
              </span>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>

        {/* Clear all */}
        {activeFilterCount > 0 && (
          <Button
            variant="ghost"
            size="sm"
            className="text-xs text-muted-foreground"
            onClick={handleClearAll}
          >
            <X className="mr-1 h-3 w-3" />
            Clear all filters
          </Button>
        )}
      </div>

      {/* Active filter chips */}
      {(selectedActions.length > 0 || selectedTargetTypes.length > 0) && (
        <div className="flex flex-wrap items-center gap-1.5">
          {selectedActions.map((action) => (
            <Badge key={action} variant="secondary" className="gap-1 pr-1">
              <span className="text-xs">{action}</span>
              <button
                type="button"
                className="ml-0.5 rounded-full p-0.5 hover:bg-muted"
                onClick={() =>
                  handleActionsChange(selectedActions.filter((a) => a !== action))
                }
                aria-label={`Remove ${action} filter`}
              >
                <X className="h-3 w-3" />
              </button>
            </Badge>
          ))}
          {selectedTargetTypes.map((type) => (
            <Badge key={type} variant="outline" className="gap-1 pr-1">
              <span className="text-xs">{type.replace(/_/g, " ")}</span>
              <button
                type="button"
                className="ml-0.5 rounded-full p-0.5 hover:bg-muted"
                onClick={() =>
                  handleTargetTypesChange(
                    selectedTargetTypes.filter((t) => t !== type),
                  )
                }
                aria-label={`Remove ${type} filter`}
              >
                <X className="h-3 w-3" />
              </button>
            </Badge>
          ))}
        </div>
      )}

      {/* Content */}
      {isLoading ? (
        <SkeletonTable rows={8} />
      ) : isError ? (
        <EmptyState
          icon={AlertCircle}
          title="Unable to load audit logs"
          description="Something went wrong while fetching audit log entries. Please try refreshing the page."
          action={
            <Button
              variant="outline"
              size="sm"
              onClick={() => window.location.reload()}
            >
              Refresh page
            </Button>
          }
        />
      ) : !hasData && activeFilterCount === 0 ? (
        <EmptyState
          icon={Clock}
          title="No audit log entries"
          description="Audit log entries will appear here as users perform actions in the system."
        />
      ) : !hasData ? (
        <EmptyState
          icon={Search}
          variant="no-results"
          title="No results found"
          description="No audit entries match your current filters. Try adjusting your search or filter criteria."
          action={
            <Button variant="outline" size="sm" onClick={handleClearAll}>
              Clear all filters
            </Button>
          }
        />
      ) : (
        <div className="space-y-3">
          {/* Result count */}
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">
              {totalCount.toLocaleString()} {totalCount === 1 ? "entry" : "entries"}
              {activeFilterCount > 0 && " (filtered)"}
            </p>
          </div>

          {/* Table */}
          <div className="rounded-md border border-border/60 bg-card/80">
            <Table>
              <TableHeader className="sticky top-0 z-10 bg-background">
                <TableRow>
                  <TableHead className="w-8" />
                  <SortableHeader
                    label="Action"
                    sortKey="action"
                    currentSort={sortKey}
                    currentDirection={sortDir}
                    onSort={handleSort}
                  />
                  <SortableHeader
                    label="Actor"
                    sortKey="actor_name"
                    currentSort={sortKey}
                    currentDirection={sortDir}
                    onSort={handleSort}
                  />
                  <SortableHeader
                    label="Target"
                    sortKey="target_label"
                    currentSort={sortKey}
                    currentDirection={sortDir}
                    onSort={handleSort}
                  />
                  <TableHead>Resource</TableHead>
                  <SortableHeader
                    label="Time"
                    sortKey="created_at"
                    currentSort={sortKey}
                    currentDirection={sortDir}
                    onSort={handleSort}
                    className="text-right"
                  />
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((entry) => {
                  const isExpanded = expandedRows.has(entry.id)
                  return (
                    <Fragment key={entry.id}>
                      <TableRow
                        className="cursor-pointer transition-colors hover:bg-muted/50"
                        onClick={() => toggleRow(entry.id)}
                      >
                        <TableCell className="w-8 pr-0">
                          {isExpanded ? (
                            <ChevronDown className="h-4 w-4 text-muted-foreground" />
                          ) : (
                            <ChevronRight className="h-4 w-4 text-muted-foreground" />
                          )}
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant="outline"
                            className={getActionBadgeClasses(entry.action)}
                          >
                            {entry.action}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-muted-foreground">
                          {entry.actorName ? (
                            <div>
                              <span className="text-sm">{entry.actorName}</span>
                              {entry.actorEmail && (
                                <span className="block text-xs text-muted-foreground/70">
                                  {entry.actorEmail}
                                </span>
                              )}
                            </div>
                          ) : entry.actorEmail ? (
                            <span className="text-sm">{entry.actorEmail}</span>
                          ) : (
                            <span className="text-sm italic text-muted-foreground/60">
                              System
                            </span>
                          )}
                        </TableCell>
                        <TableCell className="text-muted-foreground">
                          <span className="text-sm">
                            {entry.targetLabel ?? entry.targetId ?? "-"}
                          </span>
                        </TableCell>
                        <TableCell>
                          {entry.targetType ? (
                            <Badge variant="outline" className="text-xs font-normal">
                              {entry.targetType.replace(/_/g, " ")}
                            </Badge>
                          ) : (
                            <span className="text-xs text-muted-foreground/50">--</span>
                          )}
                        </TableCell>
                        <TableCell className="text-right">
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <span className="cursor-default text-sm text-muted-foreground">
                                {relativeTime(entry.createdAt)}
                              </span>
                            </TooltipTrigger>
                            <TooltipContent>
                              {new Date(entry.createdAt).toLocaleString()}
                            </TooltipContent>
                          </Tooltip>
                        </TableCell>
                      </TableRow>
                      {isExpanded && (
                        <AuditDetailRow
                          key={`${entry.id}-detail`}
                          entry={entry}
                          colSpan={colSpan}
                        />
                      )}
                    </Fragment>
                  )
                })}
              </TableBody>
            </Table>
          </div>

          {/* Pagination */}
          <div className="flex items-center justify-between">
            <p className="text-xs text-muted-foreground">
              Page {page} of {totalPages} ({totalCount.toLocaleString()} total)
            </p>
            <div className="flex gap-2">
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
          </div>
        </div>
      )}
    </div>
  )
}
