import { Calendar, ChevronDown, ChevronRight, Download, Loader2, Search, X } from "lucide-react"
import { useCallback, useMemo, useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectGroup, SelectItem, SelectLabel, SelectTrigger, SelectValue } from "@/components/ui/select"
import { SkeletonTable } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useAdminAuditLogs, useAdminAuditLogsExport } from "@/lib/api/hooks/admin"
import type { AuditLogEntry } from "@/lib/generated/api"

const PAGE_SIZE = 50

/** Known audit action types grouped by domain. */
const ACTION_GROUPS: Record<string, string[]> = {
  Account: ["account.created", "account.updated", "account.deleted", "login.success", "login.failed", "password.changed", "mfa.enabled", "mfa.disabled"],
  Team: ["team.created", "team.updated", "team.deleted", "team.member_added", "team.member_removed", "team.invite_sent"],
  User: ["user.created", "user.updated", "user.deleted", "user.role_changed"],
  Device: ["device.created", "device.updated", "device.deleted"],
  Voice: ["extension.created", "extension.updated", "extension.deleted", "phone_number.created", "phone_number.updated", "phone_number.deleted"],
  System: ["system.config_changed", "system.maintenance"],
}

/** Date preset definitions. */
const DATE_PRESETS = [
  { label: "Today", days: 0 },
  { label: "Last 7 days", days: 7 },
  { label: "Last 30 days", days: 30 },
  { label: "All time", days: -1 },
] as const

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

function escapeCsvField(value: string): string {
  if (value.includes(",") || value.includes('"') || value.includes("\n")) {
    return `"${value.replace(/"/g, '""')}"`
  }
  return value
}

function generateCsv(items: AuditLogEntry[]): string {
  const headers = ["timestamp", "action", "actor_email", "target_type", "target_id", "target_label", "ip_address", "user_agent"]
  const rows = items.map((entry) =>
    [
      new Date(entry.createdAt).toISOString(),
      entry.action,
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

function downloadCsv(csv: string) {
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" })
  const url = URL.createObjectURL(blob)
  const link = document.createElement("a")
  const date = new Date().toISOString().split("T")[0]
  link.href = url
  link.download = `audit-log-${date}.csv`
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(url)
}

/** Expandable detail row for a single audit log entry. */
function AuditDetailRow({ entry }: { entry: AuditLogEntry }) {
  return (
    <TableRow className="bg-muted/30 hover:bg-muted/30">
      <TableCell colSpan={5} className="p-4">
        <div className="grid gap-4 text-sm md:grid-cols-2">
          <div className="space-y-2">
            <p>
              <span className="font-medium text-muted-foreground">Actor ID:</span> <span className="font-mono text-xs">{entry.actorId ?? "N/A"}</span>
            </p>
            <p>
              <span className="font-medium text-muted-foreground">Target ID:</span> <span className="font-mono text-xs">{entry.targetId ?? "N/A"}</span>
            </p>
            <p>
              <span className="font-medium text-muted-foreground">IP Address:</span> <span className="font-mono text-xs">{entry.ipAddress ?? "N/A"}</span>
            </p>
            <p>
              <span className="font-medium text-muted-foreground">User Agent:</span> <span className="max-w-md truncate text-xs">{entry.userAgent ?? "N/A"}</span>
            </p>
          </div>
          {entry.details && Object.keys(entry.details).length > 0 && (
            <div>
              <p className="mb-1 font-medium text-muted-foreground">Details:</p>
              <pre className="max-h-48 overflow-auto rounded-md border bg-muted/50 p-2 font-mono text-xs">{JSON.stringify(entry.details, null, 2)}</pre>
            </div>
          )}
        </div>
      </TableCell>
    </TableRow>
  )
}

export function AuditLogTable() {
  const [page, setPage] = useState(1)
  const [actorEmail, setActorEmail] = useState("")
  const [targetType, setTargetType] = useState("")
  const [startDate, setStartDate] = useState("")
  const [endDate, setEndDate] = useState("")
  const [selectedActions, setSelectedActions] = useState<string[]>([])
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set())
  const [isExporting, setIsExporting] = useState(false)

  // Reset to page 1 when filters change
  const resetPage = useCallback(() => setPage(1), [])

  const { data, isLoading, isError } = useAdminAuditLogs({
    page,
    pageSize: PAGE_SIZE,
    actions: selectedActions.length > 0 ? selectedActions : undefined,
    actorEmail: actorEmail || undefined,
    targetType: targetType || undefined,
    startDate: startDate ? new Date(startDate).toISOString() : undefined,
    endDate: endDate ? new Date(`${endDate}T23:59:59`).toISOString() : undefined,
  })

  const { refetch: fetchExport } = useAdminAuditLogsExport({
    actions: selectedActions.length > 0 ? selectedActions : undefined,
    actorEmail: actorEmail || undefined,
    targetType: targetType || undefined,
    startDate: startDate ? new Date(startDate).toISOString() : undefined,
    endDate: endDate ? new Date(`${endDate}T23:59:59`).toISOString() : undefined,
    enabled: false,
  })

  const totalPages = useMemo(() => Math.max(1, Math.ceil((data?.total ?? 0) / PAGE_SIZE)), [data?.total])

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

  const handleExport = useCallback(async () => {
    setIsExporting(true)
    try {
      const result = await fetchExport()
      if (result.data?.items) {
        const csv = generateCsv(result.data.items)
        downloadCsv(csv)
      }
    } finally {
      setIsExporting(false)
    }
  }, [fetchExport])

  const handleDatePreset = useCallback(
    (days: number) => {
      const { start, end } = getPresetDates(days)
      setStartDate(start)
      setEndDate(end)
      resetPage()
    },
    [resetPage],
  )

  const handleAddAction = useCallback(
    (action: string) => {
      if (action && !selectedActions.includes(action)) {
        setSelectedActions((prev) => [...prev, action])
        resetPage()
      }
    },
    [selectedActions, resetPage],
  )

  const handleRemoveAction = useCallback(
    (action: string) => {
      setSelectedActions((prev) => prev.filter((a) => a !== action))
      resetPage()
    },
    [resetPage],
  )

  const handleClearActions = useCallback(() => {
    setSelectedActions([])
    resetPage()
  }, [resetPage])

  const handleTargetTypeChange = useCallback(
    (value: string) => {
      setTargetType(value === "all" ? "" : value)
      resetPage()
    },
    [resetPage],
  )

  const handleActorEmailChange = useCallback(
    (value: string) => {
      setActorEmail(value)
      resetPage()
    },
    [resetPage],
  )

  const activeFilterCount = useMemo(() => {
    let count = 0
    if (selectedActions.length > 0) count++
    if (actorEmail) count++
    if (targetType) count++
    if (startDate || endDate) count++
    return count
  }, [selectedActions, actorEmail, targetType, startDate, endDate])

  const handleClearAll = useCallback(() => {
    setSelectedActions([])
    setActorEmail("")
    setTargetType("")
    setStartDate("")
    setEndDate("")
    resetPage()
  }, [resetPage])

  // Known target types for the filter
  const targetTypes = ["user", "team", "device", "extension", "phone_number", "role", "organization", "location"]

  if (isLoading) {
    return <SkeletonTable rows={6} />
  }

  if (isError || !data) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Audit log</CardTitle>
        </CardHeader>
        <CardContent className="text-muted-foreground">We could not load audit logs.</CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-4">
        <div>
          <CardTitle>Audit log</CardTitle>
          <p className="mt-1 text-sm text-muted-foreground">
            {data.total.toLocaleString()} {data.total === 1 ? "entry" : "entries"} found
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={handleExport} disabled={isExporting || data.total === 0}>
          {isExporting ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Download className="mr-2 h-4 w-4" />}
          Export CSV
        </Button>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Filter bar */}
        <div className="space-y-3">
          {/* Row 1: Date range + presets */}
          <div className="flex flex-wrap items-center gap-2">
            <Calendar className="h-4 w-4 text-muted-foreground" />
            <Input
              type="date"
              className="w-[160px]"
              value={startDate}
              onChange={(e) => {
                setStartDate(e.target.value)
                resetPage()
              }}
              aria-label="From date"
            />
            <span className="text-sm text-muted-foreground">to</span>
            <Input
              type="date"
              className="w-[160px]"
              value={endDate}
              onChange={(e) => {
                setEndDate(e.target.value)
                resetPage()
              }}
              aria-label="To date"
            />
            <div className="flex gap-1">
              {DATE_PRESETS.map((preset) => (
                <Button key={preset.label} variant="ghost" size="sm" className="h-8 text-xs" onClick={() => handleDatePreset(preset.days)}>
                  {preset.label}
                </Button>
              ))}
            </div>
          </div>

          {/* Row 2: Actor email, Target type, Action type selector */}
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative w-[220px]">
              <Search className="absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input placeholder="Filter by actor email" className="pl-9" value={actorEmail} onChange={(e) => handleActorEmailChange(e.target.value)} />
            </div>

            <Select value={targetType || "all"} onValueChange={handleTargetTypeChange}>
              <SelectTrigger className="w-[170px]">
                <SelectValue placeholder="Target type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All targets</SelectItem>
                {targetTypes.map((t) => (
                  <SelectItem key={t} value={t}>
                    {t.replace(/_/g, " ")}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select value="" onValueChange={handleAddAction}>
              <SelectTrigger className="w-[200px]">
                <SelectValue placeholder="Add action filter" />
              </SelectTrigger>
              <SelectContent>
                {Object.entries(ACTION_GROUPS).map(([group, actions]) => {
                  const available = actions.filter((a) => !selectedActions.includes(a))
                  if (available.length === 0) return null
                  return (
                    <SelectGroup key={group}>
                      <SelectLabel>{group}</SelectLabel>
                      {available.map((a) => (
                        <SelectItem key={a} value={a}>
                          {a}
                        </SelectItem>
                      ))}
                    </SelectGroup>
                  )
                })}
              </SelectContent>
            </Select>

            {activeFilterCount > 0 && (
              <Button variant="ghost" size="sm" className="h-8 text-xs text-muted-foreground" onClick={handleClearAll}>
                <X className="mr-1 h-3 w-3" />
                Clear filters
              </Button>
            )}
          </div>

          {/* Action filter chips */}
          {selectedActions.length > 0 && (
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-xs text-muted-foreground">Actions:</span>
              {selectedActions.map((action) => (
                <Badge key={action} variant="secondary" className="gap-1 pr-1">
                  <span className="text-xs">{action}</span>
                  <button type="button" className="ml-0.5 rounded-full p-0.5 hover:bg-muted" onClick={() => handleRemoveAction(action)} aria-label={`Remove ${action} filter`}>
                    <X className="h-3 w-3" />
                  </button>
                </Badge>
              ))}
              {selectedActions.length > 1 && (
                <button type="button" className="text-xs text-muted-foreground underline-offset-4 hover:underline" onClick={handleClearActions}>
                  Clear all
                </button>
              )}
            </div>
          )}
        </div>

        {/* Table */}
        <div className="rounded-md border">
          <Table>
            <TableHeader className="sticky top-0 z-10 bg-background">
              <TableRow>
                <TableHead className="w-8" />
                <TableHead>Action</TableHead>
                <TableHead>Actor</TableHead>
                <TableHead>Target</TableHead>
                <TableHead className="text-right">Time</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.items.length === 0 && (
                <TableRow>
                  <TableCell colSpan={5} className="py-12 text-center text-muted-foreground">
                    No audit entries match the current filters.
                  </TableCell>
                </TableRow>
              )}
              {data.items.map((entry) => {
                const isExpanded = expandedRows.has(entry.id)
                return (
                  <>
                    <TableRow key={entry.id} className="cursor-pointer transition-colors hover:bg-muted/50" onClick={() => toggleRow(entry.id)}>
                      <TableCell className="w-8 pr-0">
                        {isExpanded ? <ChevronDown className="h-4 w-4 text-muted-foreground" /> : <ChevronRight className="h-4 w-4 text-muted-foreground" />}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className={getActionBadgeClasses(entry.action)}>
                          {entry.action}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-muted-foreground">{entry.actorEmail ?? "System"}</TableCell>
                      <TableCell className="text-muted-foreground">
                        {entry.targetLabel ?? entry.targetId ?? "-"}
                        {entry.targetType && <span className="ml-1.5 text-xs text-muted-foreground/60">({entry.targetType})</span>}
                      </TableCell>
                      <TableCell className="text-right">
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <span className="cursor-default text-sm text-muted-foreground">{relativeTime(entry.createdAt)}</span>
                          </TooltipTrigger>
                          <TooltipContent>{new Date(entry.createdAt).toLocaleString()}</TooltipContent>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                    {isExpanded && <AuditDetailRow key={`${entry.id}-detail`} entry={entry} />}
                  </>
                )
              })}
            </TableBody>
          </Table>
        </div>

        {/* Pagination */}
        <div className="flex items-center justify-between">
          <p className="text-xs text-muted-foreground">
            Page {page} of {totalPages} ({data.total.toLocaleString()} total)
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
  )
}
