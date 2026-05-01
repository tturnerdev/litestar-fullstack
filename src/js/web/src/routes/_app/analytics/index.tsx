import { createFileRoute, Link } from "@tanstack/react-router"
import { useCallback, useEffect, useMemo, useState } from "react"
import {
  AlertCircle,
  BarChart3,
  Clock,
  Download,
  FileText,
  Loader2,
  Phone,
  PhoneIncoming,
  PhoneMissed,
  PhoneOutgoing,
  Search,
  X,
} from "lucide-react"

import { Badge } from "@/components/ui/badge"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { BulkActionBar, createExportAction } from "@/components/ui/bulk-action-bar"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { DateRangeFilter, getPresetDates } from "@/components/ui/date-range-filter"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { EmptyState } from "@/components/ui/empty-state"
import { FilterDropdown, type FilterOption } from "@/components/ui/filter-dropdown"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import {
  useAnalyticsByExtension,
  useAnalyticsSummary,
  useAnalyticsVolume,
  useCallRecord,
  useCallRecords,
  type CallRecord,
} from "@/lib/api/hooks/analytics"
import { exportToCsv, type CsvHeader } from "@/lib/csv-export"
import { formatDateTime } from "@/lib/date-utils"
import { useDebouncedValue } from "@/hooks/use-debounced-value"
import { useDocumentTitle } from "@/hooks/use-document-title"

export const Route = createFileRoute("/_app/analytics/")({
  component: AnalyticsPage,
  validateSearch: (search: Record<string, unknown>): { tab?: string } => ({
    tab: (search.tab as string) || undefined,
  }),
})

// -- Constants ----------------------------------------------------------------

const PAGE_SIZE = 25

const directionOptions: FilterOption[] = [
  { value: "inbound", label: "Inbound" },
  { value: "outbound", label: "Outbound" },
  { value: "internal", label: "Internal" },
]

const dispositionOptions: FilterOption[] = [
  { value: "answered", label: "Answered" },
  { value: "missed", label: "Missed" },
  { value: "voicemail", label: "Voicemail" },
  { value: "busy", label: "Busy" },
  { value: "failed", label: "Failed" },
  { value: "no_answer", label: "No Answer" },
]

const csvHeaders: CsvHeader<CallRecord>[] = [
  { label: "Date/Time", accessor: (r) => formatDateTime(r.startedAt) },
  { label: "Direction", accessor: (r) => r.direction },
  { label: "Source", accessor: (r) => r.source },
  { label: "Destination", accessor: (r) => r.destination },
  { label: "Duration (s)", accessor: (r) => r.durationSeconds },
  { label: "Disposition", accessor: (r) => r.disposition },
  { label: "Cost", accessor: (r) => r.cost ?? "" },
  { label: "Extension", accessor: (r) => r.extensionNumber ?? "" },
  { label: "Channel", accessor: (r) => r.channel ?? "" },
]

// -- Helpers ------------------------------------------------------------------

function formatDuration(seconds: number): string {
  if (seconds <= 0) return "0:00"
  const m = Math.floor(seconds / 60)
  const s = seconds % 60
  return `${m}:${String(Math.floor(s)).padStart(2, "0")}`
}

function formatDurationLong(seconds: number): string {
  if (seconds <= 0) return "0s"
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  const s = Math.floor(seconds % 60)
  const parts: string[] = []
  if (h > 0) parts.push(`${h}h`)
  if (m > 0) parts.push(`${m}m`)
  if (s > 0 || parts.length === 0) parts.push(`${s}s`)
  return parts.join(" ")
}

function formatCost(cost: number | null): string {
  if (cost === null || cost === undefined) return "--"
  return `$${cost.toFixed(4)}`
}

function formatPeriodLabel(period: string): string {
  try {
    const d = new Date(period)
    return d.toLocaleDateString(undefined, { month: "short", day: "numeric" })
  } catch {
    return period
  }
}

// -- Direction badge ----------------------------------------------------------

function DirectionBadge({ direction }: { direction: string }) {
  switch (direction) {
    case "inbound":
      return (
        <Badge variant="outline" className="gap-1 border-blue-300 text-blue-700 dark:border-blue-700 dark:text-blue-300">
          <PhoneIncoming className="h-3 w-3" />
          In
        </Badge>
      )
    case "outbound":
      return (
        <Badge variant="outline" className="gap-1 border-emerald-300 text-emerald-700 dark:border-emerald-700 dark:text-emerald-300">
          <PhoneOutgoing className="h-3 w-3" />
          Out
        </Badge>
      )
    case "internal":
      return (
        <Badge variant="outline" className="gap-1">
          <Phone className="h-3 w-3" />
          Int
        </Badge>
      )
    default:
      return <Badge variant="outline">{direction}</Badge>
  }
}

// -- Disposition badge --------------------------------------------------------

const dispositionColors: Record<string, { variant: "default" | "secondary" | "outline" | "destructive"; className?: string }> = {
  answered: { variant: "default", className: "bg-emerald-600 hover:bg-emerald-700 dark:bg-emerald-700" },
  missed: { variant: "destructive" },
  voicemail: { variant: "secondary" },
  busy: { variant: "outline", className: "border-amber-300 text-amber-700 dark:border-amber-700 dark:text-amber-300" },
  failed: { variant: "destructive", className: "bg-red-800 hover:bg-red-900 dark:bg-red-900" },
  no_answer: { variant: "outline", className: "text-muted-foreground" },
}

function DispositionBadge({ disposition }: { disposition: string }) {
  const config = dispositionColors[disposition] ?? { variant: "outline" as const }
  const label = disposition.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())
  return (
    <Badge variant={config.variant} className={config.className}>
      {label}
    </Badge>
  )
}

// -- Stat card ----------------------------------------------------------------

function StatCard({
  title,
  value,
  subtitle,
  icon: Icon,
}: {
  title: string
  value: string | number
  subtitle?: string
  icon: typeof Phone
}) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">{title}</CardTitle>
        <Icon className="h-4 w-4 text-muted-foreground" />
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold">{value}</div>
        {subtitle && <p className="mt-1 text-xs text-muted-foreground">{subtitle}</p>}
      </CardContent>
    </Card>
  )
}

// -- Volume bar chart ---------------------------------------------------------

function VolumeChart({
  data,
}: {
  data: { period: string; count: number; answered: number; missed: number }[]
}) {
  if (data.length === 0) {
    return (
      <div className="flex h-48 items-center justify-center text-sm text-muted-foreground">
        No volume data for this period
      </div>
    )
  }

  const maxCount = Math.max(...data.map((d) => d.count), 1)

  return (
    <div className="space-y-2">
      <div className="flex items-end gap-1" style={{ height: 200 }}>
        {data.map((point) => {
          const totalHeight = (point.count / maxCount) * 100
          const answeredHeight = point.count > 0 ? (point.answered / point.count) * totalHeight : 0
          const missedHeight = totalHeight - answeredHeight

          return (
            <Tooltip key={point.period}>
              <TooltipTrigger asChild>
                <div className="flex flex-1 flex-col-reverse items-stretch" style={{ height: "100%" }}>
                  <div className="flex flex-col-reverse rounded-t" style={{ height: `${totalHeight}%`, minHeight: point.count > 0 ? 4 : 0 }}>
                    <div
                      className="rounded-t-sm bg-emerald-500 dark:bg-emerald-600 transition-all"
                      style={{ height: `${answeredHeight > 0 ? (answeredHeight / totalHeight) * 100 : 0}%`, minHeight: point.answered > 0 ? 2 : 0 }}
                    />
                    <div
                      className="bg-red-400 dark:bg-red-500 transition-all"
                      style={{ height: `${missedHeight > 0 ? (missedHeight / totalHeight) * 100 : 0}%`, minHeight: point.missed > 0 ? 2 : 0 }}
                    />
                  </div>
                </div>
              </TooltipTrigger>
              <TooltipContent>
                <div className="text-xs">
                  <p className="font-medium">{formatPeriodLabel(point.period)}</p>
                  <p>Total: {point.count}</p>
                  <p className="text-emerald-400">Answered: {point.answered}</p>
                  <p className="text-red-400">Missed: {point.missed}</p>
                </div>
              </TooltipContent>
            </Tooltip>
          )
        })}
      </div>
      {/* X-axis labels */}
      <div className="flex gap-1">
        {data.map((point, i) => {
          // Show labels sparsely when there are many data points
          const showLabel = data.length <= 14 || i % Math.ceil(data.length / 10) === 0 || i === data.length - 1
          return (
            <div key={point.period} className="flex-1 text-center">
              {showLabel && (
                <span className="text-[10px] text-muted-foreground">{formatPeriodLabel(point.period)}</span>
              )}
            </div>
          )
        })}
      </div>
      {/* Legend */}
      <div className="flex items-center justify-center gap-4 pt-1">
        <div className="flex items-center gap-1.5">
          <div className="h-2.5 w-2.5 rounded-sm bg-emerald-500 dark:bg-emerald-600" />
          <span className="text-xs text-muted-foreground">Answered</span>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="h-2.5 w-2.5 rounded-sm bg-red-400 dark:bg-red-500" />
          <span className="text-xs text-muted-foreground">Missed</span>
        </div>
      </div>
    </div>
  )
}

// -- CDR detail dialog --------------------------------------------------------

function CdrDetailDialog({
  cdrId,
  open,
  onOpenChange,
}: {
  cdrId: string
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const { data: record, isLoading, isError } = useCallRecord(cdrId)

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-2xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Call Detail Record</DialogTitle>
          <DialogDescription>Full details for this call record.</DialogDescription>
        </DialogHeader>

        {isLoading && (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
          </div>
        )}

        {isError && (
          <div className="rounded-md bg-destructive/10 px-4 py-3 text-sm text-destructive">
            Unable to load call record details.
          </div>
        )}

        {record && (
          <div className="space-y-4">
            {/* Key info */}
            <div className="grid grid-cols-2 gap-4">
              <DetailField label="Direction">
                <DirectionBadge direction={record.direction} />
              </DetailField>
              <DetailField label="Disposition">
                <DispositionBadge disposition={record.disposition} />
              </DetailField>
              <DetailField label="Source">
                <span className="font-mono text-sm">{record.source}</span>
              </DetailField>
              <DetailField label="Destination">
                <span className="font-mono text-sm">{record.destination}</span>
              </DetailField>
              <DetailField label="Started">
                <span className="text-sm">{formatDateTime(record.startedAt)}</span>
              </DetailField>
              <DetailField label="Ended">
                <span className="text-sm">{record.endedAt ? formatDateTime(record.endedAt) : "--"}</span>
              </DetailField>
              <DetailField label="Duration">
                <span className="text-sm">{formatDurationLong(record.durationSeconds)}</span>
              </DetailField>
              <DetailField label="Billable">
                <span className="text-sm">{formatDurationLong(record.billableSeconds)}</span>
              </DetailField>
              <DetailField label="Cost">
                <span className="text-sm font-mono">{formatCost(record.cost)}</span>
              </DetailField>
              <DetailField label="Extension">
                <span className="text-sm font-mono">{record.extensionNumber ?? "--"}</span>
              </DetailField>
            </div>

            {/* Channel info */}
            <div className="space-y-2 rounded-md border p-3">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Channel Info</h4>
              <div className="grid grid-cols-2 gap-3">
                <DetailField label="Channel">
                  <span className="text-sm font-mono">{record.channel ?? "--"}</span>
                </DetailField>
                <DetailField label="Unique ID">
                  <span className="text-sm font-mono break-all">{record.uniqueId ?? "--"}</span>
                </DetailField>
                <DetailField label="Linked ID">
                  <span className="text-sm font-mono break-all">{record.linkedId ?? "--"}</span>
                </DetailField>
              </div>
            </div>

            {/* Recording */}
            {record.recordingUrl && (
              <div className="space-y-2 rounded-md border p-3">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Recording</h4>
                <div className="flex items-center gap-3">
                  <audio controls preload="none" className="h-8 flex-1">
                    <source src={record.recordingUrl} />
                    Your browser does not support audio playback.
                  </audio>
                  <Button variant="outline" size="sm" asChild>
                    <a href={record.recordingUrl} download>
                      <Download className="mr-1.5 h-3.5 w-3.5" />
                      Download
                    </a>
                  </Button>
                </div>
              </div>
            )}

            {/* Notes */}
            {record.notes && (
              <div className="space-y-2 rounded-md border p-3">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Notes</h4>
                <p className="text-sm whitespace-pre-wrap">{record.notes}</p>
              </div>
            )}
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}

function DetailField({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-0.5">
      <p className="text-xs font-medium text-muted-foreground">{label}</p>
      <div>{children}</div>
    </div>
  )
}

// -- Dashboard tab ------------------------------------------------------------

function DashboardTab() {
  const defaultDates = getPresetDates(7)
  const [startDate, setStartDate] = useState(defaultDates.start)
  const [endDate, setEndDate] = useState(defaultDates.end)

  const { data: summary, isLoading: summaryLoading } = useAnalyticsSummary(startDate, endDate)
  const { data: volumeData, isLoading: volumeLoading } = useAnalyticsVolume(startDate, endDate, "day")
  const { data: extensionData, isLoading: extensionLoading } = useAnalyticsByExtension(startDate, endDate)

  const handleDatePreset = useCallback((days: number) => {
    const { start, end } = getPresetDates(days)
    setStartDate(start)
    setEndDate(end)
  }, [])

  const answeredPct = summary && summary.totalCalls > 0
    ? ((summary.answered / summary.totalCalls) * 100).toFixed(1)
    : "0"

  const missedPct = summary && summary.totalCalls > 0
    ? ((summary.missed / summary.totalCalls) * 100).toFixed(1)
    : "0"

  return (
    <div className="space-y-6">
      {/* Date filter */}
      <div className="flex items-center gap-3">
        <DateRangeFilter
          startDate={startDate}
          endDate={endDate}
          onStartDateChange={setStartDate}
          onEndDateChange={setEndDate}
          onPreset={handleDatePreset}
          label="Date range"
        />
      </div>

      {/* Summary stat cards */}
      {summaryLoading ? (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <SkeletonCard key={i} />
          ))}
        </div>
      ) : summary ? (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <StatCard
            title="Total Calls"
            value={summary.totalCalls.toLocaleString()}
            subtitle={`${formatDurationLong(summary.totalDuration)} total duration`}
            icon={Phone}
          />
          <StatCard
            title="Answered"
            value={summary.answered.toLocaleString()}
            subtitle={`${answeredPct}% answer rate`}
            icon={PhoneIncoming}
          />
          <StatCard
            title="Missed"
            value={summary.missed.toLocaleString()}
            subtitle={`${missedPct}% of total calls`}
            icon={PhoneMissed}
          />
          <StatCard
            title="Avg Duration"
            value={formatDuration(summary.avgDuration)}
            subtitle={`${formatDuration(summary.avgBillableSeconds)} avg billable`}
            icon={Clock}
          />
        </div>
      ) : null}

      {/* Call volume chart */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Call Volume</CardTitle>
        </CardHeader>
        <CardContent>
          {volumeLoading ? (
            <div className="flex h-48 items-center justify-center">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : (
            <VolumeChart data={volumeData?.items ?? []} />
          )}
        </CardContent>
      </Card>

      {/* Per-extension table */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">By Extension</CardTitle>
        </CardHeader>
        <CardContent>
          {extensionLoading ? (
            <div className="flex h-32 items-center justify-center">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : !extensionData?.items?.length ? (
            <div className="flex h-32 items-center justify-center text-sm text-muted-foreground">
              No extension data for this period
            </div>
          ) : (
            <div className="overflow-x-auto rounded-md border border-border/60">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Extension</TableHead>
                    <TableHead className="text-right">Total</TableHead>
                    <TableHead className="text-right">Answered</TableHead>
                    <TableHead className="text-right">Missed</TableHead>
                    <TableHead className="text-right">Avg Duration</TableHead>
                    <TableHead className="text-right">Answer Rate</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {extensionData.items.map((ext) => {
                    const rate = ext.totalCalls > 0
                      ? ((ext.answered / ext.totalCalls) * 100).toFixed(1)
                      : "0.0"
                    return (
                      <TableRow key={ext.extension}>
                        <TableCell className="font-mono font-medium">{ext.extension}</TableCell>
                        <TableCell className="text-right">{ext.totalCalls}</TableCell>
                        <TableCell className="text-right text-emerald-600 dark:text-emerald-400">{ext.answered}</TableCell>
                        <TableCell className="text-right text-red-600 dark:text-red-400">{ext.missed}</TableCell>
                        <TableCell className="text-right">{formatDuration(ext.avgDuration)}</TableCell>
                        <TableCell className="text-right">
                          <Badge
                            variant={Number(rate) >= 80 ? "default" : Number(rate) >= 50 ? "secondary" : "destructive"}
                            className="text-xs"
                          >
                            {rate}%
                          </Badge>
                        </TableCell>
                      </TableRow>
                    )
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

// -- Call Records tab ---------------------------------------------------------

function CallRecordsTab() {
  // Filter state
  const [search, setSearch] = useState("")
  const debouncedSearch = useDebouncedValue(search)
  const [directionFilter, setDirectionFilter] = useState<string[]>([])
  const [dispositionFilter, setDispositionFilter] = useState<string[]>([])
  const defaultDates = getPresetDates(7)
  const [startDate, setStartDate] = useState(defaultDates.start)
  const [endDate, setEndDate] = useState(defaultDates.end)
  const [minDuration, setMinDuration] = useState("")
  const [maxDuration, setMaxDuration] = useState("")
  const [page, setPage] = useState(1)

  // Row selection
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())

  // Detail dialog
  const [selectedCdrId, setSelectedCdrId] = useState<string | null>(null)

  // Determine source/destination from search
  const sourceSearch = debouncedSearch || undefined
  const destinationSearch = debouncedSearch || undefined

  const { data, isLoading, isError, refetch } = useCallRecords({
    page,
    pageSize: PAGE_SIZE,
    startDate: startDate || undefined,
    endDate: endDate || undefined,
    direction: directionFilter.length === 1 ? directionFilter[0] : undefined,
    disposition: dispositionFilter.length === 1 ? dispositionFilter[0] : undefined,
    source: sourceSearch,
    destination: !sourceSearch ? destinationSearch : undefined,
    minDuration: minDuration ? Number(minDuration) : undefined,
    maxDuration: maxDuration ? Number(maxDuration) : undefined,
  })

  // Client-side filters for multi-select (API takes single value)
  const filteredItems = useMemo(() => {
    if (!data?.items) return []
    return data.items.filter((record) => {
      if (directionFilter.length > 1 && !directionFilter.includes(record.direction)) return false
      if (dispositionFilter.length > 1 && !dispositionFilter.includes(record.disposition)) return false
      return true
    })
  }, [data?.items, directionFilter, dispositionFilter])

  // Selection helpers
  const allVisibleIds = useMemo(() => filteredItems.map((r) => r.id), [filteredItems])
  const allSelected = filteredItems.length > 0 && filteredItems.every((r) => selectedIds.has(r.id))
  const someSelected = filteredItems.some((r) => selectedIds.has(r.id))

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

  // Clear selection when filters/search/page change
  useEffect(() => {
    setSelectedIds(new Set())
  }, [debouncedSearch, directionFilter, dispositionFilter, startDate, endDate, minDuration, maxDuration, page])

  // Bulk actions (export only — CDR is audit data, no delete)
  const bulkActions = useMemo(
    () => [
      createExportAction<CallRecord>(
        "call-records-selected",
        csvHeaders,
        (ids) => filteredItems.filter((r) => ids.includes(r.id)),
      ),
    ],
    [filteredItems],
  )

  const totalPages = Math.max(1, Math.ceil((data?.total ?? 0) / PAGE_SIZE))
  const hasData = filteredItems.length > 0
  const hasAnyRecords = (data?.items?.length ?? 0) > 0

  const handleDatePreset = useCallback((days: number) => {
    const { start, end } = getPresetDates(days)
    setStartDate(start)
    setEndDate(end)
    setPage(1)
  }, [])

  const handleExportAll = useCallback(() => {
    if (!filteredItems.length) return
    exportToCsv("call-records", csvHeaders, filteredItems)
  }, [filteredItems])

  const activeFilterCount =
    directionFilter.length +
    dispositionFilter.length +
    (startDate || endDate ? 1 : 0) +
    (minDuration || maxDuration ? 1 : 0)

  const handleClearFilters = useCallback(() => {
    setSearch("")
    setDirectionFilter([])
    setDispositionFilter([])
    setStartDate("")
    setEndDate("")
    setMinDuration("")
    setMaxDuration("")
    setPage(1)
  }, [])

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative max-w-sm flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search source or destination..."
            value={search}
            onChange={(e) => {
              setSearch(e.target.value)
              setPage(1)
            }}
            className="pl-9 pr-8"
          />
          {search && (
            <button
              type="button"
              onClick={() => {
                setSearch("")
                setPage(1)
              }}
              className="absolute right-2 top-1/2 -translate-y-1/2 rounded-sm p-0.5 text-muted-foreground hover:text-foreground"
            >
              <X className="h-3.5 w-3.5" />
              <span className="sr-only">Clear search</span>
            </button>
          )}
        </div>
        <DateRangeFilter
          startDate={startDate}
          endDate={endDate}
          onStartDateChange={(v) => { setStartDate(v); setPage(1) }}
          onEndDateChange={(v) => { setEndDate(v); setPage(1) }}
          onPreset={handleDatePreset}
          label="Date range"
        />
        <FilterDropdown
          label="Direction"
          options={directionOptions}
          selected={directionFilter}
          onChange={(v) => { setDirectionFilter(v); setPage(1) }}
        />
        <FilterDropdown
          label="Disposition"
          options={dispositionOptions}
          selected={dispositionFilter}
          onChange={(v) => { setDispositionFilter(v); setPage(1) }}
        />
        {/* Duration range inputs */}
        <div className="flex items-center gap-1.5">
          <Input
            type="number"
            placeholder="Min sec"
            value={minDuration}
            onChange={(e) => { setMinDuration(e.target.value); setPage(1) }}
            className="h-9 w-20 text-xs"
            min={0}
          />
          <span className="text-xs text-muted-foreground">-</span>
          <Input
            type="number"
            placeholder="Max sec"
            value={maxDuration}
            onChange={(e) => { setMaxDuration(e.target.value); setPage(1) }}
            className="h-9 w-20 text-xs"
            min={0}
          />
        </div>
        {activeFilterCount > 0 && (
          <Button
            variant="ghost"
            size="sm"
            className="text-xs text-muted-foreground"
            onClick={handleClearFilters}
          >
            Clear all filters
          </Button>
        )}
      </div>

      {/* Export button */}
      <div className="flex items-center justify-between">
        <p className="text-xs text-muted-foreground">
          {data?.total ?? 0} record{(data?.total ?? 0) === 1 ? "" : "s"}
          {activeFilterCount > 0 && " (filtered)"}
        </p>
        <div className="flex items-center gap-2">
          {totalPages > 1 && (
            <p className="text-xs text-muted-foreground">
              Page {page} of {totalPages}
            </p>
          )}
          <Button variant="outline" size="sm" onClick={handleExportAll} disabled={!hasData}>
            <Download className="mr-2 h-4 w-4" />
            Export CSV
          </Button>
        </div>
      </div>

      {/* Table */}
      {isLoading ? (
        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <SkeletonCard key={i} />
          ))}
        </div>
      ) : isError ? (
        <EmptyState
          icon={AlertCircle}
          title="Unable to load call records"
          description="Something went wrong while fetching call records. Please try again."
          action={
            <Button variant="outline" size="sm" onClick={() => refetch()}>
              Try again
            </Button>
          }
        />
      ) : !hasAnyRecords && !search && activeFilterCount === 0 ? (
        <EmptyState
          icon={FileText}
          title="No call records yet"
          description="Call detail records will appear here once calls are processed."
        />
      ) : !hasData ? (
        <EmptyState
          icon={FileText}
          variant="no-results"
          title="No results found"
          description="No call records match your current filters. Try adjusting your search or filters."
          action={
            <Button variant="outline" size="sm" onClick={handleClearFilters}>
              Clear all filters
            </Button>
          }
        />
      ) : (
        <>
          <div className="overflow-x-auto rounded-md border border-border/60 bg-card/80">
            <Table aria-label="Call Records">
              <TableHeader>
                <TableRow>
                  <TableHead className="w-10">
                    <Checkbox
                      checked={allSelected}
                      indeterminate={someSelected && !allSelected}
                      onChange={toggleAll}
                      aria-label="Select all call records"
                    />
                  </TableHead>
                  <TableHead>Date/Time</TableHead>
                  <TableHead>Direction</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Destination</TableHead>
                  <TableHead className="text-right">Duration</TableHead>
                  <TableHead>Disposition</TableHead>
                  <TableHead className="text-right">Cost</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredItems.map((record) => (
                  <TableRow
                    key={record.id}
                    data-state={selectedIds.has(record.id) ? "selected" : undefined}
                    className="cursor-pointer hover:bg-muted/50"
                    onClick={(e) => {
                      const target = e.target as HTMLElement
                      if (target.closest("[role=checkbox]")) return
                      setSelectedCdrId(record.id)
                    }}
                  >
                    <TableCell>
                      <Checkbox
                        checked={selectedIds.has(record.id)}
                        onChange={(e) => {
                          e.stopPropagation()
                          toggleOne(record.id)
                        }}
                        aria-label={`Select call record from ${record.source} to ${record.destination}`}
                      />
                    </TableCell>
                    <TableCell>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span className="text-sm whitespace-nowrap">
                            {new Date(record.startedAt).toLocaleDateString(undefined, { month: "short", day: "numeric" })}
                            {" "}
                            <span className="text-muted-foreground">
                              {new Date(record.startedAt).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}
                            </span>
                          </span>
                        </TooltipTrigger>
                        <TooltipContent>{formatDateTime(record.startedAt)}</TooltipContent>
                      </Tooltip>
                    </TableCell>
                    <TableCell>
                      <DirectionBadge direction={record.direction} />
                    </TableCell>
                    <TableCell>
                      <span className="font-mono text-sm">{record.source}</span>
                    </TableCell>
                    <TableCell>
                      <span className="font-mono text-sm">{record.destination}</span>
                    </TableCell>
                    <TableCell className="text-right font-mono text-sm">
                      {formatDuration(record.durationSeconds)}
                    </TableCell>
                    <TableCell>
                      <DispositionBadge disposition={record.disposition} />
                    </TableCell>
                    <TableCell className="text-right font-mono text-sm">
                      {formatCost(record.cost)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>

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
        </>
      )}

      {/* CDR Detail Dialog */}
      {selectedCdrId && (
        <CdrDetailDialog
          cdrId={selectedCdrId}
          open={!!selectedCdrId}
          onOpenChange={(open) => {
            if (!open) setSelectedCdrId(null)
          }}
        />
      )}

      {/* Bulk action bar */}
      <BulkActionBar
        selectedCount={selectedIds.size}
        selectedIds={Array.from(selectedIds)}
        onClearSelection={() => setSelectedIds(new Set())}
        actions={bulkActions}
      />
    </div>
  )
}

// -- Main page ----------------------------------------------------------------

function AnalyticsPage() {
  useDocumentTitle("Analytics")
  const { tab = "dashboard" } = Route.useSearch()
  const navigate = Route.useNavigate()

  const breadcrumbs = (
    <Breadcrumb>
      <BreadcrumbList>
        <BreadcrumbItem>
          <BreadcrumbLink asChild>
            <Link to="/home">Home</Link>
          </BreadcrumbLink>
        </BreadcrumbItem>
        <BreadcrumbSeparator />
        <BreadcrumbItem>
          <BreadcrumbPage>Analytics</BreadcrumbPage>
        </BreadcrumbItem>
      </BreadcrumbList>
    </Breadcrumb>
  )

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Insights"
        title="Analytics"
        description="Call analytics, volume trends, and detailed call records."
        breadcrumbs={breadcrumbs}
      />

      <PageSection>
        <Tabs
          value={tab}
          onValueChange={(value) => navigate({ search: () => ({ tab: value }), replace: true })}
        >
          <TabsList>
            <TabsTrigger value="dashboard" className="gap-1.5">
              <BarChart3 className="h-4 w-4" />
              Dashboard
            </TabsTrigger>
            <TabsTrigger value="records" className="gap-1.5">
              <FileText className="h-4 w-4" />
              Call Records
            </TabsTrigger>
          </TabsList>

          <TabsContent value="dashboard" className="mt-6">
            <DashboardTab />
          </TabsContent>

          <TabsContent value="records" className="mt-6">
            <CallRecordsTab />
          </TabsContent>
        </Tabs>
      </PageSection>
    </PageContainer>
  )
}
