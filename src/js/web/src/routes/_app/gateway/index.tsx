import { createFileRoute, Link } from "@tanstack/react-router"
import { AlertCircle, CheckCircle2, Clock, Download, Hash, History, Info, Layers, Loader2, Monitor, Phone, Search, ShieldAlert, Trash2, XCircle } from "lucide-react"
import { useCallback, useRef, useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { useGatewayLookupDevice, useGatewayLookupExtension, useGatewayLookupNumber } from "@/lib/api/hooks/gateway"
import type { DeviceGatewayResponse, ExtensionGatewayResponse, NumberGatewayResponse, SourceResult } from "@/lib/generated/api"
import { gatewayLookupDevice, gatewayLookupExtension, gatewayLookupNumber } from "@/lib/generated/api"

export const Route = createFileRoute("/_app/gateway/")({
  component: GatewayPage,
  validateSearch: (search: Record<string, unknown>): { tab?: string } => ({
    tab: (search.tab as string) || undefined,
  }),
})

// -- Recent searches ----------------------------------------------------------

function useRecentSearches(key: string, max = 10) {
  const storageKey = `gateway-recent-${key}`
  const [items, setItems] = useState<string[]>(() => {
    try {
      return JSON.parse(localStorage.getItem(storageKey) ?? "[]")
    } catch {
      return []
    }
  })
  const add = useCallback(
    (term: string) => {
      const trimmed = term.trim()
      if (!trimmed) return
      setItems((prev) => {
        const updated = [trimmed, ...prev.filter((i) => i !== trimmed)].slice(0, max)
        localStorage.setItem(storageKey, JSON.stringify(updated))
        return updated
      })
    },
    [storageKey, max],
  )
  const clear = useCallback(() => {
    setItems([])
    localStorage.removeItem(storageKey)
  }, [storageKey])
  return { items, add, clear }
}

function RecentSearches({ items, onSelect, onClear }: { items: string[]; onSelect: (term: string) => void; onClear: () => void }) {
  if (items.length === 0) return null
  return (
    <div className="rounded-md border border-border bg-card p-3 space-y-2">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
          <History className="h-3 w-3" />
          Recent searches
        </div>
        <Button variant="ghost" size="sm" className="h-6 px-2 text-xs text-muted-foreground hover:text-destructive" onClick={onClear}>
          <Trash2 className="mr-1 h-3 w-3" />
          Clear
        </Button>
      </div>
      <div className="flex flex-wrap gap-1.5">
        {items.map((term) => (
          <button
            key={term}
            type="button"
            onClick={() => onSelect(term)}
            className="inline-flex items-center rounded-md border border-border bg-background px-2.5 py-1 text-sm font-mono transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
          >
            {term}
          </button>
        ))}
      </div>
    </div>
  )
}

// -- Status helpers -----------------------------------------------------------

const statusConfig: Record<string, { icon: typeof CheckCircle2; label: string; color: string; badgeVariant: "default" | "secondary" | "outline" | "destructive" }> = {
  ok: { icon: CheckCircle2, label: "OK", color: "text-emerald-600 dark:text-emerald-400", badgeVariant: "default" },
  error: { icon: XCircle, label: "Error", color: "text-destructive", badgeVariant: "destructive" },
  timeout: { icon: Clock, label: "Timeout", color: "text-amber-600 dark:text-amber-400", badgeVariant: "secondary" },
  not_supported: { icon: ShieldAlert, label: "Not Supported", color: "text-muted-foreground", badgeVariant: "outline" },
}

function SourceStatusBadge({ status }: { status: string }) {
  const config = statusConfig[status] ?? statusConfig.error
  const Icon = config.icon
  return (
    <Badge variant={config.badgeVariant} className="gap-1">
      <Icon className="h-3 w-3" />
      {config.label}
    </Badge>
  )
}

// -- Data rendering -----------------------------------------------------------

function formatKey(key: string): string {
  return key
    .replace(/_/g, " ")
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/\b\w/g, (c) => c.toUpperCase())
}

function DataValue({ value }: { value: unknown }) {
  if (value === null || value === undefined) {
    return <span className="text-muted-foreground italic">--</span>
  }
  if (typeof value === "boolean") {
    return (
      <Badge variant={value ? "default" : "outline"} className="text-xs">
        {value ? "Yes" : "No"}
      </Badge>
    )
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="text-muted-foreground italic">Empty</span>
    const keyed = value.map((item, idx) => ({
      key: `${typeof item === "object" ? JSON.stringify(item) : String(item)}-${idx}`,
      item,
    }))
    return (
      <div className="flex flex-wrap gap-1">
        {keyed.map(({ key, item }) => (
          <Badge key={key} variant="outline" className="text-xs font-normal">
            {typeof item === "object" ? JSON.stringify(item) : String(item)}
          </Badge>
        ))}
      </div>
    )
  }
  if (typeof value === "object") {
    return <DataSection data={value as Record<string, unknown>} nested />
  }
  return <span className="font-mono text-sm">{String(value)}</span>
}

function DataSection({ data, nested = false }: { data: Record<string, unknown>; nested?: boolean }) {
  const entries = Object.entries(data)
  if (entries.length === 0) {
    return (
      <div className="flex items-center gap-2 py-2 text-sm text-muted-foreground">
        <Info className="h-4 w-4 shrink-0" />
        <span className="italic">No fields returned for this record.</span>
      </div>
    )
  }
  return (
    <dl className={nested ? "space-y-1 pl-4 border-l border-border/40" : "space-y-2"}>
      {entries.map(([key, value]) => (
        <div key={key} className="flex flex-col gap-0.5 sm:flex-row sm:gap-3">
          <dt className="min-w-[140px] shrink-0 text-sm font-medium text-muted-foreground">{formatKey(key)}</dt>
          <dd className="text-sm break-all">
            <DataValue value={value} />
          </dd>
        </div>
      ))}
    </dl>
  )
}

// -- Source result card --------------------------------------------------------

function SourceCard({ name, result }: { name: string; result: SourceResult }) {
  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between gap-3">
          <div className="space-y-0.5">
            <CardTitle className="text-base">{result.connectionName}</CardTitle>
            <p className="text-xs text-muted-foreground font-mono">{name}</p>
          </div>
          <SourceStatusBadge status={result.status} />
        </div>
      </CardHeader>
      <CardContent>
        {result.error ? (
          <div className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">{result.error}</div>
        ) : result.data && Object.keys(result.data).length > 0 ? (
          <DataSection data={result.data} />
        ) : (
          <div className="flex items-center gap-2 py-2 text-sm text-muted-foreground">
            <Info className="h-4 w-4 shrink-0" />
            <span className="italic">This source returned no data for the lookup.</span>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

// -- Lookup results -----------------------------------------------------------

function LookupResults({
  sources,
  isLoading,
  isError,
  error,
  hasSearched,
}: {
  sources?: Record<string, SourceResult> | null
  isLoading: boolean
  isError: boolean
  error: Error | null
  hasSearched: boolean
}) {
  if (isLoading) {
    return (
      <div className="space-y-4">
        {["sk-card-0", "sk-card-1", "sk-card-2"].map((key) => (
          <SkeletonCard key={key} />
        ))}
      </div>
    )
  }

  if (isError) {
    return <EmptyState icon={AlertCircle} title="Lookup failed" description={error?.message ?? "An unexpected error occurred. Please try again."} />
  }

  if (!hasSearched) {
    return <EmptyState icon={Search} title="Enter a value to look up" description="Search across all configured connections to find matching records." />
  }

  if (!sources || Object.keys(sources).length === 0) {
    return (
      <EmptyState icon={Search} variant="no-results" title="No sources returned" description="No connections returned results for this lookup. Verify the value and try again." />
    )
  }

  const entries = Object.entries(sources)

  return (
    <div className="space-y-3">
      <p className="text-sm text-muted-foreground">
        {entries.length} source{entries.length === 1 ? "" : "s"} queried
      </p>
      <div className="grid gap-4 md:grid-cols-2">
        {entries.map(([name, result]) => (
          <SourceCard key={name} name={name} result={result} />
        ))}
      </div>
    </div>
  )
}

// -- Tab panels ---------------------------------------------------------------

function PhoneNumberTab() {
  const [input, setInput] = useState("")
  const [searchValue, setSearchValue] = useState("")
  const [showRecent, setShowRecent] = useState(false)
  const containerRef = useRef<HTMLDivElement>(null)
  const query = useGatewayLookupNumber(searchValue)
  const recent = useRecentSearches("phone")

  const executeLookup = useCallback(
    (value: string) => {
      const trimmed = value.trim()
      if (!trimmed) return
      setInput(trimmed)
      setSearchValue(trimmed)
      setShowRecent(false)
      recent.add(trimmed)
      setTimeout(() => query.refetch(), 0)
    },
    [query, recent],
  )

  const handleLookup = useCallback(() => {
    executeLookup(input)
  }, [input, executeLookup])

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "Enter") handleLookup()
    },
    [handleLookup],
  )

  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <div className="flex items-end gap-3">
          <div ref={containerRef} className="flex-1 max-w-md space-y-1.5">
            <label htmlFor="phone-input" className="text-sm font-medium">
              Phone Number
            </label>
            <Input
              id="phone-input"
              placeholder="e.g. +15551234567"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              onFocus={() => setShowRecent(true)}
              onBlur={(e) => {
                if (!containerRef.current?.contains(e.relatedTarget)) {
                  setShowRecent(false)
                }
              }}
            />
          </div>
          <Button onClick={handleLookup} disabled={!input.trim() || query.isFetching}>
            {query.isFetching ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Search className="mr-2 h-4 w-4" />}
            Look Up
          </Button>
        </div>
        {showRecent && (
          <div className="max-w-md">
            <RecentSearches items={recent.items} onSelect={executeLookup} onClear={recent.clear} />
          </div>
        )}
      </div>
      <LookupResults sources={query.data?.sources} isLoading={query.isFetching} isError={query.isError} error={query.error} hasSearched={query.isSuccess || query.isError} />
    </div>
  )
}

function ExtensionTab() {
  const [input, setInput] = useState("")
  const [searchValue, setSearchValue] = useState("")
  const [showRecent, setShowRecent] = useState(false)
  const containerRef = useRef<HTMLDivElement>(null)
  const query = useGatewayLookupExtension(searchValue)
  const recent = useRecentSearches("extension")

  const executeLookup = useCallback(
    (value: string) => {
      const trimmed = value.trim()
      if (!trimmed) return
      setInput(trimmed)
      setSearchValue(trimmed)
      setShowRecent(false)
      recent.add(trimmed)
      setTimeout(() => query.refetch(), 0)
    },
    [query, recent],
  )

  const handleLookup = useCallback(() => {
    executeLookup(input)
  }, [input, executeLookup])

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "Enter") handleLookup()
    },
    [handleLookup],
  )

  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <div className="flex items-end gap-3">
          <div ref={containerRef} className="flex-1 max-w-md space-y-1.5">
            <label htmlFor="ext-input" className="text-sm font-medium">
              Extension Number
            </label>
            <Input
              id="ext-input"
              placeholder="e.g. 1001"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              onFocus={() => setShowRecent(true)}
              onBlur={(e) => {
                if (!containerRef.current?.contains(e.relatedTarget)) {
                  setShowRecent(false)
                }
              }}
            />
          </div>
          <Button onClick={handleLookup} disabled={!input.trim() || query.isFetching}>
            {query.isFetching ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Search className="mr-2 h-4 w-4" />}
            Look Up
          </Button>
        </div>
        {showRecent && (
          <div className="max-w-md">
            <RecentSearches items={recent.items} onSelect={executeLookup} onClear={recent.clear} />
          </div>
        )}
      </div>
      <LookupResults sources={query.data?.sources} isLoading={query.isFetching} isError={query.isError} error={query.error} hasSearched={query.isSuccess || query.isError} />
    </div>
  )
}

function DeviceTab() {
  const [input, setInput] = useState("")
  const [searchValue, setSearchValue] = useState("")
  const [showRecent, setShowRecent] = useState(false)
  const containerRef = useRef<HTMLDivElement>(null)
  const query = useGatewayLookupDevice(searchValue)
  const recent = useRecentSearches("device")

  const executeLookup = useCallback(
    (value: string) => {
      const trimmed = value.trim()
      if (!trimmed) return
      setInput(trimmed)
      setSearchValue(trimmed)
      setShowRecent(false)
      recent.add(trimmed)
      setTimeout(() => query.refetch(), 0)
    },
    [query, recent],
  )

  const handleLookup = useCallback(() => {
    executeLookup(input)
  }, [input, executeLookup])

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "Enter") handleLookup()
    },
    [handleLookup],
  )

  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <div className="flex items-end gap-3">
          <div ref={containerRef} className="flex-1 max-w-md space-y-1.5">
            <label htmlFor="mac-input" className="text-sm font-medium">
              MAC Address
            </label>
            <Input
              id="mac-input"
              placeholder="e.g. AA:BB:CC:DD:EE:FF"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              onFocus={() => setShowRecent(true)}
              onBlur={(e) => {
                if (!containerRef.current?.contains(e.relatedTarget)) {
                  setShowRecent(false)
                }
              }}
            />
          </div>
          <Button onClick={handleLookup} disabled={!input.trim() || query.isFetching}>
            {query.isFetching ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Search className="mr-2 h-4 w-4" />}
            Look Up
          </Button>
        </div>
        {showRecent && (
          <div className="max-w-md">
            <RecentSearches items={recent.items} onSelect={executeLookup} onClear={recent.clear} />
          </div>
        )}
      </div>
      <LookupResults sources={query.data?.sources} isLoading={query.isFetching} isError={query.isError} error={query.error} hasSearched={query.isSuccess || query.isError} />
    </div>
  )
}

// -- Batch lookup -------------------------------------------------------------

type BatchLookupType = "phone" | "extension" | "device"

interface BatchResultEntry {
  input: string
  status: "pending" | "loading" | "ok" | "error"
  summary: string
  sources?: Record<string, SourceResult>
  error?: string
}

function parseBatchInput(raw: string): string[] {
  return raw
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
}

async function executeSingleLookup(type: BatchLookupType, value: string): Promise<{ sources?: Record<string, SourceResult>; error?: string }> {
  try {
    if (type === "phone") {
      const res = await gatewayLookupNumber({ path: { phone_number: value } })
      const data = res.data as NumberGatewayResponse | undefined
      return { sources: data?.sources }
    }
    if (type === "extension") {
      const res = await gatewayLookupExtension({ path: { extension_number: value } })
      const data = res.data as ExtensionGatewayResponse | undefined
      return { sources: data?.sources }
    }
    const res = await gatewayLookupDevice({ path: { mac_address: value } })
    const data = res.data as DeviceGatewayResponse | undefined
    return { sources: data?.sources }
  } catch (err) {
    return { error: err instanceof Error ? err.message : "Lookup failed" }
  }
}

function summarizeSources(sources?: Record<string, SourceResult> | null): string {
  if (!sources) return "No sources"
  const entries = Object.values(sources)
  if (entries.length === 0) return "No sources"
  const ok = entries.filter((s) => s.status === "ok").length
  const errors = entries.filter((s) => s.status === "error").length
  const parts: string[] = []
  if (ok > 0) parts.push(`${ok} OK`)
  if (errors > 0) parts.push(`${errors} error`)
  const other = entries.length - ok - errors
  if (other > 0) parts.push(`${other} other`)
  return parts.join(", ")
}

function escapeCsvField(value: string): string {
  if (value.includes(",") || value.includes('"') || value.includes("\n")) {
    return `"${value.replace(/"/g, '""')}"`
  }
  return value
}

function exportBatchCsv(results: BatchResultEntry[], lookupType: BatchLookupType) {
  const headerLabel = lookupType === "phone" ? "Phone Number" : lookupType === "extension" ? "Extension" : "MAC Address"
  const rows = [[headerLabel, "Status", "Summary", "Sources", "Error"].map(escapeCsvField).join(",")]
  for (const r of results) {
    const sourcesDetail = r.sources
      ? Object.entries(r.sources)
          .map(([name, src]) => {
            const fields = src.data
              ? Object.entries(src.data)
                  .map(([k, v]) => `${k}=${typeof v === "object" ? JSON.stringify(v) : String(v ?? "")}`)
                  .join("; ")
              : ""
            return `${name} (${src.status})${fields ? `: ${fields}` : ""}`
          })
          .join(" | ")
      : ""
    rows.push([r.input, r.status, r.summary, sourcesDetail, r.error ?? ""].map(escapeCsvField).join(","))
  }
  const blob = new Blob([rows.join("\n")], { type: "text/csv;charset=utf-8;" })
  const url = URL.createObjectURL(blob)
  const a = document.createElement("a")
  a.href = url
  a.download = `gateway-batch-${lookupType}-${new Date().toISOString().slice(0, 10)}.csv`
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

function BatchStatusBadge({ status }: { status: BatchResultEntry["status"] }) {
  switch (status) {
    case "pending":
      return (
        <Badge variant="outline" className="gap-1">
          <Clock className="h-3 w-3" />
          Pending
        </Badge>
      )
    case "loading":
      return (
        <Badge variant="secondary" className="gap-1">
          <Loader2 className="h-3 w-3 animate-spin" />
          Loading
        </Badge>
      )
    case "ok":
      return (
        <Badge variant="default" className="gap-1">
          <CheckCircle2 className="h-3 w-3" />
          OK
        </Badge>
      )
    case "error":
      return (
        <Badge variant="destructive" className="gap-1">
          <XCircle className="h-3 w-3" />
          Error
        </Badge>
      )
  }
}

function BatchTab() {
  const [lookupType, setLookupType] = useState<BatchLookupType>("phone")
  const [rawInput, setRawInput] = useState("")
  const [results, setResults] = useState<BatchResultEntry[]>([])
  const [isRunning, setIsRunning] = useState(false)
  const [progress, setProgress] = useState({ completed: 0, total: 0 })
  const abortRef = useRef(false)

  const placeholderMap: Record<BatchLookupType, string> = {
    phone: "+15551234567\n+15559876543\n+15550001111",
    extension: "1001\n1002\n1003",
    device: "AA:BB:CC:DD:EE:FF\n11:22:33:44:55:66",
  }

  const handleRun = useCallback(async () => {
    const entries = parseBatchInput(rawInput)
    if (entries.length === 0) return

    abortRef.current = false
    setIsRunning(true)

    const initial: BatchResultEntry[] = entries.map((input) => ({
      input,
      status: "pending",
      summary: "",
    }))
    setResults(initial)
    setProgress({ completed: 0, total: entries.length })

    for (let i = 0; i < entries.length; i++) {
      if (abortRef.current) break

      setResults((prev) => prev.map((r, idx) => (idx === i ? { ...r, status: "loading" } : r)))

      const { sources, error } = await executeSingleLookup(lookupType, entries[i])

      setResults((prev) =>
        prev.map((r, idx) =>
          idx === i
            ? {
                ...r,
                status: error ? "error" : "ok",
                summary: error ? error : summarizeSources(sources),
                sources,
                error,
              }
            : r,
        ),
      )
      setProgress((prev) => ({ ...prev, completed: i + 1 }))
    }

    setIsRunning(false)
  }, [rawInput, lookupType])

  const handleStop = useCallback(() => {
    abortRef.current = true
  }, [])

  const entryCount = parseBatchInput(rawInput).length
  const hasResults = results.length > 0
  const completedResults = results.filter((r) => r.status === "ok" || r.status === "error")

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Batch Lookup</CardTitle>
          <p className="text-sm text-muted-foreground">Look up multiple values at once. Enter one value per line.</p>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-end">
            <div className="w-full sm:w-48 space-y-1.5">
              <label htmlFor="batch-type" className="text-sm font-medium">
                Lookup Type
              </label>
              <Select value={lookupType} onValueChange={(v) => setLookupType(v as BatchLookupType)}>
                <SelectTrigger id="batch-type">
                  <SelectValue placeholder="Select type" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="phone">
                    <span className="flex items-center gap-2">
                      <Phone className="h-3.5 w-3.5" />
                      Phone Number
                    </span>
                  </SelectItem>
                  <SelectItem value="extension">
                    <span className="flex items-center gap-2">
                      <Hash className="h-3.5 w-3.5" />
                      Extension
                    </span>
                  </SelectItem>
                  <SelectItem value="device">
                    <span className="flex items-center gap-2">
                      <Monitor className="h-3.5 w-3.5" />
                      Device (MAC)
                    </span>
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="space-y-1.5">
            <label htmlFor="batch-input" className="text-sm font-medium">
              Values (one per line)
            </label>
            <Textarea
              id="batch-input"
              placeholder={placeholderMap[lookupType]}
              value={rawInput}
              onChange={(e) => setRawInput(e.target.value)}
              rows={6}
              className="font-mono text-sm"
              disabled={isRunning}
            />
            {entryCount > 0 && (
              <p className="text-xs text-muted-foreground">
                {entryCount} {entryCount === 1 ? "entry" : "entries"} detected
              </p>
            )}
          </div>

          <div className="flex items-center gap-3">
            {isRunning ? (
              <Button variant="destructive" onClick={handleStop}>
                <XCircle className="mr-2 h-4 w-4" />
                Stop
              </Button>
            ) : (
              <Button onClick={handleRun} disabled={entryCount === 0}>
                <Search className="mr-2 h-4 w-4" />
                Look Up {entryCount > 0 ? `(${entryCount})` : ""}
              </Button>
            )}
            {hasResults && !isRunning && completedResults.length > 0 && (
              <Button variant="outline" onClick={() => exportBatchCsv(results, lookupType)}>
                <Download className="mr-2 h-4 w-4" />
                Export CSV
              </Button>
            )}
          </div>

          {isRunning && progress.total > 0 && (
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-xs text-muted-foreground">
                <span>
                  Processing {progress.completed} of {progress.total}
                </span>
                <span>{Math.round((progress.completed / progress.total) * 100)}%</span>
              </div>
              <div className="h-2 w-full overflow-hidden rounded-full bg-secondary">
                <div className="h-full bg-primary transition-all duration-300 ease-out" style={{ width: `${(progress.completed / progress.total) * 100}%` }} />
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {hasResults && (
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-base">Results</CardTitle>
              {!isRunning && (
                <p className="text-sm text-muted-foreground">
                  {completedResults.filter((r) => r.status === "ok").length} succeeded, {completedResults.filter((r) => r.status === "error").length} failed
                </p>
              )}
            </div>
          </CardHeader>
          <CardContent>
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[200px]">Input</TableHead>
                    <TableHead className="w-[100px]">Status</TableHead>
                    <TableHead>Summary</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {results.map((r, idx) => (
                    <TableRow key={`${r.input}-${idx}`}>
                      <TableCell className="font-mono text-sm">{r.input}</TableCell>
                      <TableCell>
                        <BatchStatusBadge status={r.status} />
                      </TableCell>
                      <TableCell className="text-sm">{r.summary || "--"}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

// -- Main page ----------------------------------------------------------------

function GatewayPage() {
  useDocumentTitle("Gateway")
  const { tab = "phone" } = Route.useSearch()
  const navigate = Route.useNavigate()

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Tools"
        title="Gateway Lookup"
        description="Search for phone numbers, extensions, and devices across all configured connections."
        breadcrumbs={
          <Breadcrumb>
            <BreadcrumbList>
              <BreadcrumbItem>
                <BreadcrumbLink asChild>
                  <Link to="/home">Home</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbPage>Gateway</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
      />

      <PageSection>
        <Tabs value={tab} onValueChange={(value) => navigate({ search: () => ({ tab: value }), replace: true })}>
          <TabsList>
            <TabsTrigger value="phone" className="gap-1.5">
              <Phone className="h-4 w-4" />
              Phone Number
            </TabsTrigger>
            <TabsTrigger value="extension" className="gap-1.5">
              <Hash className="h-4 w-4" />
              Extension
            </TabsTrigger>
            <TabsTrigger value="device" className="gap-1.5">
              <Monitor className="h-4 w-4" />
              Device
            </TabsTrigger>
            <TabsTrigger value="batch" className="gap-1.5">
              <Layers className="h-4 w-4" />
              Batch
            </TabsTrigger>
          </TabsList>

          <TabsContent value="phone" className="mt-6">
            <SectionErrorBoundary name="Phone Number Lookup">
              <PhoneNumberTab />
            </SectionErrorBoundary>
          </TabsContent>

          <TabsContent value="extension" className="mt-6">
            <SectionErrorBoundary name="Extension Lookup">
              <ExtensionTab />
            </SectionErrorBoundary>
          </TabsContent>

          <TabsContent value="device" className="mt-6">
            <SectionErrorBoundary name="Device Lookup">
              <DeviceTab />
            </SectionErrorBoundary>
          </TabsContent>

          <TabsContent value="batch" className="mt-6">
            <SectionErrorBoundary name="Batch Lookup">
              <BatchTab />
            </SectionErrorBoundary>
          </TabsContent>
        </Tabs>
      </PageSection>
    </PageContainer>
  )
}
