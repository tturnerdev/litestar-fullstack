import { createFileRoute, Link } from "@tanstack/react-router"
import {
  AlertCircle,
  CheckCircle2,
  Clock,
  Hash,
  Loader2,
  Monitor,
  Phone,
  Search,
  ShieldAlert,
  XCircle,
} from "lucide-react"
import { useCallback, useState } from "react"
import { Badge } from "@/components/ui/badge"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import {
  useGatewayLookupDevice,
  useGatewayLookupExtension,
  useGatewayLookupNumber,
} from "@/lib/api/hooks/gateway"
import type { SourceResult } from "@/lib/generated/api"

export const Route = createFileRoute("/_app/gateway/")({
  component: GatewayPage,
})

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
    return (
      <div className="flex flex-wrap gap-1">
        {value.map((item, i) => (
          <Badge key={i} variant="outline" className="text-xs font-normal">
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
    return <p className="text-sm text-muted-foreground italic">No data</p>
  }
  return (
    <dl className={nested ? "space-y-1 pl-4 border-l border-border/40" : "space-y-2"}>
      {entries.map(([key, value]) => (
        <div key={key} className="flex flex-col gap-0.5 sm:flex-row sm:gap-3">
          <dt className="min-w-[140px] shrink-0 text-sm font-medium text-muted-foreground">
            {formatKey(key)}
          </dt>
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
          <div className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
            {result.error}
          </div>
        ) : result.data && Object.keys(result.data).length > 0 ? (
          <DataSection data={result.data} />
        ) : (
          <p className="text-sm text-muted-foreground italic">No data returned</p>
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
      <div className="flex items-center justify-center py-16">
        <div className="flex flex-col items-center gap-3">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
          <p className="text-sm text-muted-foreground">Querying connections...</p>
        </div>
      </div>
    )
  }

  if (isError) {
    return (
      <EmptyState
        icon={AlertCircle}
        title="Lookup failed"
        description={error?.message ?? "An unexpected error occurred. Please try again."}
      />
    )
  }

  if (!hasSearched) {
    return (
      <EmptyState
        icon={Search}
        title="Enter a value to look up"
        description="Search across all configured connections to find matching records."
      />
    )
  }

  if (!sources || Object.keys(sources).length === 0) {
    return (
      <EmptyState
        icon={Search}
        variant="no-results"
        title="No sources returned"
        description="No connections returned results for this lookup. Verify the value and try again."
      />
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
  const query = useGatewayLookupNumber(searchValue)

  const handleLookup = useCallback(() => {
    const trimmed = input.trim()
    if (!trimmed) return
    setSearchValue(trimmed)
    // setTimeout ensures the query key updates before refetch
    setTimeout(() => query.refetch(), 0)
  }, [input, query])

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "Enter") handleLookup()
    },
    [handleLookup],
  )

  return (
    <div className="space-y-6">
      <div className="flex items-end gap-3">
        <div className="flex-1 max-w-md space-y-1.5">
          <label htmlFor="phone-input" className="text-sm font-medium">
            Phone Number
          </label>
          <Input
            id="phone-input"
            placeholder="e.g. +15551234567"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
          />
        </div>
        <Button onClick={handleLookup} disabled={!input.trim() || query.isFetching}>
          {query.isFetching ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Search className="mr-2 h-4 w-4" />}
          Look Up
        </Button>
      </div>
      <LookupResults
        sources={query.data?.sources}
        isLoading={query.isFetching}
        isError={query.isError}
        error={query.error}
        hasSearched={query.isSuccess || query.isError}
      />
    </div>
  )
}

function ExtensionTab() {
  const [input, setInput] = useState("")
  const [searchValue, setSearchValue] = useState("")
  const query = useGatewayLookupExtension(searchValue)

  const handleLookup = useCallback(() => {
    const trimmed = input.trim()
    if (!trimmed) return
    setSearchValue(trimmed)
    setTimeout(() => query.refetch(), 0)
  }, [input, query])

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "Enter") handleLookup()
    },
    [handleLookup],
  )

  return (
    <div className="space-y-6">
      <div className="flex items-end gap-3">
        <div className="flex-1 max-w-md space-y-1.5">
          <label htmlFor="ext-input" className="text-sm font-medium">
            Extension Number
          </label>
          <Input
            id="ext-input"
            placeholder="e.g. 1001"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
          />
        </div>
        <Button onClick={handleLookup} disabled={!input.trim() || query.isFetching}>
          {query.isFetching ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Search className="mr-2 h-4 w-4" />}
          Look Up
        </Button>
      </div>
      <LookupResults
        sources={query.data?.sources}
        isLoading={query.isFetching}
        isError={query.isError}
        error={query.error}
        hasSearched={query.isSuccess || query.isError}
      />
    </div>
  )
}

function DeviceTab() {
  const [input, setInput] = useState("")
  const [searchValue, setSearchValue] = useState("")
  const query = useGatewayLookupDevice(searchValue)

  const handleLookup = useCallback(() => {
    const trimmed = input.trim()
    if (!trimmed) return
    setSearchValue(trimmed)
    setTimeout(() => query.refetch(), 0)
  }, [input, query])

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "Enter") handleLookup()
    },
    [handleLookup],
  )

  return (
    <div className="space-y-6">
      <div className="flex items-end gap-3">
        <div className="flex-1 max-w-md space-y-1.5">
          <label htmlFor="mac-input" className="text-sm font-medium">
            MAC Address
          </label>
          <Input
            id="mac-input"
            placeholder="e.g. AA:BB:CC:DD:EE:FF"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
          />
        </div>
        <Button onClick={handleLookup} disabled={!input.trim() || query.isFetching}>
          {query.isFetching ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Search className="mr-2 h-4 w-4" />}
          Look Up
        </Button>
      </div>
      <LookupResults
        sources={query.data?.sources}
        isLoading={query.isFetching}
        isError={query.isError}
        error={query.error}
        hasSearched={query.isSuccess || query.isError}
      />
    </div>
  )
}

// -- Main page ----------------------------------------------------------------

function GatewayPage() {
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
        <Tabs defaultValue="phone">
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
          </TabsList>

          <TabsContent value="phone" className="mt-6">
            <PhoneNumberTab />
          </TabsContent>

          <TabsContent value="extension" className="mt-6">
            <ExtensionTab />
          </TabsContent>

          <TabsContent value="device" className="mt-6">
            <DeviceTab />
          </TabsContent>
        </Tabs>
      </PageSection>
    </PageContainer>
  )
}
