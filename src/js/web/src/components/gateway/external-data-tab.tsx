import { Info, Loader2, RefreshCw } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import type { SourceResult } from "@/lib/generated/api"

// ---------------------------------------------------------------------------
// Status badge
// ---------------------------------------------------------------------------

const statusConfig: Record<string, { label: string; variant: "default" | "destructive" | "outline"; className?: string }> = {
  ok: { label: "OK", variant: "default", className: "bg-green-600 hover:bg-green-600 text-white" },
  error: { label: "Error", variant: "destructive" },
  timeout: { label: "Timeout", variant: "outline", className: "border-yellow-500 text-yellow-600" },
  not_found: { label: "Not Found", variant: "outline" },
}

function StatusBadge({ status }: { status: string }) {
  const cfg = statusConfig[status] ?? { label: status, variant: "outline" as const }
  return (
    <Badge variant={cfg.variant} className={cfg.className}>
      {cfg.label}
    </Badge>
  )
}

// ---------------------------------------------------------------------------
// Data grid for key-value pairs
// ---------------------------------------------------------------------------

function formatKey(key: string): string {
  return key
    .replace(/([A-Z])/g, " $1")
    .replace(/_/g, " ")
    .replace(/^\w/, (c) => c.toUpperCase())
    .trim()
}

function renderValue(value: unknown): string {
  if (value === null || value === undefined) return "---"
  if (typeof value === "boolean") return value ? "Yes" : "No"
  if (typeof value === "object") return JSON.stringify(value, null, 2)
  return String(value)
}

function DataGrid({ data }: { data: Record<string, unknown> }) {
  const entries = Object.entries(data)
  if (entries.length === 0) {
    return <p className="text-sm text-muted-foreground">No data returned</p>
  }

  // Separate simple vs complex values
  const simple: [string, unknown][] = []
  const complex: [string, unknown][] = []
  for (const [k, v] of entries) {
    if (typeof v === "object" && v !== null && !Array.isArray(v)) {
      complex.push([k, v])
    } else if (Array.isArray(v)) {
      complex.push([k, v])
    } else {
      simple.push([k, v])
    }
  }

  return (
    <div className="space-y-4">
      {simple.length > 0 && (
        <div className="grid gap-x-6 gap-y-3 text-sm md:grid-cols-2 lg:grid-cols-3">
          {simple.map(([key, val]) => (
            <div key={key}>
              <p className="text-muted-foreground">{formatKey(key)}</p>
              <p className="font-mono text-xs break-all">{renderValue(val)}</p>
            </div>
          ))}
        </div>
      )}
      {complex.map(([key, val]) => (
        <div key={key}>
          <p className="mb-1 text-sm font-medium text-muted-foreground">{formatKey(key)}</p>
          <pre className="overflow-x-auto rounded-md bg-muted/50 p-3 font-mono text-xs">
            {JSON.stringify(val, null, 2)}
          </pre>
        </div>
      ))}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Source card
// ---------------------------------------------------------------------------

function SourceCard({ source }: { source: SourceResult }) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between pb-3">
        <CardTitle className="text-sm">{source.connectionName}</CardTitle>
        <StatusBadge status={source.status} />
      </CardHeader>
      <CardContent>
        {source.status === "error" && source.error ? (
          <p className="text-sm text-destructive">{source.error}</p>
        ) : source.status === "timeout" ? (
          <p className="text-sm text-yellow-600">Request to this source timed out. Try refreshing.</p>
        ) : source.status === "not_found" ? (
          <p className="text-sm text-muted-foreground">No data found at this source.</p>
        ) : source.data ? (
          <DataGrid data={source.data} />
        ) : (
          <p className="text-sm text-muted-foreground">No data returned</p>
        )}
      </CardContent>
    </Card>
  )
}

// ---------------------------------------------------------------------------
// Loading skeleton
// ---------------------------------------------------------------------------

function ExternalDataSkeleton() {
  return (
    <div className="space-y-4">
      {Array.from({ length: 2 }).map((_, i) => (
        <Card key={i}>
          <CardHeader className="flex flex-row items-center justify-between pb-3">
            <Skeleton className="h-5 w-32" />
            <Skeleton className="h-5 w-16 rounded-full" />
          </CardHeader>
          <CardContent>
            <div className="grid gap-x-6 gap-y-3 md:grid-cols-2 lg:grid-cols-3">
              {Array.from({ length: 6 }).map((_, j) => (
                <div key={j} className="space-y-1.5">
                  <Skeleton className="h-3.5 w-20" />
                  <Skeleton className="h-4 w-32" />
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  )
}

// ---------------------------------------------------------------------------
// No-identifier message
// ---------------------------------------------------------------------------

function NoIdentifierMessage({ message }: { message: string }) {
  return (
    <Card>
      <CardContent className="flex items-center gap-3 py-8">
        <Info className="h-5 w-5 text-muted-foreground" />
        <p className="text-sm text-muted-foreground">{message}</p>
      </CardContent>
    </Card>
  )
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

interface ExternalDataTabProps {
  /** Whether the identifier is available for lookup */
  hasIdentifier: boolean
  /** Message to show when no identifier is available */
  noIdentifierMessage: string
  /** The sources map from the gateway response */
  sources?: Record<string, SourceResult>
  /** Whether the query is currently loading */
  isLoading: boolean
  /** Whether the query is currently refetching */
  isRefetching: boolean
  /** Whether there was an error fetching */
  isError: boolean
  /** Refetch function */
  onRefresh: () => void
}

export function ExternalDataTab({
  hasIdentifier,
  noIdentifierMessage,
  sources,
  isLoading,
  isRefetching,
  isError,
  onRefresh,
}: ExternalDataTabProps) {
  if (!hasIdentifier) {
    return <NoIdentifierMessage message={noIdentifierMessage} />
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          Data fetched from external providers. This data is not stored locally.
        </p>
        <Button
          variant="outline"
          size="sm"
          onClick={onRefresh}
          disabled={isLoading || isRefetching}
        >
          {isLoading || isRefetching ? (
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
          ) : (
            <RefreshCw className="mr-2 h-4 w-4" />
          )}
          Refresh
        </Button>
      </div>

      {isLoading ? (
        <ExternalDataSkeleton />
      ) : isError ? (
        <Card>
          <CardContent className="py-8">
            <p className="text-sm text-destructive">
              Failed to load external data. Please try again.
            </p>
          </CardContent>
        </Card>
      ) : sources && Object.keys(sources).length > 0 ? (
        Object.entries(sources).map(([name, source]) => (
          <SourceCard key={name} source={source} />
        ))
      ) : (
        <Card>
          <CardContent className="flex items-center gap-3 py-8">
            <Info className="h-5 w-5 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">
              No external data sources returned results. Click Refresh to try again.
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
