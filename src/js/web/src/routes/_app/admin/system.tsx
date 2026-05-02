import { useQuery } from "@tanstack/react-query"
import { createFileRoute, Link } from "@tanstack/react-router"
import {
  Activity,
  AlertCircle,
  ArrowUpFromDot,
  BarChart3,
  Cable,
  CheckCircle2,
  Circle,
  Clock,
  Cpu,
  Database,
  ExternalLink,
  Gauge,
  HardDrive,
  Layers,
  Loader2,
  Radio,
  RefreshCw,
  Server,
  XCircle,
  Zap,
} from "lucide-react"
import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { Area, AreaChart, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer, XAxis, YAxis } from "recharts"
import { AdminBreadcrumbs } from "@/components/admin/admin-breadcrumbs"
import { AdminNav } from "@/components/admin/admin-nav"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { DataFreshness } from "@/components/ui/data-freshness"
import { EmptyState } from "@/components/ui/empty-state"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { Separator } from "@/components/ui/separator"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { useAdminSystemStatus } from "@/lib/api/hooks/admin"
import { useConnections, useTestAnyConnection } from "@/lib/api/hooks/connections"
import { sseStatus } from "@/lib/api/hooks/events"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"
import { formatUptime } from "@/lib/format-utils"
import { type SystemHealth, systemHealth } from "@/lib/generated/api"

export const Route = createFileRoute("/_app/admin/system")({
  component: AdminSystemPage,
})

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function useTimeSince(timestamp: string | undefined) {
  const [, setTick] = useState(0)
  useEffect(() => {
    if (!timestamp) return
    const id = setInterval(() => setTick((t) => t + 1), 1000)
    return () => clearInterval(id)
  }, [timestamp])

  if (!timestamp) return null
  const elapsed = Math.floor((Date.now() - new Date(timestamp).getTime()) / 1000)
  return formatUptime(Math.max(0, elapsed), true)
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function StatusDot({ ok, label }: { ok: boolean; label?: string }) {
  const statusLabel = label ?? (ok ? "Healthy" : "Unhealthy")
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="relative flex h-2.5 w-2.5">
          {ok && <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-40" />}
          <span className={`relative inline-flex h-2.5 w-2.5 rounded-full ${ok ? "bg-emerald-500" : "bg-destructive"}`} />
        </span>
      </TooltipTrigger>
      <TooltipContent side="top" className="text-xs">
        {statusLabel}
      </TooltipContent>
    </Tooltip>
  )
}

function OverallHealthBanner({ healthy }: { healthy: boolean }) {
  return (
    <div
      className={`flex items-center gap-3 rounded-lg border px-4 py-3 ${
        healthy ? "border-emerald-500/20 bg-emerald-500/5 text-emerald-700 dark:text-emerald-400" : "border-destructive/20 bg-destructive/5 text-destructive"
      }`}
    >
      {healthy ? <CheckCircle2 className="h-5 w-5" /> : <XCircle className="h-5 w-5" />}
      <div>
        <p className="text-sm font-semibold">{healthy ? "All Systems Operational" : "Issue Detected"}</p>
        <p className="text-xs opacity-75">{healthy ? "All services are running normally." : "One or more services are reporting problems."}</p>
      </div>
    </div>
  )
}

function UptimeBanner({ startedAt, uptimeSeconds }: { startedAt: string; uptimeSeconds: number }) {
  const liveUptime = useTimeSince(startedAt)
  const display = liveUptime ?? formatUptime(uptimeSeconds, true)

  // Parse into segments for the large display
  const totalSec = startedAt ? Math.max(0, Math.floor((Date.now() - new Date(startedAt).getTime()) / 1000)) : uptimeSeconds
  const days = Math.floor(totalSec / 86400)
  const hours = Math.floor((totalSec % 86400) / 3600)
  const minutes = Math.floor((totalSec % 3600) / 60)

  return (
    <Card>
      <CardContent className="flex items-center gap-4 p-4">
        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
          <ArrowUpFromDot className="h-5 w-5" />
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-xs font-medium text-muted-foreground">Uptime</p>
          <div className="flex items-baseline gap-1">
            {days > 0 && (
              <>
                <span className="text-2xl font-bold tabular-nums">{days}</span>
                <span className="text-sm text-muted-foreground">d</span>
              </>
            )}
            <span className="text-2xl font-bold tabular-nums">{hours}</span>
            <span className="text-sm text-muted-foreground">h</span>
            <span className="text-2xl font-bold tabular-nums">{minutes}</span>
            <span className="text-sm text-muted-foreground">m</span>
          </div>
        </div>
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="shrink-0 cursor-default text-xs text-muted-foreground">since {formatDateTime(startedAt)}</span>
          </TooltipTrigger>
          <TooltipContent side="top" className="text-xs">
            {display}
          </TooltipContent>
        </Tooltip>
      </CardContent>
    </Card>
  )
}

// ---------------------------------------------------------------------------
// System Health Indicators
// ---------------------------------------------------------------------------

const HEALTH_CHECK_INTERVAL = 30_000

type HealthStatus = "healthy" | "degraded" | "unhealthy" | "unknown"

interface HealthIndicator {
  name: string
  icon: typeof Server
  status: HealthStatus
  detail: string
}

function useSystemHealthCheck(autoRefreshEnabled: boolean) {
  return useQuery({
    queryKey: ["system", "health-check"],
    queryFn: async () => {
      const response = await systemHealth()
      return response.data as SystemHealth
    },
    refetchInterval: autoRefreshEnabled ? HEALTH_CHECK_INTERVAL : false,
    retry: 1,
  })
}

function healthStatusColor(status: HealthStatus) {
  switch (status) {
    case "healthy":
      return {
        dot: "bg-emerald-500",
        ping: "bg-emerald-400",
        icon: "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
        badge: "text-emerald-600 dark:text-emerald-400",
        badgeVariant: "outline" as const,
        label: "Healthy",
      }
    case "degraded":
      return {
        dot: "bg-amber-500",
        ping: "bg-amber-400",
        icon: "bg-amber-500/10 text-amber-600 dark:text-amber-400",
        badge: "text-amber-600 dark:text-amber-400",
        badgeVariant: "outline" as const,
        label: "Degraded",
      }
    case "unhealthy":
      return {
        dot: "bg-destructive",
        ping: "",
        icon: "bg-destructive/10 text-destructive",
        badge: "",
        badgeVariant: "destructive" as const,
        label: "Unhealthy",
      }
    case "unknown":
      return {
        dot: "bg-muted-foreground",
        ping: "",
        icon: "bg-muted text-muted-foreground",
        badge: "",
        badgeVariant: "secondary" as const,
        label: "Unknown",
      }
  }
}

function HealthIndicatorCard({ indicator }: { indicator: HealthIndicator }) {
  const Icon = indicator.icon
  const colors = healthStatusColor(indicator.status)
  const showPing = indicator.status === "healthy" || indicator.status === "degraded"

  return (
    <Card>
      <CardContent className="flex items-center gap-3 p-4">
        <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg ${colors.icon}`}>
          <Icon className="h-5 w-5" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center justify-between">
            <p className="text-sm font-medium">{indicator.name}</p>
            <div className="flex items-center gap-2">
              <Badge variant={colors.badgeVariant} className={`text-[10px] ${colors.badge}`}>
                {colors.label}
              </Badge>
              <span className="relative flex h-2.5 w-2.5">
                {showPing && <span className={`absolute inline-flex h-full w-full animate-ping rounded-full ${colors.ping} opacity-40`} />}
                <span className={`relative inline-flex h-2.5 w-2.5 rounded-full ${colors.dot}`} />
              </span>
            </div>
          </div>
          <p className="text-xs text-muted-foreground">{indicator.detail}</p>
        </div>
      </CardContent>
    </Card>
  )
}

function SystemHealthIndicators({ autoRefresh }: { autoRefresh: boolean }) {
  const { data: healthData, isError: healthError, dataUpdatedAt, refetch, isFetching } = useSystemHealthCheck(autoRefresh)

  // Live "last checked X ago" ticker
  const [, setTick] = useState(0)
  useEffect(() => {
    const id = setInterval(() => setTick((t) => t + 1), 5_000)
    return () => clearInterval(id)
  }, [])

  // Read SSE status reactively by polling the module-level object
  const [sseConnected, setSseConnected] = useState(sseStatus.connected)
  useEffect(() => {
    const id = setInterval(() => setSseConnected(sseStatus.connected), 2_000)
    return () => clearInterval(id)
  }, [])

  // Determine individual statuses
  const apiStatus: HealthStatus = healthError ? "unhealthy" : healthData ? "healthy" : "unknown"
  const dbStatus: HealthStatus = healthError ? "unknown" : healthData?.databaseStatus === "online" ? "healthy" : healthData?.databaseStatus === "offline" ? "unhealthy" : "unknown"
  const redisStatus: HealthStatus = healthError ? "unknown" : healthData ? "healthy" : "unknown"
  const sseIndicatorStatus: HealthStatus = sseConnected ? "healthy" : "degraded"

  const indicators: HealthIndicator[] = [
    {
      name: "API Server",
      icon: Server,
      status: apiStatus,
      detail: apiStatus === "healthy" ? `v${healthData?.version ?? "?"} -- ${healthData?.app ?? "Litestar"}` : apiStatus === "unhealthy" ? "Endpoint unreachable" : "Checking...",
    },
    {
      name: "Database",
      icon: Database,
      status: dbStatus,
      detail: dbStatus === "healthy" ? "PostgreSQL connected" : dbStatus === "unhealthy" ? "Connection failed" : "Status unavailable",
    },
    {
      name: "Redis / Queue",
      icon: Zap,
      status: redisStatus,
      detail: redisStatus === "healthy" ? "Broker reachable" : "Status unavailable",
    },
    {
      name: "SSE Connection",
      icon: Radio,
      status: sseIndicatorStatus,
      detail: sseConnected ? "Real-time events active" : sseStatus.disconnectedSince ? `Disconnected ${formatTimeSince(new Date(sseStatus.disconnectedSince))}` : "Reconnecting...",
    },
  ]

  const lastCheckedLabel = dataUpdatedAt > 0 ? `Last checked: ${formatTimeSince(new Date(dataUpdatedAt))}` : "Checking..."

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="space-y-1">
            <CardTitle className="flex items-center gap-2 text-base">
              <Activity className="h-4 w-4 text-muted-foreground" />
              System Health
            </CardTitle>
            <CardDescription>Real-time health indicators for core subsystems.</CardDescription>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-[11px] text-muted-foreground">{lastCheckedLabel}</span>
            <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching} aria-label="Refresh health checks">
              <RefreshCw className={`h-3.5 w-3.5 ${isFetching ? "animate-spin" : ""}`} />
              Refresh
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          {indicators.map((indicator) => (
            <HealthIndicatorCard key={indicator.name} indicator={indicator} />
          ))}
        </div>
      </CardContent>
    </Card>
  )
}

function ServiceStatusGrid({
  databaseStatus,
  workerQueues,
}: {
  databaseStatus: "online" | "offline"
  workerQueues?: Array<{ name: string; active?: number; queued?: number; scheduled?: number }>
}) {
  const dbOnline = databaseStatus === "online"
  const hasWorkers = workerQueues && workerQueues.length > 0

  const services = [
    {
      name: "Database",
      icon: Database,
      status: dbOnline ? ("healthy" as const) : ("down" as const),
      detail: dbOnline ? "PostgreSQL" : "Connection failed",
    },
    {
      name: "Cache / Queue Broker",
      icon: Zap,
      status: hasWorkers ? ("healthy" as const) : ("unknown" as const),
      detail: hasWorkers ? "Redis" : "Not detected",
    },
    {
      name: "Task Workers",
      icon: Cpu,
      status: hasWorkers ? ("healthy" as const) : ("unknown" as const),
      detail: hasWorkers ? `${workerQueues.length} queue${workerQueues.length !== 1 ? "s" : ""}` : "No workers running",
    },
    {
      name: "Application Server",
      icon: Server,
      status: "healthy" as const,
      detail: "Litestar",
    },
  ]

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Layers className="h-4 w-4 text-muted-foreground" />
          Service Status
        </CardTitle>
        <CardDescription>Health and connectivity of core infrastructure services.</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="grid gap-3 sm:grid-cols-2">
          {services.map((svc) => {
            const SvcIcon = svc.icon
            const isHealthy = svc.status === "healthy"
            const isUnknown = svc.status === "unknown"
            return (
              <div key={svc.name} className="flex items-center justify-between rounded-lg border px-4 py-3">
                <div className="flex items-center gap-3">
                  <div
                    className={`flex h-8 w-8 items-center justify-center rounded-md ${
                      isHealthy ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400" : isUnknown ? "bg-muted text-muted-foreground" : "bg-destructive/10 text-destructive"
                    }`}
                  >
                    <SvcIcon className="h-4 w-4" />
                  </div>
                  <div>
                    <p className="text-sm font-medium">{svc.name}</p>
                    <p className="text-xs text-muted-foreground">{svc.detail}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Badge
                    variant={isHealthy ? "outline" : isUnknown ? "secondary" : "destructive"}
                    className={`text-[10px] ${isHealthy ? "text-emerald-600 dark:text-emerald-400" : ""}`}
                  >
                    {isHealthy ? "Healthy" : isUnknown ? "N/A" : "Down"}
                  </Badge>
                  {!isUnknown && <StatusDot ok={isHealthy} />}
                </div>
              </div>
            )
          })}
        </div>
      </CardContent>
    </Card>
  )
}

function SystemInfoCard({
  appName,
  appVersion,
  pythonVersion,
  uptimeSeconds,
  startedAt,
  debugMode,
}: {
  appName: string
  appVersion: string
  pythonVersion: string
  uptimeSeconds: number
  startedAt: string
  debugMode: boolean
}) {
  const liveUptime = useTimeSince(startedAt)

  const rows = [
    { label: "Application", value: appName, icon: Server },
    { label: "App Version", value: appVersion, icon: Activity, mono: true },
    { label: "Python Version", value: pythonVersion, icon: HardDrive, mono: true },
    {
      label: "Uptime",
      value: liveUptime ?? formatUptime(uptimeSeconds, true),
      icon: Clock,
    },
    {
      label: "Started",
      value: formatDateTime(startedAt),
      icon: Zap,
    },
  ]

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Server className="h-4 w-4 text-muted-foreground" />
          System Information
        </CardTitle>
        <CardDescription>Application runtime and environment details.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-1">
        {rows.map((row) => {
          const RowIcon = row.icon
          return (
            <div key={row.label} className="flex items-center justify-between rounded-md px-2 py-2">
              <div className="flex items-center gap-2.5">
                <RowIcon className="h-3.5 w-3.5 text-muted-foreground" />
                <span className="text-sm text-muted-foreground">{row.label}</span>
              </div>
              <span className={`text-sm font-medium ${row.mono ? "font-mono" : ""}`}>{row.value}</span>
            </div>
          )
        })}
        {debugMode && (
          <>
            <Separator className="my-2" />
            <div className="flex items-center justify-between rounded-md px-2 py-2">
              <span className="text-sm text-muted-foreground">Debug Mode</span>
              <Badge variant="secondary" className="text-[10px]">
                Enabled
              </Badge>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  )
}

function WorkerQueuesCard({ queues }: { queues: Array<{ name: string; active?: number; queued?: number; scheduled?: number }> }) {
  const totalActive = queues.reduce((sum, q) => sum + (q.active ?? 0), 0)
  const totalQueued = queues.reduce((sum, q) => sum + (q.queued ?? 0), 0)
  const totalScheduled = queues.reduce((sum, q) => sum + (q.scheduled ?? 0), 0)

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Cpu className="h-4 w-4 text-muted-foreground" />
          Worker Queues
        </CardTitle>
        <CardDescription>Background job processing status across all queues.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Summary counters */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="rounded-lg border bg-muted/30 px-4 py-3 text-center">
            <p className="text-2xl font-bold tabular-nums">{totalActive}</p>
            <p className="text-xs text-muted-foreground">Active</p>
          </div>
          <div className="rounded-lg border bg-muted/30 px-4 py-3 text-center">
            <p className="text-2xl font-bold tabular-nums">{totalQueued}</p>
            <p className="text-xs text-muted-foreground">Pending</p>
          </div>
          <div className="rounded-lg border bg-muted/30 px-4 py-3 text-center">
            <p className="text-2xl font-bold tabular-nums">{totalScheduled}</p>
            <p className="text-xs text-muted-foreground">Scheduled</p>
          </div>
        </div>

        <Separator />

        {/* Per-queue rows with progress visualization */}
        <div className="space-y-3">
          {queues.map((queue) => {
            const active = queue.active ?? 0
            const queued = queue.queued ?? 0
            const scheduled = queue.scheduled ?? 0
            const total = active + queued + scheduled
            const isIdle = total === 0

            // Compute segment percentages for the stacked bar
            const activePct = total > 0 ? (active / total) * 100 : 0
            const queuedPct = total > 0 ? (queued / total) * 100 : 0
            const scheduledPct = total > 0 ? (scheduled / total) * 100 : 0

            return (
              <div key={queue.name} className="rounded-lg border px-4 py-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <StatusDot ok label={isIdle ? "Idle" : `${total} job${total !== 1 ? "s" : ""}`} />
                    <div>
                      <p className="text-sm font-medium">{queue.name}</p>
                      <p className="text-xs text-muted-foreground">{isIdle ? "No active jobs" : `${active} active, ${queued} pending, ${scheduled} scheduled`}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-1.5">
                    {active > 0 && (
                      <Badge variant="default" className="h-5 px-1.5 text-[10px]">
                        {active} active
                      </Badge>
                    )}
                    {queued > 0 && (
                      <Badge variant="secondary" className="h-5 px-1.5 text-[10px]">
                        {queued} queued
                      </Badge>
                    )}
                    {scheduled > 0 && (
                      <Badge variant="outline" className="h-5 px-1.5 text-[10px]">
                        {scheduled} sched
                      </Badge>
                    )}
                    {isIdle && <span className="text-xs text-muted-foreground">idle</span>}
                  </div>
                </div>
                {/* Stacked progress bar */}
                {!isIdle && (
                  <div className="mt-2.5">
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <div className="flex h-2 w-full overflow-hidden rounded-full bg-muted">
                          {activePct > 0 && <div className="h-full bg-primary transition-all duration-300" style={{ width: `${activePct}%` }} />}
                          {queuedPct > 0 && <div className="h-full bg-amber-500 transition-all duration-300" style={{ width: `${queuedPct}%` }} />}
                          {scheduledPct > 0 && <div className="h-full bg-muted-foreground/30 transition-all duration-300" style={{ width: `${scheduledPct}%` }} />}
                        </div>
                      </TooltipTrigger>
                      <TooltipContent side="bottom" className="text-xs">
                        {active} active / {queued} pending / {scheduled} scheduled
                      </TooltipContent>
                    </Tooltip>
                    {/* Legend */}
                    <div className="mt-1.5 flex items-center gap-3">
                      <div className="flex items-center gap-1">
                        <span className="inline-block h-2 w-2 rounded-full bg-primary" />
                        <span className="text-[10px] text-muted-foreground">Active</span>
                      </div>
                      <div className="flex items-center gap-1">
                        <span className="inline-block h-2 w-2 rounded-full bg-amber-500" />
                        <span className="text-[10px] text-muted-foreground">Pending</span>
                      </div>
                      <div className="flex items-center gap-1">
                        <span className="inline-block h-2 w-2 rounded-full bg-muted-foreground/30" />
                        <span className="text-[10px] text-muted-foreground">Scheduled</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </CardContent>
    </Card>
  )
}

// ---------------------------------------------------------------------------
// External Connections Overview
// ---------------------------------------------------------------------------

const connectionStatusConfig: Record<string, { icon: typeof CheckCircle2; colorClass: string; label: string }> = {
  connected: { icon: CheckCircle2, colorClass: "text-emerald-600 dark:text-emerald-400", label: "Connected" },
  error: { icon: AlertCircle, colorClass: "text-destructive", label: "Error" },
  disconnected: { icon: XCircle, colorClass: "text-muted-foreground", label: "Disconnected" },
  unknown: { icon: Circle, colorClass: "text-muted-foreground", label: "Unknown" },
}

const typeLabels: Record<string, string> = {
  pbx: "PBX",
  helpdesk: "Helpdesk",
  carrier: "Carrier",
  network: "Network",
  other: "Other",
}

function ExternalConnectionsCard() {
  const { data, isLoading } = useConnections({ page: 1, pageSize: 100 })
  const testConnection = useTestAnyConnection()
  const [testingAll, setTestingAll] = useState(false)

  const connections = data?.items ?? []
  const connectedCount = connections.filter((c) => c.status === "connected").length
  const totalCount = connections.length

  const handleTestAll = useCallback(async () => {
    if (testingAll || connections.length === 0) return
    setTestingAll(true)
    try {
      for (const conn of connections) {
        await testConnection.mutateAsync(conn.id)
      }
    } finally {
      setTestingAll(false)
    }
  }, [testingAll, connections, testConnection])

  if (isLoading) {
    return <SkeletonCard />
  }

  if (totalCount === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Cable className="h-4 w-4 text-muted-foreground" />
            External Connections
          </CardTitle>
          <CardDescription>Status overview of configured integrations.</CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            No connections configured.{" "}
            <Link to="/connections/new" className="text-primary underline-offset-4 hover:underline">
              Add one
            </Link>
            .
          </p>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="space-y-1">
            <CardTitle className="flex items-center gap-2 text-base">
              <Cable className="h-4 w-4 text-muted-foreground" />
              External Connections
              <Badge variant="secondary" className="ml-1 text-[10px]">
                {connectedCount} of {totalCount} connected
              </Badge>
            </CardTitle>
            <CardDescription>Status overview of configured integrations.</CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={handleTestAll} disabled={testingAll}>
              {testingAll ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : <Zap className="mr-1.5 h-3.5 w-3.5" />}
              Test All
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-2">
        {connections.map((conn) => {
          const config = connectionStatusConfig[conn.status] ?? connectionStatusConfig.unknown
          const StatusIcon = config.icon
          const isCurrentlyTesting = testConnection.isPending && testConnection.variables === conn.id
          return (
            <div key={conn.id} className="flex items-center justify-between rounded-lg border px-4 py-3">
              <div className="flex items-center gap-3">
                <Tooltip>
                  <TooltipTrigger asChild>
                    <span className={`flex items-center ${config.colorClass}`}>
                      {isCurrentlyTesting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <StatusIcon className="h-3.5 w-3.5" />}
                    </span>
                  </TooltipTrigger>
                  <TooltipContent side="top" className="text-xs">
                    {isCurrentlyTesting ? "Testing..." : config.label}
                    {conn.lastError && conn.status === "error" ? `: ${conn.lastError}` : ""}
                  </TooltipContent>
                </Tooltip>
                <div>
                  <p className="text-sm font-medium">{conn.name}</p>
                  <p className="text-xs text-muted-foreground">{conn.provider}</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Badge variant="outline" className="text-[10px]">
                  {typeLabels[conn.connectionType] ?? conn.connectionType}
                </Badge>
                {conn.lastHealthCheck && (
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <span className="cursor-default text-[10px] text-muted-foreground">{formatRelativeTimeShort(conn.lastHealthCheck)}</span>
                    </TooltipTrigger>
                    <TooltipContent className="text-xs">{formatDateTime(conn.lastHealthCheck)}</TooltipContent>
                  </Tooltip>
                )}
              </div>
            </div>
          )
        })}
        <div className="pt-1">
          <Link to="/connections" className="inline-flex items-center gap-1 text-xs text-primary underline-offset-4 hover:underline">
            Manage connections
            <ExternalLink className="h-3 w-3" />
          </Link>
        </div>
      </CardContent>
    </Card>
  )
}

// ---------------------------------------------------------------------------
// Worker Queue History Chart
// ---------------------------------------------------------------------------

interface QueueSnapshot {
  time: string
  active: number
  queued: number
  scheduled: number
}

const MAX_HISTORY_POINTS = 20

function useQueueHistory(queues: Array<{ name: string; active?: number; queued?: number; scheduled?: number }> | undefined) {
  const historyRef = useRef<QueueSnapshot[]>([])
  const lastUpdateRef = useRef<number>(0)

  useEffect(() => {
    if (!queues) return
    const now = Date.now()
    // Throttle: only add a point every 10 seconds minimum
    if (now - lastUpdateRef.current < 10_000 && historyRef.current.length > 0) return
    lastUpdateRef.current = now

    const totalActive = queues.reduce((sum, q) => sum + (q.active ?? 0), 0)
    const totalQueued = queues.reduce((sum, q) => sum + (q.queued ?? 0), 0)
    const totalScheduled = queues.reduce((sum, q) => sum + (q.scheduled ?? 0), 0)

    const snapshot: QueueSnapshot = {
      time: new Date(now).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
      active: totalActive,
      queued: totalQueued,
      scheduled: totalScheduled,
    }
    historyRef.current = [...historyRef.current.slice(-(MAX_HISTORY_POINTS - 1)), snapshot]
  }, [queues])

  return historyRef.current
}

function WorkerQueueHistoryChart({ queues }: { queues?: Array<{ name: string; active?: number; queued?: number; scheduled?: number }> }) {
  const history = useQueueHistory(queues)

  // Calculate throughput estimate from snapshot deltas
  const throughputEstimate = useMemo(() => {
    if (!queues) return null
    const totalActive = queues.reduce((sum, q) => sum + (q.active ?? 0), 0)
    const totalQueued = queues.reduce((sum, q) => sum + (q.queued ?? 0), 0)
    const totalScheduled = queues.reduce((sum, q) => sum + (q.scheduled ?? 0), 0)
    const total = totalActive + totalQueued + totalScheduled
    if (total === 0 && totalActive === 0) return { rate: 0, label: "Idle" }
    // Estimate: active jobs are processing, so throughput ~ active jobs per refresh cycle
    return {
      rate: totalActive,
      label: totalActive > 0 ? `~${totalActive} jobs/cycle` : "Idle",
    }
  }, [queues])

  const hasHistory = history.length >= 2

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <BarChart3 className="h-4 w-4 text-muted-foreground" />
          Queue Activity
        </CardTitle>
        <CardDescription>{hasHistory ? "Job counts sampled over recent refreshes." : "Live throughput estimate based on current queue state."}</CardDescription>
      </CardHeader>
      <CardContent>
        {hasHistory ? (
          <div className="h-[200px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={history} margin={{ top: 8, right: 8, bottom: 0, left: -20 }}>
                <defs>
                  <linearGradient id="activeGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="hsl(var(--primary))" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="hsl(var(--primary))" stopOpacity={0.02} />
                  </linearGradient>
                  <linearGradient id="queuedGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="hsl(38 92% 50%)" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="hsl(38 92% 50%)" stopOpacity={0.02} />
                  </linearGradient>
                  <linearGradient id="scheduledGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="hsl(var(--muted-foreground))" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="hsl(var(--muted-foreground))" stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" opacity={0.5} />
                <XAxis dataKey="time" axisLine={false} tickLine={false} tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} dy={4} />
                <YAxis axisLine={false} tickLine={false} tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} allowDecimals={false} width={35} />
                <RechartsTooltip
                  contentStyle={{
                    backgroundColor: "hsl(var(--popover))",
                    border: "1px solid hsl(var(--border))",
                    borderRadius: "6px",
                    fontSize: "12px",
                  }}
                  labelStyle={{ color: "hsl(var(--popover-foreground))", fontWeight: 500 }}
                />
                <Area type="monotone" dataKey="active" name="Active" stroke="hsl(var(--primary))" fill="url(#activeGradient)" strokeWidth={2} />
                <Area type="monotone" dataKey="queued" name="Pending" stroke="hsl(38 92% 50%)" fill="url(#queuedGradient)" strokeWidth={2} />
                <Area
                  type="monotone"
                  dataKey="scheduled"
                  name="Scheduled"
                  stroke="hsl(var(--muted-foreground))"
                  fill="url(#scheduledGradient)"
                  strokeWidth={1.5}
                  strokeDasharray="4 2"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center py-8 text-center">
            <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-muted">
              <BarChart3 className="h-5 w-5 text-muted-foreground" />
            </div>
            <p className="text-sm font-medium">{(throughputEstimate?.rate ?? 0 > 0) ? "Processing" : "No Active Jobs"}</p>
            <p className="mt-1 text-xs text-muted-foreground">{throughputEstimate?.label ?? "Idle"}</p>
            <p className="mt-3 text-[11px] text-muted-foreground">Enable auto-refresh to build a history chart of queue activity over time.</p>
          </div>
        )}

        {/* Chart legend */}
        {hasHistory && (
          <div className="mt-3 flex items-center justify-center gap-4">
            <div className="flex items-center gap-1.5">
              <span className="inline-block h-2 w-2 rounded-full bg-primary" />
              <span className="text-[10px] text-muted-foreground">Active</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: "hsl(38 92% 50%)" }} />
              <span className="text-[10px] text-muted-foreground">Pending</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="inline-block h-2 w-2 rounded-full bg-muted-foreground/50" />
              <span className="text-[10px] text-muted-foreground">Scheduled</span>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

// ---------------------------------------------------------------------------
// System Status Timeline
// ---------------------------------------------------------------------------

type TimelineSegmentStatus = "up" | "down" | "degraded" | "unknown"

interface TimelineSegment {
  startHour: number
  status: TimelineSegmentStatus
  label: string
}

function useStatusTimeline(startedAt: string, databaseStatus: "online" | "offline") {
  return useMemo(() => {
    const now = new Date()
    const segments: TimelineSegment[] = []
    const serverStart = new Date(startedAt)
    const twentyFourHoursAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000)

    for (let i = 0; i < 24; i++) {
      const segmentStart = new Date(twentyFourHoursAgo.getTime() + i * 60 * 60 * 1000)
      const segmentEnd = new Date(segmentStart.getTime() + 60 * 60 * 1000)

      let status: TimelineSegmentStatus
      if (segmentEnd <= serverStart) {
        // Before server started -- unknown/down
        status = "unknown"
      } else if (segmentStart >= serverStart) {
        // Server was running during this entire segment
        status = databaseStatus === "online" ? "up" : "degraded"
      } else {
        // Server started partway through this segment
        status = "degraded"
      }

      const hourLabel = segmentStart.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
      segments.push({
        startHour: i,
        status,
        label: hourLabel,
      })
    }

    return segments
  }, [startedAt, databaseStatus])
}

const timelineStatusColors: Record<TimelineSegmentStatus, string> = {
  up: "bg-emerald-500",
  down: "bg-destructive",
  degraded: "bg-amber-500",
  unknown: "bg-muted-foreground/20",
}

const timelineStatusLabels: Record<TimelineSegmentStatus, string> = {
  up: "Operational",
  down: "Down",
  degraded: "Degraded",
  unknown: "No data",
}

function SystemStatusTimeline({ startedAt, databaseStatus }: { startedAt: string; databaseStatus: "online" | "offline" }) {
  const segments = useStatusTimeline(startedAt, databaseStatus)

  const uptimePercent = useMemo(() => {
    const upCount = segments.filter((s) => s.status === "up").length
    return Math.round((upCount / segments.length) * 100)
  }, [segments])

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="space-y-1">
            <CardTitle className="flex items-center gap-2 text-base">
              <Clock className="h-4 w-4 text-muted-foreground" />
              Uptime Timeline
            </CardTitle>
            <CardDescription>System availability over the last 24 hours.</CardDescription>
          </div>
          <Badge
            variant="outline"
            className={`text-xs ${uptimePercent >= 99 ? "text-emerald-600 dark:text-emerald-400" : uptimePercent >= 90 ? "text-amber-600 dark:text-amber-400" : "text-destructive"}`}
          >
            {uptimePercent}% uptime
          </Badge>
        </div>
      </CardHeader>
      <CardContent>
        {/* Timeline bar */}
        <div className="space-y-3">
          <div className="flex h-8 w-full gap-[2px] overflow-hidden rounded-md">
            {segments.map((seg) => (
              <Tooltip key={seg.startHour}>
                <TooltipTrigger asChild>
                  <div className={`flex-1 cursor-default transition-opacity hover:opacity-80 ${timelineStatusColors[seg.status]}`} />
                </TooltipTrigger>
                <TooltipContent side="bottom" className="text-xs">
                  <p className="font-medium">{seg.label}</p>
                  <p className="text-muted-foreground">{timelineStatusLabels[seg.status]}</p>
                </TooltipContent>
              </Tooltip>
            ))}
          </div>

          {/* Time labels */}
          <div className="flex justify-between text-[10px] text-muted-foreground">
            <span>{segments[0]?.label ?? ""}</span>
            <span>{segments[Math.floor(segments.length / 4)]?.label ?? ""}</span>
            <span>{segments[Math.floor(segments.length / 2)]?.label ?? ""}</span>
            <span>{segments[Math.floor((segments.length * 3) / 4)]?.label ?? ""}</span>
            <span>Now</span>
          </div>

          {/* Legend */}
          <div className="flex items-center gap-4">
            {(["up", "degraded", "down", "unknown"] as const).map((status) => (
              <div key={status} className="flex items-center gap-1.5">
                <span className={`inline-block h-2 w-2 rounded-sm ${timelineStatusColors[status]}`} />
                <span className="text-[10px] text-muted-foreground">{timelineStatusLabels[status]}</span>
              </div>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

// ---------------------------------------------------------------------------
// Resource Utilization Gauges
// ---------------------------------------------------------------------------

function CircularGauge({
  value,
  max,
  label,
  sublabel,
  size = 96,
  strokeWidth = 8,
}: {
  value: number
  max: number
  label: string
  sublabel?: string
  size?: number
  strokeWidth?: number
}) {
  const percentage = max > 0 ? Math.min((value / max) * 100, 100) : 0
  const radius = (size - strokeWidth) / 2
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (percentage / 100) * circumference

  // Color based on utilization
  const getColor = (pct: number) => {
    if (pct >= 90) return "text-destructive"
    if (pct >= 70) return "text-amber-500"
    return "text-emerald-500"
  }
  const getStroke = (pct: number) => {
    if (pct >= 90) return "stroke-destructive"
    if (pct >= 70) return "stroke-amber-500"
    return "stroke-emerald-500"
  }

  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="-rotate-90">
          {/* Background ring */}
          <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="hsl(var(--muted))" strokeWidth={strokeWidth} />
          {/* Progress ring */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            className={getStroke(percentage)}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            style={{ transition: "stroke-dashoffset 0.5s ease-in-out" }}
          />
        </svg>
        {/* Center text */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`text-lg font-bold tabular-nums ${getColor(percentage)}`}>{Math.round(percentage)}%</span>
        </div>
      </div>
      <div className="text-center">
        <p className="text-xs font-medium">{label}</p>
        {sublabel && <p className="text-[10px] text-muted-foreground">{sublabel}</p>}
      </div>
    </div>
  )
}

function QueueUtilizationGauges({ queues }: { queues: Array<{ name: string; active?: number; queued?: number; scheduled?: number }> }) {
  // Compute utilization metrics from queue data
  const metrics = useMemo(() => {
    const totalActive = queues.reduce((sum, q) => sum + (q.active ?? 0), 0)
    const totalQueued = queues.reduce((sum, q) => sum + (q.queued ?? 0), 0)
    const totalScheduled = queues.reduce((sum, q) => sum + (q.scheduled ?? 0), 0)
    const totalJobs = totalActive + totalQueued + totalScheduled

    // Derive a capacity estimate: each queue can reasonably handle ~100 jobs
    const estimatedCapacity = Math.max(queues.length * 100, totalJobs, 1)
    // Worker load: active as portion of total pipeline
    const pipelineTotal = totalActive + totalQueued
    const workerLoad = pipelineTotal > 0 ? (totalActive / pipelineTotal) * 100 : 0

    return {
      queueDepth: { value: totalJobs, max: estimatedCapacity, label: "Queue Depth", sublabel: `${totalJobs} total jobs` },
      workerLoad: { value: Math.round(workerLoad), max: 100, label: "Worker Load", sublabel: `${totalActive} active` },
      pendingRatio: {
        value: totalQueued,
        max: Math.max(totalQueued + totalActive, 1),
        label: "Backlog",
        sublabel: `${totalQueued} pending`,
      },
      scheduledLoad: {
        value: totalScheduled,
        max: Math.max(estimatedCapacity, 1),
        label: "Scheduled",
        sublabel: `${totalScheduled} upcoming`,
      },
    }
  }, [queues])

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Gauge className="h-4 w-4 text-muted-foreground" />
          Queue Utilization
        </CardTitle>
        <CardDescription>Worker and queue capacity utilization gauges.</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 gap-6 sm:grid-cols-4">
          <CircularGauge {...metrics.queueDepth} />
          <CircularGauge {...metrics.workerLoad} />
          <CircularGauge {...metrics.pendingRatio} />
          <CircularGauge {...metrics.scheduledLoad} />
        </div>
      </CardContent>
    </Card>
  )
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

const AUTO_REFRESH_INTERVAL = 30_000

function AdminSystemPage() {
  useDocumentTitle("System Status")
  const [autoRefresh, setAutoRefresh] = useState(false)

  const { data, isLoading, isError, refetch, isFetching, dataUpdatedAt } = useAdminSystemStatus({
    refetchInterval: autoRefresh ? AUTO_REFRESH_INTERVAL : false,
  })

  const handleRefresh = useCallback(() => {
    refetch()
  }, [refetch])

  return (
    <TooltipProvider>
      <PageContainer className="flex-1 space-y-8">
        <PageHeader
          eyebrow="Administration"
          title="System Status"
          description="Monitor system health, services, and worker queues."
          breadcrumbs={<AdminBreadcrumbs />}
          actions={
            <div className="flex items-center gap-4">
              {/* Auto-refresh toggle */}
              <div className="flex items-center gap-2">
                <Switch checked={autoRefresh} onCheckedChange={setAutoRefresh} aria-label="Auto-refresh" />
                <span className="text-xs text-muted-foreground">Auto-refresh</span>
              </div>
              {/* Manual refresh */}
              <Button variant="outline" size="sm" onClick={handleRefresh} disabled={isFetching}>
                <RefreshCw className={`h-4 w-4 ${isFetching ? "animate-spin" : ""}`} />
                Refresh
              </Button>
            </div>
          }
        />
        <AdminNav />

        <PageSection>
          {isLoading ? (
            <div className="space-y-6">
              <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                {Array.from({ length: 4 }).map((_, index) => (
                  // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
                  <SkeletonCard key={`system-skeleton-${index}`} />
                ))}
              </div>
            </div>
          ) : isError || !data ? (
            <EmptyState
              icon={AlertCircle}
              title="Unable to load system status"
              description="The server may be unreachable. Please try again."
              action={
                <Button variant="outline" size="sm" onClick={() => refetch()}>
                  Try again
                </Button>
              }
            />
          ) : (
            <div className="space-y-6">
              {/* Overall health banner + uptime */}
              <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                <div className="flex-1">
                  <OverallHealthBanner healthy={data.databaseStatus === "online"} />
                </div>
                <div className="shrink-0">
                  <UptimeBanner startedAt={data.startedAt} uptimeSeconds={data.uptimeSeconds} />
                </div>
              </div>

              {/* System health indicators */}
              <SectionErrorBoundary name="System Health">
                <SystemHealthIndicators autoRefresh={autoRefresh} />
              </SectionErrorBoundary>

              {/* Service status grid */}
              <SectionErrorBoundary name="Service Status">
                <ServiceStatusGrid databaseStatus={data.databaseStatus} workerQueues={data.workerQueues} />
              </SectionErrorBoundary>

              {/* System status timeline */}
              <SectionErrorBoundary name="Uptime Timeline">
                <SystemStatusTimeline startedAt={data.startedAt} databaseStatus={data.databaseStatus} />
              </SectionErrorBoundary>

              {/* Two-column layout: System info + Worker queues */}
              <div className="grid gap-6 lg:grid-cols-2">
                <SectionErrorBoundary name="System Information">
                  <SystemInfoCard
                    appName={data.appName}
                    appVersion={data.appVersion}
                    pythonVersion={data.pythonVersion}
                    uptimeSeconds={data.uptimeSeconds}
                    startedAt={data.startedAt}
                    debugMode={data.debugMode}
                  />
                </SectionErrorBoundary>

                <SectionErrorBoundary name="Worker Queues">
                  {data.workerQueues && data.workerQueues.length > 0 ? (
                    <WorkerQueuesCard queues={data.workerQueues} />
                  ) : (
                    <Card>
                      <CardHeader>
                        <CardTitle className="flex items-center gap-2 text-base">
                          <Cpu className="h-4 w-4 text-muted-foreground" />
                          Worker Queues
                        </CardTitle>
                        <CardDescription>Background job processing status.</CardDescription>
                      </CardHeader>
                      <CardContent>
                        <p className="text-sm text-muted-foreground">No worker queue data available. Workers may not be running.</p>
                      </CardContent>
                    </Card>
                  )}
                </SectionErrorBoundary>
              </div>

              {/* Queue activity chart + utilization gauges */}
              <div className="grid gap-6 lg:grid-cols-2">
                <SectionErrorBoundary name="Queue Activity">
                  <WorkerQueueHistoryChart queues={data.workerQueues} />
                </SectionErrorBoundary>

                <SectionErrorBoundary name="Queue Utilization">
                  {data.workerQueues && data.workerQueues.length > 0 ? (
                    <QueueUtilizationGauges queues={data.workerQueues} />
                  ) : (
                    <Card>
                      <CardHeader>
                        <CardTitle className="flex items-center gap-2 text-base">
                          <Gauge className="h-4 w-4 text-muted-foreground" />
                          Queue Utilization
                        </CardTitle>
                        <CardDescription>Worker and queue capacity gauges.</CardDescription>
                      </CardHeader>
                      <CardContent>
                        <p className="text-sm text-muted-foreground">No queue data available. Workers may not be running.</p>
                      </CardContent>
                    </Card>
                  )}
                </SectionErrorBoundary>
              </div>

              {/* External connections overview */}
              <SectionErrorBoundary name="External Connections">
                <ExternalConnectionsCard />
              </SectionErrorBoundary>

              {/* Data freshness footer */}
              <div className="flex items-center justify-end">
                <DataFreshness dataUpdatedAt={dataUpdatedAt > 0 ? dataUpdatedAt : undefined} onRefresh={handleRefresh} isRefreshing={isFetching} />
              </div>
            </div>
          )}
        </PageSection>
      </PageContainer>
    </TooltipProvider>
  )
}

// ---------------------------------------------------------------------------
// Utility: human-readable "X ago" from a Date
// ---------------------------------------------------------------------------

function formatTimeSince(date: Date): string {
  const seconds = Math.floor((Date.now() - date.getTime()) / 1000)
  if (seconds < 5) return "just now"
  if (seconds < 60) return `${seconds}s ago`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  return `${hours}h ${minutes % 60}m ago`
}
