import { useCallback, useEffect, useRef, useState } from "react"
import { createFileRoute } from "@tanstack/react-router"
import {
  Activity,
  CheckCircle2,
  Clock,
  Cpu,
  Database,
  HardDrive,
  Layers,
  RefreshCw,
  Server,
  XCircle,
  Zap,
} from "lucide-react"
import { AdminBreadcrumbs } from "@/components/admin/admin-breadcrumbs"
import { AdminNav } from "@/components/admin/admin-nav"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Separator } from "@/components/ui/separator"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { useAdminSystemStatus } from "@/lib/api/hooks/admin"

export const Route = createFileRoute("/_app/admin/system")({
  component: AdminSystemPage,
})

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  const secs = Math.floor(seconds % 60)

  const parts: string[] = []
  if (days > 0) parts.push(`${days}d`)
  if (hours > 0) parts.push(`${hours}h`)
  if (minutes > 0) parts.push(`${minutes}m`)
  parts.push(`${secs}s`)
  return parts.join(" ")
}

function useTimeSince(timestamp: string | undefined) {
  const [, setTick] = useState(0)
  useEffect(() => {
    if (!timestamp) return
    const id = setInterval(() => setTick((t) => t + 1), 1000)
    return () => clearInterval(id)
  }, [timestamp])

  if (!timestamp) return null
  const elapsed = Math.floor((Date.now() - new Date(timestamp).getTime()) / 1000)
  return formatUptime(Math.max(0, elapsed))
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
          {ok && (
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-40" />
          )}
          <span
            className={`relative inline-flex h-2.5 w-2.5 rounded-full ${ok ? "bg-emerald-500" : "bg-destructive"}`}
          />
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
        healthy
          ? "border-emerald-500/20 bg-emerald-500/5 text-emerald-700 dark:text-emerald-400"
          : "border-destructive/20 bg-destructive/5 text-destructive"
      }`}
    >
      {healthy ? <CheckCircle2 className="h-5 w-5" /> : <XCircle className="h-5 w-5" />}
      <div>
        <p className="text-sm font-semibold">{healthy ? "All Systems Operational" : "Issue Detected"}</p>
        <p className="text-xs opacity-75">
          {healthy ? "All services are running normally." : "One or more services are reporting problems."}
        </p>
      </div>
    </div>
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
      detail: hasWorkers ? "Redis" : "No data available",
    },
    {
      name: "Task Workers",
      icon: Cpu,
      status: hasWorkers ? ("healthy" as const) : ("unknown" as const),
      detail: hasWorkers ? `${workerQueues.length} queue${workerQueues.length !== 1 ? "s" : ""}` : "No data available",
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
              <div
                key={svc.name}
                className="flex items-center justify-between rounded-lg border px-4 py-3"
              >
                <div className="flex items-center gap-3">
                  <div
                    className={`flex h-8 w-8 items-center justify-center rounded-md ${
                      isHealthy
                        ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                        : isUnknown
                          ? "bg-muted text-muted-foreground"
                          : "bg-destructive/10 text-destructive"
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
      value: liveUptime ?? formatUptime(uptimeSeconds),
      icon: Clock,
    },
    {
      label: "Started",
      value: new Date(startedAt).toLocaleString(),
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

function WorkerQueuesCard({
  queues,
}: {
  queues: Array<{ name: string; active?: number; queued?: number; scheduled?: number }>
}) {
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
        <div className="grid grid-cols-3 gap-4">
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

        {/* Per-queue rows */}
        <div className="space-y-2">
          {queues.map((queue) => {
            const active = queue.active ?? 0
            const queued = queue.queued ?? 0
            const scheduled = queue.scheduled ?? 0
            const total = active + queued + scheduled
            const isIdle = total === 0

            return (
              <div key={queue.name} className="flex items-center justify-between rounded-lg border px-4 py-3">
                <div className="flex items-center gap-3">
                  <StatusDot ok label={isIdle ? "Idle" : `${total} job${total !== 1 ? "s" : ""}`} />
                  <div>
                    <p className="text-sm font-medium">{queue.name}</p>
                    <p className="text-xs text-muted-foreground">
                      {isIdle ? "No active jobs" : `${active} active, ${queued} pending, ${scheduled} scheduled`}
                    </p>
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
            )
          })}
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
  const [autoRefresh, setAutoRefresh] = useState(false)
  const [lastRefreshed, setLastRefreshed] = useState<Date | null>(null)
  const lastRefreshedRef = useRef<Date | null>(null)

  const { data, isLoading, isError, refetch, isFetching, dataUpdatedAt } = useAdminSystemStatus({
    refetchInterval: autoRefresh ? AUTO_REFRESH_INTERVAL : false,
  })

  // Track last refresh time
  useEffect(() => {
    if (dataUpdatedAt > 0) {
      const ts = new Date(dataUpdatedAt)
      lastRefreshedRef.current = ts
      setLastRefreshed(ts)
    }
  }, [dataUpdatedAt])

  // Live "last refreshed X ago" ticker
  const [, setRefreshTick] = useState(0)
  useEffect(() => {
    const id = setInterval(() => setRefreshTick((t) => t + 1), 5000)
    return () => clearInterval(id)
  }, [])

  const handleRefresh = useCallback(() => {
    refetch()
  }, [refetch])

  const lastRefreshedLabel = lastRefreshed
    ? `Updated ${formatTimeSince(lastRefreshed)}`
    : null

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
            <Card>
              <CardHeader>
                <CardTitle>System Status</CardTitle>
              </CardHeader>
              <CardContent className="text-muted-foreground">
                Unable to load system status. The server may be unreachable.
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-6">
              {/* Overall health banner + last refreshed */}
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div className="flex-1">
                  <OverallHealthBanner healthy={data.databaseStatus === "online"} />
                </div>
                {lastRefreshedLabel && (
                  <p className="shrink-0 text-xs text-muted-foreground">
                    {lastRefreshedLabel}
                    {autoRefresh && " (auto)"}
                  </p>
                )}
              </div>

              {/* Service status grid */}
              <ServiceStatusGrid databaseStatus={data.databaseStatus} workerQueues={data.workerQueues} />

              {/* Two-column layout: System info + Worker queues */}
              <div className="grid gap-6 lg:grid-cols-2">
                <SystemInfoCard
                  appName={data.appName}
                  appVersion={data.appVersion}
                  pythonVersion={data.pythonVersion}
                  uptimeSeconds={data.uptimeSeconds}
                  startedAt={data.startedAt}
                  debugMode={data.debugMode}
                />

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
                      <p className="text-sm text-muted-foreground">
                        No worker queue data available. Workers may not be running.
                      </p>
                    </CardContent>
                  </Card>
                )}
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
