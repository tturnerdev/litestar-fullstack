import { Link } from "@tanstack/react-router"
import { Activity, Cable, CheckCircle2, Clock, Database, Server, XCircle } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { useAdminSystemStatus } from "@/lib/api/hooks/admin"
import { useConnections } from "@/lib/api/hooks/connections"
import { formatUptime } from "@/lib/format-utils"

function StatusIndicator({ ok, label }: { ok: boolean; label?: string }) {
  const statusLabel = label ?? (ok ? "Healthy" : "Unhealthy")
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="relative flex h-2.5 w-2.5">
          {ok && <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-40" />}
          <span
            className={`relative inline-flex h-2.5 w-2.5 rounded-full ${ok ? "bg-emerald-500" : "bg-destructive"}`}
          />
        </span>
      </TooltipTrigger>
      <TooltipContent side="left" className="text-xs">
        {statusLabel}
      </TooltipContent>
    </Tooltip>
  )
}

export function SystemHealthCard() {
  const { data, isLoading, isError } = useAdminSystemStatus()
  const { data: connectionsData, isLoading: connectionsLoading } = useConnections({ page: 1, pageSize: 50 })

  const connections = connectionsData?.items ?? []

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-semibold">System Health</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {Array.from({ length: 4 }).map((_, i) => (
            // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
            <div key={`health-skeleton-${i}`} className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Skeleton className="h-4 w-4 rounded" />
                <Skeleton className="h-3 w-20" />
              </div>
              <Skeleton className="h-3 w-16" />
            </div>
          ))}
        </CardContent>
      </Card>
    )
  }

  if (isError || !data) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-semibold">System Health</CardTitle>
        </CardHeader>
        <CardContent className="text-muted-foreground text-sm">Unable to load system status.</CardContent>
      </Card>
    )
  }

  const dbOnline = data.databaseStatus === "online"
  const connectionsHealthy = connections.length === 0 || connections.every(
    (c) => c.isEnabled && ["connected", "healthy", "active"].includes(c.status.toLowerCase()),
  )
  const allHealthy = dbOnline && connectionsHealthy

  const services = [
    {
      label: "Application",
      icon: Server,
      value: data.appName,
      ok: true,
    },
    {
      label: "Database",
      icon: Database,
      value: data.databaseStatus,
      ok: dbOnline,
    },
    {
      label: "Uptime",
      icon: Clock,
      value: formatUptime(data.uptimeSeconds),
      ok: true,
    },
  ]

  return (
    <TooltipProvider>
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-sm font-semibold">System Health</CardTitle>
          <Badge variant={allHealthy ? "outline" : "destructive"} className="gap-1 text-[10px]">
            {allHealthy ? (
              <CheckCircle2 className="h-3 w-3 text-emerald-500" />
            ) : (
              <XCircle className="h-3 w-3" />
            )}
            {allHealthy ? "All Systems OK" : "Issue Detected"}
          </Badge>
        </CardHeader>
        <CardContent className="space-y-2.5">
          {/* Service status rows */}
          {services.map((service) => {
            const SvcIcon = service.icon
            return (
              <div key={service.label} className="flex items-center justify-between rounded-md px-1 py-1">
                <div className="flex items-center gap-2.5">
                  <SvcIcon className="h-3.5 w-3.5 text-muted-foreground" />
                  <span className="text-sm">{service.label}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-medium text-muted-foreground capitalize">{service.value}</span>
                  <StatusIndicator ok={service.ok} />
                </div>
              </div>
            )
          })}

          {/* Version badge */}
          <div className="flex items-center justify-between rounded-md px-1 py-1">
            <div className="flex items-center gap-2.5">
              <Activity className="h-3.5 w-3.5 text-muted-foreground" />
              <span className="text-sm">Version</span>
            </div>
            <Badge variant="secondary" className="text-[10px] font-mono">
              {data.appVersion}
            </Badge>
          </div>

          {/* Worker queues */}
          {data.workerQueues && data.workerQueues.length > 0 && (
            <>
              <Separator className="my-2" />
              <p className="px-1 text-xs font-medium text-muted-foreground">Worker Queues</p>
              <div className="space-y-1.5">
                {data.workerQueues.map((queue) => {
                  const totalJobs = (queue.active ?? 0) + (queue.queued ?? 0) + (queue.scheduled ?? 0)
                  return (
                    <div key={queue.name} className="flex items-center justify-between rounded-md bg-muted/40 px-2.5 py-1.5">
                      <span className="text-xs font-medium">{queue.name}</span>
                      <div className="flex items-center gap-2">
                        {(queue.active ?? 0) > 0 && (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Badge variant="default" className="h-5 px-1.5 text-[10px]">
                                {queue.active} active
                              </Badge>
                            </TooltipTrigger>
                            <TooltipContent side="left" className="text-xs">
                              Currently processing
                            </TooltipContent>
                          </Tooltip>
                        )}
                        {(queue.queued ?? 0) > 0 && (
                          <Badge variant="secondary" className="h-5 px-1.5 text-[10px]">
                            {queue.queued} queued
                          </Badge>
                        )}
                        {totalJobs === 0 && (
                          <span className="text-[10px] text-muted-foreground">idle</span>
                        )}
                      </div>
                    </div>
                  )
                })}
              </div>
            </>
          )}

          {/* Connections */}
          <Separator className="my-2" />
          <p className="px-1 text-xs font-medium text-muted-foreground">Connections</p>
          {connectionsLoading ? (
            <div className="space-y-1.5">
              {Array.from({ length: 2 }).map((_, i) => (
                // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
                <div key={`conn-skeleton-${i}`} className="flex items-center justify-between rounded-md bg-muted/40 px-2.5 py-1.5">
                  <div className="flex items-center gap-2">
                    <Skeleton className="h-3.5 w-3.5 rounded" />
                    <Skeleton className="h-3 w-24" />
                  </div>
                  <Skeleton className="h-2.5 w-2.5 rounded-full" />
                </div>
              ))}
            </div>
          ) : connections.length === 0 ? (
            <p className="px-1 text-xs text-muted-foreground/70">No connections configured</p>
          ) : (
            <div className="space-y-1.5">
              {connections.map((connection) => {
                const isHealthy = connection.isEnabled && ["connected", "healthy", "active"].includes(connection.status.toLowerCase())
                const statusLabel = !connection.isEnabled
                  ? "Disabled"
                  : isHealthy
                    ? "Healthy"
                    : connection.status.charAt(0).toUpperCase() + connection.status.slice(1)
                return (
                  <div key={connection.id} className="flex items-center justify-between rounded-md bg-muted/40 px-2.5 py-1.5">
                    <div className="flex items-center gap-2">
                      <Cable className="h-3.5 w-3.5 text-muted-foreground" />
                      <span className="text-xs font-medium">{connection.name}</span>
                      <Badge variant="secondary" className="h-4 px-1 text-[9px] font-medium">
                        {connection.provider}
                      </Badge>
                    </div>
                    <StatusIndicator ok={isHealthy} label={statusLabel} />
                  </div>
                )
              })}
            </div>
          )}
        </CardContent>
        <CardFooter>
          <Link to="/admin/system" className="text-xs text-primary hover:underline">
            View system details
          </Link>
        </CardFooter>
      </Card>
    </TooltipProvider>
  )
}
