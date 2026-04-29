import { Link } from "@tanstack/react-router"
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { useAdminSystemStatus } from "@/lib/api/hooks/admin"

function StatusDot({ ok }: { ok: boolean }) {
  return (
    <span
      className={`inline-block size-2.5 rounded-full ${ok ? "bg-emerald-500" : "bg-destructive"}`}
      aria-label={ok ? "Healthy" : "Unhealthy"}
    />
  )
}

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  if (days > 0) return `${days}d ${hours}h`
  const minutes = Math.floor((seconds % 3600) / 60)
  return `${hours}h ${minutes}m`
}

export function SystemHealthCard() {
  const { data, isLoading, isError } = useAdminSystemStatus()

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-semibold">System health</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={`health-skeleton-${i}`} className="flex items-center justify-between">
              <Skeleton className="h-3 w-24" />
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
          <CardTitle className="text-sm font-semibold">System health</CardTitle>
        </CardHeader>
        <CardContent className="text-muted-foreground text-sm">Unable to load system status.</CardContent>
      </Card>
    )
  }

  const dbOnline = data.databaseStatus === "online"

  const items = [
    { label: "Application", value: data.appName, ok: true },
    { label: "Database", value: data.databaseStatus, ok: dbOnline },
    { label: "Version", value: data.appVersion, ok: true },
    { label: "Uptime", value: formatUptime(data.uptimeSeconds), ok: true },
  ]

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-semibold">System health</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {items.map((item) => (
          <div key={item.label} className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <StatusDot ok={item.ok} />
              <span className="text-sm">{item.label}</span>
            </div>
            <span className="text-xs font-medium text-muted-foreground capitalize">{item.value}</span>
          </div>
        ))}
      </CardContent>
      <CardFooter>
        <Link to="/admin/system" className="text-xs text-primary hover:underline">
          View system details
        </Link>
      </CardFooter>
    </Card>
  )
}
