import { AlertCircle } from "lucide-react"
import { useMemo, useState } from "react"
import { Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { EmptyState } from "@/components/ui/empty-state"
import { SkeletonCard } from "@/components/ui/skeleton"
import { useAdminTrends } from "@/lib/api/hooks/admin"

type Period = "7d" | "30d" | "90d"

const PERIOD_DAYS: Record<Period, number> = { "7d": 7, "30d": 30, "90d": 90 }

function PeriodToggle({ value, onChange }: { value: Period; onChange: (p: Period) => void }) {
  return (
    <div className="flex gap-0.5 rounded-md border border-border bg-muted/40 p-0.5">
      {(["7d", "30d", "90d"] as const).map((p) => (
        <button
          type="button"
          key={p}
          onClick={() => onChange(p)}
          className={`rounded px-2 py-0.5 text-[11px] font-medium transition-colors ${
            value === p ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"
          }`}
        >
          {p}
        </button>
      ))}
    </div>
  )
}

function ChartTooltip({ active, payload, label }: { active?: boolean; payload?: Array<{ value: number; name: string; color: string }>; label?: string }) {
  if (!active || !payload?.length) return null
  return (
    <div className="rounded-lg border border-border/60 bg-card px-3 py-2 shadow-md">
      <p className="mb-1 text-xs font-medium text-muted-foreground">{label}</p>
      {payload.map((entry) => (
        <p key={entry.name} className="text-sm font-semibold" style={{ color: entry.color }}>
          {entry.name}: {entry.value}
        </p>
      ))}
    </div>
  )
}

export function AdminCharts() {
  const { data, isLoading, isError, refetch } = useAdminTrends()
  const [activityPeriod, setActivityPeriod] = useState<Period>("30d")
  const [growthPeriod, setGrowthPeriod] = useState<Period>("30d")

  const activityPoints = useMemo(() => {
    if (!data?.points) return []
    return data.points.slice(-PERIOD_DAYS[activityPeriod])
  }, [data, activityPeriod])

  const growthPoints = useMemo(() => {
    if (!data?.points) return []
    return data.points.slice(-PERIOD_DAYS[growthPeriod])
  }, [data, growthPeriod])

  const totalEvents = useMemo(() => activityPoints.reduce((sum, p) => sum + p.events, 0), [activityPoints])

  const totalNewUsers = useMemo(() => growthPoints.reduce((sum, p) => sum + p.newUsers, 0), [growthPoints])

  if (isLoading) {
    return (
      <div className="grid gap-4 md:grid-cols-2">
        <SkeletonCard className="h-[360px] animate-pulse" />
        <SkeletonCard className="h-[360px] animate-pulse" />
      </div>
    )
  }

  if (isError || !data) {
    return (
      <EmptyState
        icon={AlertCircle}
        title="Unable to load trend data"
        description="Something went wrong. Please try again."
        action={
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            Try again
          </Button>
        }
      />
    )
  }

  return (
    <div className="grid gap-4 md:grid-cols-2">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="space-y-1">
              <CardTitle className="text-sm text-muted-foreground">Activity Trend</CardTitle>
              <CardDescription>Event volume over time</CardDescription>
            </div>
            <div className="flex flex-col items-end gap-1">
              <PeriodToggle value={activityPeriod} onChange={setActivityPeriod} />
              <span className="text-xs font-medium text-muted-foreground">{totalEvents.toLocaleString()} total events</span>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={280}>
            <AreaChart data={activityPoints} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="eventsFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="hsl(var(--primary))" stopOpacity={0.3} />
                  <stop offset="100%" stopColor="hsl(var(--primary))" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
              <XAxis dataKey="date" tick={{ fontSize: 12, fill: "hsl(var(--muted-foreground))" }} tickLine={false} axisLine={false} />
              <YAxis allowDecimals={false} tick={{ fontSize: 12, fill: "hsl(var(--muted-foreground))" }} tickLine={false} axisLine={false} />
              <Tooltip content={<ChartTooltip />} cursor={{ stroke: "hsl(var(--muted-foreground))", strokeWidth: 1, strokeDasharray: "4 4" }} />
              <Area type="monotone" dataKey="events" name="Events" stroke="hsl(var(--primary))" fill="url(#eventsFill)" strokeWidth={2} animationDuration={800} />
            </AreaChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="space-y-1">
              <CardTitle className="text-sm text-muted-foreground">User Growth</CardTitle>
              <CardDescription>New user registrations</CardDescription>
            </div>
            <div className="flex flex-col items-end gap-1">
              <PeriodToggle value={growthPeriod} onChange={setGrowthPeriod} />
              <span className="text-xs font-medium text-muted-foreground">{totalNewUsers.toLocaleString()} total new users</span>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={growthPoints} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
              <XAxis dataKey="date" tick={{ fontSize: 12, fill: "hsl(var(--muted-foreground))" }} tickLine={false} axisLine={false} />
              <YAxis allowDecimals={false} tick={{ fontSize: 12, fill: "hsl(var(--muted-foreground))" }} tickLine={false} axisLine={false} />
              <Tooltip content={<ChartTooltip />} cursor={{ fill: "hsl(var(--muted-foreground))", fillOpacity: 0.06 }} />
              <Bar dataKey="newUsers" name="New Users" fill="hsl(var(--primary))" radius={[4, 4, 0, 0]} animationDuration={800} />
            </BarChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>
    </div>
  )
}
