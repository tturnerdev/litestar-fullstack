import { Link } from "@tanstack/react-router"
import { Activity, ArrowDownRight, ArrowRight, ArrowUpRight, CalendarPlus, Users, UsersRound } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { useAdminDashboardStats, useAdminTrends } from "@/lib/api/hooks/admin"

type StatsData = {
  activeUsers: number
  newUsersWeek: number
  verifiedUsers: number
  totalUsers: number
  totalTeams: number
  eventsToday: number
  newUsersToday: number
}

const statConfig = [
  {
    key: "totalUsers" as const,
    label: "Total Users",
    subtitle: (data: StatsData) => `${data.activeUsers} active, ${data.verifiedUsers} verified`,
    icon: Users,
    color: "text-blue-600 dark:text-blue-400",
    bg: "bg-blue-500/10",
    hoverBg: "group-hover:bg-blue-500",
    to: "/admin/users",
    trendKey: "users" as const,
  },
  {
    key: "totalTeams" as const,
    label: "Total Teams",
    subtitle: () => "All workspaces",
    icon: UsersRound,
    color: "text-violet-600 dark:text-violet-400",
    bg: "bg-violet-500/10",
    hoverBg: "group-hover:bg-violet-500",
    to: "/admin/teams",
    trendKey: null,
  },
  {
    key: "eventsToday" as const,
    label: "Events Today",
    subtitle: () => "Audit log entries",
    icon: Activity,
    color: "text-amber-600 dark:text-amber-400",
    bg: "bg-amber-500/10",
    hoverBg: "group-hover:bg-amber-500",
    to: "/admin/audit",
    trendKey: "events" as const,
  },
  {
    key: "newUsersToday" as const,
    label: "New Users Today",
    subtitle: (data: StatsData) => `${data.newUsersWeek} this week`,
    icon: CalendarPlus,
    color: "text-emerald-600 dark:text-emerald-400",
    bg: "bg-emerald-500/10",
    hoverBg: "group-hover:bg-emerald-500",
    to: "/admin/users",
    trendKey: "newUsers" as const,
  },
] as const

/** Compute a percentage change from the trend points for a given metric. */
function computeTrend(points: Array<{ events: number; newUsers: number }>, key: "events" | "newUsers" | "users"): { pct: number; direction: "up" | "down" | "flat" } {
  if (!points || points.length < 2) return { pct: 0, direction: "flat" }

  // Compare the most recent half to the older half
  const mid = Math.floor(points.length / 2)
  const older = points.slice(0, mid)
  const newer = points.slice(mid)

  const sumOlder = older.reduce((s, p) => s + (key === "users" ? p.newUsers : p[key]), 0)
  const sumNewer = newer.reduce((s, p) => s + (key === "users" ? p.newUsers : p[key]), 0)

  if (sumOlder === 0 && sumNewer === 0) return { pct: 0, direction: "flat" }
  if (sumOlder === 0) return { pct: 100, direction: "up" }

  const pct = Math.round(((sumNewer - sumOlder) / sumOlder) * 100)
  if (pct > 0) return { pct, direction: "up" }
  if (pct < 0) return { pct: Math.abs(pct), direction: "down" }
  return { pct: 0, direction: "flat" }
}

function TrendBadge({ pct, direction }: { pct: number; direction: "up" | "down" | "flat" }) {
  if (direction === "flat") {
    return (
      <span className="inline-flex items-center gap-0.5 rounded-full bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground">
        <ArrowRight className="h-3 w-3" />
        0%
      </span>
    )
  }

  const isUp = direction === "up"
  return (
    <span
      className={`inline-flex items-center gap-0.5 rounded-full px-1.5 py-0.5 text-[10px] font-medium ${
        isUp ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400" : "bg-red-500/10 text-red-600 dark:text-red-400"
      }`}
    >
      {isUp ? <ArrowUpRight className="h-3 w-3" /> : <ArrowDownRight className="h-3 w-3" />}
      {pct}%
    </span>
  )
}

function StatsCardSkeleton() {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <Skeleton className="h-4 w-24" />
        <Skeleton className="h-9 w-9 rounded-lg" />
      </CardHeader>
      <CardContent>
        <div className="flex items-baseline gap-2">
          <Skeleton className="h-8 w-16" />
          <Skeleton className="h-4 w-10 rounded-full" />
        </div>
        <Skeleton className="mt-2 h-3 w-32" />
      </CardContent>
    </Card>
  )
}

export function StatsCards() {
  const { data, isLoading, isError } = useAdminDashboardStats()
  const { data: trends } = useAdminTrends()

  if (isLoading) {
    return (
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {Array.from({ length: 4 }).map((_, index) => (
          // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
          <StatsCardSkeleton key={`stats-skeleton-${index}`} />
        ))}
      </div>
    )
  }

  if (isError || !data) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Admin stats</CardTitle>
        </CardHeader>
        <CardContent className="text-muted-foreground">We could not load dashboard stats.</CardContent>
      </Card>
    )
  }

  return (
    <TooltipProvider>
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {statConfig.map((stat) => {
          const Icon = stat.icon
          const trend = stat.trendKey && trends?.points ? computeTrend(trends.points, stat.trendKey) : null

          return (
            <Link key={stat.key} to={stat.to} className="group">
              <Card className="transition-all duration-200 group-hover:shadow-md group-hover:border-primary/30 group-hover:-translate-y-0.5">
                <CardHeader className="flex flex-row items-center justify-between pb-2">
                  <CardTitle className="text-sm font-medium text-muted-foreground">{stat.label}</CardTitle>
                  <div
                    className={`flex h-9 w-9 items-center justify-center rounded-lg ${stat.bg} ${stat.color} transition-colors ${stat.hoverBg} group-hover:text-white`}
                  >
                    <Icon className="h-4 w-4" />
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="flex items-baseline gap-2">
                    <span className="text-3xl font-semibold tracking-tight">{data[stat.key]}</span>
                    {trend && (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span>
                            <TrendBadge pct={trend.pct} direction={trend.direction} />
                          </span>
                        </TooltipTrigger>
                        <TooltipContent side="top" className="text-xs">
                          vs. previous period
                        </TooltipContent>
                      </Tooltip>
                    )}
                  </div>
                  <p className="mt-1.5 text-xs text-muted-foreground">{stat.subtitle(data)}</p>
                </CardContent>
              </Card>
            </Link>
          )
        })}
      </div>
    </TooltipProvider>
  )
}
