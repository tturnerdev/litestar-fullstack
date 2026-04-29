import { Link } from "@tanstack/react-router"
import { Activity, CalendarPlus, Users, UsersRound } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { useAdminDashboardStats } from "@/lib/api/hooks/admin"

const statConfig = [
  {
    key: "totalUsers" as const,
    label: "Total Users",
    subtitle: (data: { activeUsers: number }) => `${data.activeUsers} active`,
    icon: Users,
    color: "text-blue-600 dark:text-blue-400",
    bg: "bg-blue-500/10",
    hoverBg: "group-hover:bg-blue-500",
    to: "/admin/users",
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
  },
  {
    key: "newUsersToday" as const,
    label: "New Users Today",
    subtitle: (data: { newUsersWeek: number }) => `${data.newUsersWeek} this week`,
    icon: CalendarPlus,
    color: "text-emerald-600 dark:text-emerald-400",
    bg: "bg-emerald-500/10",
    hoverBg: "group-hover:bg-emerald-500",
    to: "/admin/users",
  },
] as const

function StatsCardSkeleton() {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <Skeleton className="h-4 w-24" />
        <Skeleton className="h-9 w-9 rounded-lg" />
      </CardHeader>
      <CardContent>
        <Skeleton className="mb-1 h-8 w-16" />
        <Skeleton className="h-3 w-20" />
      </CardContent>
    </Card>
  )
}

export function StatsCards() {
  const { data, isLoading, isError } = useAdminDashboardStats()

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
    <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
      {statConfig.map((stat) => {
        const Icon = stat.icon
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
                <div className="text-3xl font-semibold tracking-tight">{data[stat.key]}</div>
                <p className="mt-1 text-xs text-muted-foreground">{stat.subtitle(data)}</p>
              </CardContent>
            </Card>
          </Link>
        )
      })}
    </div>
  )
}
