import { Activity, MonitorSmartphone, Users, UsersRound } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { SkeletonCard } from "@/components/ui/skeleton"
import { useOrganizationStats } from "@/lib/api/hooks/organization"

export function OrganizationStats() {
  const { data, isLoading, isError } = useOrganizationStats()

  if (isLoading) {
    return (
      <div className="space-y-3">
        <h2 className="text-lg font-semibold">Platform Overview</h2>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {Array.from({ length: 4 }).map((_, index) => (
            // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
            <SkeletonCard key={`stat-skeleton-${index}`} />
          ))}
        </div>
      </div>
    )
  }

  if (isError || !data) {
    return (
      <div className="space-y-3">
        <h2 className="text-lg font-semibold">Platform Overview</h2>
        <Card>
          <CardContent className="py-6 text-center text-muted-foreground">
            Unable to load platform statistics.
          </CardContent>
        </Card>
      </div>
    )
  }

  const stats = [
    {
      label: "Total Users",
      value: data.totalUsers,
      description: `${data.activeUsers} active`,
      icon: Users,
      color: "text-blue-600 dark:text-blue-400",
      bgColor: "bg-blue-500/10",
    },
    {
      label: "Total Teams",
      value: data.totalTeams,
      description: "Across the organization",
      icon: UsersRound,
      color: "text-emerald-600 dark:text-emerald-400",
      bgColor: "bg-emerald-500/10",
    },
    {
      label: "Verified Users",
      value: data.verifiedUsers,
      description: `of ${data.totalUsers} total`,
      icon: MonitorSmartphone,
      color: "text-purple-600 dark:text-purple-400",
      bgColor: "bg-purple-500/10",
    },
    {
      label: "Events Today",
      value: data.eventsToday,
      description: `${data.newUsersToday} new users today`,
      icon: Activity,
      color: "text-orange-600 dark:text-orange-400",
      bgColor: "bg-orange-500/10",
    },
  ]

  return (
    <div className="space-y-3">
      <h2 className="text-lg font-semibold">Platform Overview</h2>
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {stats.map((stat) => (
          <Card key={stat.label}>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">{stat.label}</CardTitle>
              <div className={`flex h-8 w-8 items-center justify-center rounded-lg ${stat.bgColor}`}>
                <stat.icon className={`h-4 w-4 ${stat.color}`} />
              </div>
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-semibold">{stat.value.toLocaleString()}</div>
              <p className="mt-1 text-xs text-muted-foreground">{stat.description}</p>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  )
}
