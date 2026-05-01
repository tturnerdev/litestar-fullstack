import { Activity, AlertCircle, ArrowRight, MonitorSmartphone, RefreshCw, Users, UsersRound } from "lucide-react"
import { useEffect, useState } from "react"
import { Link } from "@tanstack/react-router"
import { useQueryClient } from "@tanstack/react-query"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { EmptyState } from "@/components/ui/empty-state"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useOrganizationStats } from "@/lib/api/hooks/organization"
import { cn } from "@/lib/utils"

function formatLastUpdated(date: Date): string {
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffSec = Math.floor(diffMs / 1000)
  const diffMin = Math.floor(diffSec / 60)

  if (diffSec < 10) return "just now"
  if (diffSec < 60) return `${diffSec}s ago`
  if (diffMin < 60) return `${diffMin}m ago`
  return date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })
}

export function OrganizationStats() {
  const { data, isLoading, isError, dataUpdatedAt, refetch: refetchStats } = useOrganizationStats()
  const queryClient = useQueryClient()
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [lastUpdatedLabel, setLastUpdatedLabel] = useState("")
  const [visibleCards, setVisibleCards] = useState<boolean[]>([false, false, false, false])

  // Update the "last updated" label periodically
  useEffect(() => {
    if (!dataUpdatedAt) return
    const update = () => setLastUpdatedLabel(formatLastUpdated(new Date(dataUpdatedAt)))
    update()
    const interval = setInterval(update, 10_000)
    return () => clearInterval(interval)
  }, [dataUpdatedAt])

  // Staggered entrance animation
  useEffect(() => {
    if (!data) return
    const timers: ReturnType<typeof setTimeout>[] = []
    for (let i = 0; i < 4; i++) {
      timers.push(
        setTimeout(() => {
          setVisibleCards((prev) => {
            const next = [...prev]
            next[i] = true
            return next
          })
        }, i * 100),
      )
    }
    return () => timers.forEach(clearTimeout)
  }, [data])

  const handleRefresh = async () => {
    setIsRefreshing(true)
    await queryClient.invalidateQueries({ queryKey: ["organization", "stats"] })
    setIsRefreshing(false)
  }

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
        <EmptyState
          icon={AlertCircle}
          title="Unable to load platform statistics"
          description="The server may be unreachable. Please try again."
          action={<Button variant="outline" size="sm" onClick={() => refetchStats()}>Try again</Button>}
        />
      </div>
    )
  }

  const verifiedPercent = data.totalUsers > 0 ? Math.round((data.verifiedUsers / data.totalUsers) * 100) : 0

  const stats = [
    {
      label: "Total Users",
      value: data.totalUsers,
      description: `${data.activeUsers} active`,
      icon: Users,
      color: "text-blue-600 dark:text-blue-400",
      bgColor: "bg-blue-500/10",
      href: "/admin/users" as const,
    },
    {
      label: "Total Teams",
      value: data.totalTeams,
      description: "Across the organization",
      icon: UsersRound,
      color: "text-emerald-600 dark:text-emerald-400",
      bgColor: "bg-emerald-500/10",
      href: "/admin/teams" as const,
    },
    {
      label: "Verified Users",
      value: data.verifiedUsers,
      description: `of ${data.totalUsers} total`,
      icon: MonitorSmartphone,
      color: "text-purple-600 dark:text-purple-400",
      bgColor: "bg-purple-500/10",
      href: "/admin/users" as const,
      progressPercent: verifiedPercent,
    },
    {
      label: "Events Today",
      value: data.eventsToday,
      description: `${data.newUsersToday} new users today`,
      icon: Activity,
      color: "text-orange-600 dark:text-orange-400",
      bgColor: "bg-orange-500/10",
      href: "/admin/users" as const,
    },
  ]

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Platform Overview</h2>
        <div className="flex items-center gap-2">
          {lastUpdatedLabel && (
            <span className="text-xs text-muted-foreground">Updated {lastUpdatedLabel}</span>
          )}
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                size="sm"
                variant="ghost"
                className="h-7 w-7 p-0 text-muted-foreground hover:text-foreground"
                onClick={handleRefresh}
                disabled={isRefreshing}
              >
                <RefreshCw className={cn("h-3.5 w-3.5", isRefreshing && "animate-spin")} />
              </Button>
            </TooltipTrigger>
            <TooltipContent>Refresh stats</TooltipContent>
          </Tooltip>
        </div>
      </div>
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {stats.map((stat, index) => (
          <Link key={stat.label} to={stat.href} className="group/stat-card block">
            <Card
              className={cn(
                "cursor-pointer transition-all duration-200 hover:scale-[1.02] hover:shadow-md",
                "translate-y-0 opacity-100",
                !visibleCards[index] && "translate-y-2 opacity-0",
              )}
            >
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-sm font-medium text-muted-foreground">{stat.label}</CardTitle>
                <div className={`flex h-8 w-8 items-center justify-center rounded-lg ${stat.bgColor}`}>
                  <stat.icon className={`h-4 w-4 ${stat.color}`} />
                </div>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="text-3xl font-semibold">{stat.value.toLocaleString()}</div>
                {"progressPercent" in stat && stat.progressPercent !== undefined && (
                  <div className="space-y-1">
                    <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
                      <div
                        className="h-full rounded-full bg-purple-500 transition-all duration-500"
                        style={{ width: `${stat.progressPercent}%` }}
                      />
                    </div>
                    <p className="text-[10px] text-muted-foreground">{stat.progressPercent}% verified</p>
                  </div>
                )}
                <div className="flex items-center justify-between">
                  <p className="text-xs text-muted-foreground">{stat.description}</p>
                  <ArrowRight className="h-3 w-3 text-muted-foreground opacity-0 transition-opacity group-hover/stat-card:opacity-100" />
                </div>
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>
    </div>
  )
}
