import { useQuery } from "@tanstack/react-query"
import { Link } from "@tanstack/react-router"
import { ArrowRight, Bell, Laptop, TicketCheck, TrendingUp, Users } from "lucide-react"
import type { LucideIcon } from "lucide-react"
import { Card, CardContent } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { useAuthStore } from "@/lib/auth"
import { listTeams } from "@/lib/generated/api"

interface StatItem {
  label: string
  value: number
  icon: LucideIcon
  to: string
  color: string
  trend?: "up" | "down" | "neutral"
}

export function QuickStats() {
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated)

  const { data: teamsData, isLoading: teamsLoading } = useQuery({
    queryKey: ["teams"],
    queryFn: async () => {
      const response = await listTeams()
      return response.data?.items ?? []
    },
    enabled: isAuthenticated,
  })

  const isLoading = teamsLoading

  const teamCount = teamsData?.length ?? 0

  const stats: StatItem[] = [
    {
      label: "Your Teams",
      value: teamCount,
      icon: Users,
      to: "/teams",
      color: "text-blue-600 bg-blue-500/10 dark:text-blue-400",
      trend: teamCount > 0 ? "up" : undefined,
    },
    {
      label: "Your Devices",
      value: 0,
      icon: Laptop,
      to: "/devices",
      color: "text-emerald-600 bg-emerald-500/10 dark:text-emerald-400",
    },
    {
      label: "Open Tickets",
      value: 0,
      icon: TicketCheck,
      to: "/support/tickets",
      color: "text-amber-600 bg-amber-500/10 dark:text-amber-400",
    },
    {
      label: "Notifications",
      value: 0,
      icon: Bell,
      to: "/notifications",
      color: "text-violet-600 bg-violet-500/10 dark:text-violet-400",
    },
  ]

  if (isLoading) {
    return (
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
          <Card key={`stat-skeleton-${i}`}>
            <CardContent className="flex items-center gap-4 py-4">
              <Skeleton className="h-10 w-10 animate-pulse rounded-lg" />
              <div className="space-y-1.5">
                <Skeleton className="h-3 w-20 animate-pulse" />
                <Skeleton className="h-7 w-10 animate-pulse" />
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    )
  }

  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
      {stats.map((stat) => (
        <Link key={stat.label} to={stat.to}>
          <Card hover className="group transition-all hover:scale-[1.02]">
            <CardContent className="relative flex items-center gap-4 py-4">
              <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg ${stat.color}`}>
                <stat.icon className="h-5 w-5" />
              </div>
              <div>
                <p className="text-xs font-medium text-muted-foreground">{stat.label}</p>
                <div className="flex items-center gap-1.5">
                  <p className={`animate-in fade-in text-2xl font-semibold tracking-tight duration-500 ${stat.value === 0 ? "text-muted-foreground" : ""}`}>
                    {stat.value}
                  </p>
                  {stat.trend === "up" && (
                    <TrendingUp className="h-3.5 w-3.5 text-emerald-500" />
                  )}
                </div>
                {stat.value === 0 && (
                  <p className="text-[10px] text-muted-foreground/70">Set up</p>
                )}
              </div>
              <ArrowRight className="absolute top-3 right-3 h-3 w-3 text-muted-foreground/0 transition-all group-hover:text-muted-foreground" />
            </CardContent>
          </Card>
        </Link>
      ))}
    </div>
  )
}
