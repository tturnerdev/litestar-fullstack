import { useQuery } from "@tanstack/react-query"
import { Link } from "@tanstack/react-router"
import { Bell, Laptop, TicketCheck, Users } from "lucide-react"
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

  const stats: StatItem[] = [
    {
      label: "Your Teams",
      value: teamsData?.length ?? 0,
      icon: Users,
      to: "/teams",
      color: "text-blue-600 bg-blue-500/10 dark:text-blue-400",
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
              <Skeleton className="h-10 w-10 rounded-lg" />
              <div className="space-y-1.5">
                <Skeleton className="h-3 w-20" />
                <Skeleton className="h-7 w-10" />
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
          <Card hover className="transition-all">
            <CardContent className="flex items-center gap-4 py-4">
              <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg ${stat.color}`}>
                <stat.icon className="h-5 w-5" />
              </div>
              <div>
                <p className="text-xs font-medium text-muted-foreground">{stat.label}</p>
                <p className="text-2xl font-semibold tracking-tight">{stat.value}</p>
              </div>
            </CardContent>
          </Card>
        </Link>
      ))}
    </div>
  )
}
