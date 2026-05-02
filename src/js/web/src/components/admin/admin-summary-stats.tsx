import { Link } from "@tanstack/react-router"
import { motion } from "framer-motion"
import { Cable, CheckCircle2, Users, UsersRound, XCircle } from "lucide-react"
import { Card, CardContent } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { useAdminDashboardStats, useAdminSystemStatus } from "@/lib/api/hooks/admin"
import { useConnections } from "@/lib/api/hooks/connections"
import { cn } from "@/lib/utils"

function SummaryCardSkeleton() {
  return (
    <Card className="relative overflow-hidden">
      <CardContent className="flex items-center gap-4 p-5">
        <Skeleton className="h-11 w-11 shrink-0 rounded-lg" />
        <div className="min-w-0 flex-1 space-y-1">
          <Skeleton className="h-7 w-12" />
          <Skeleton className="h-4 w-20" />
        </div>
      </CardContent>
    </Card>
  )
}

export function AdminSummaryStats() {
  const { data: stats, isLoading: statsLoading } = useAdminDashboardStats()
  const { data: systemStatus, isLoading: systemLoading } = useAdminSystemStatus()
  const { data: connectionsData, isLoading: connectionsLoading } = useConnections({ page: 1, pageSize: 100 })

  const connections = connectionsData?.items ?? []
  const activeConnections = connections.filter(
    (c) => c.isEnabled && ["connected", "healthy", "active"].includes(c.status.toLowerCase()),
  )

  const dbOnline = systemStatus?.databaseStatus === "online"
  const allConnectionsHealthy = connections.length === 0 || activeConnections.length === connections.length
  const systemHealthy = dbOnline && allConnectionsHealthy

  const cards = [
    {
      label: "Total Users",
      value: stats?.totalUsers,
      subtitle: stats ? `${stats.activeUsers} active` : undefined,
      icon: Users,
      iconClassName: "bg-blue-500/10 text-blue-600 dark:text-blue-400",
      isLoading: statsLoading,
      href: "/admin/users",
    },
    {
      label: "Total Teams",
      value: stats?.totalTeams,
      subtitle: "All workspaces",
      icon: UsersRound,
      iconClassName: "bg-violet-500/10 text-violet-600 dark:text-violet-400",
      isLoading: statsLoading,
      href: "/admin/teams",
    },
    {
      label: "Active Connections",
      value: activeConnections.length,
      subtitle: connections.length > 0 ? `${connections.length} total` : "None configured",
      icon: Cable,
      iconClassName: "bg-cyan-500/10 text-cyan-600 dark:text-cyan-400",
      isLoading: connectionsLoading,
      href: "/connections",
    },
    {
      label: "System Health",
      value: undefined as number | undefined,
      subtitle: systemHealthy ? "All systems operational" : "Issue detected",
      icon: systemHealthy ? CheckCircle2 : XCircle,
      iconClassName: systemHealthy
        ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
        : "bg-red-500/10 text-red-600 dark:text-red-400",
      isLoading: systemLoading,
      href: "/admin/system",
      customValue: (
        <div className="flex items-center gap-2">
          <span className="relative flex h-2.5 w-2.5">
            {systemHealthy && (
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-40" />
            )}
            <span
              className={cn(
                "relative inline-flex h-2.5 w-2.5 rounded-full",
                systemHealthy ? "bg-emerald-500" : "bg-destructive",
              )}
            />
          </span>
          <span className="text-2xl font-semibold tracking-tight">
            {systemHealthy ? "OK" : "Warn"}
          </span>
        </div>
      ),
    },
  ]

  return (
    <TooltipProvider>
      <div className="grid gap-4 grid-cols-2 lg:grid-cols-4">
        {cards.map((card, index) => {
          if (card.isLoading) {
            return (
              // biome-ignore lint/suspicious/noArrayIndexKey: Static card positions
              <SummaryCardSkeleton key={`summary-skeleton-${index}`} />
            )
          }

          const Icon = card.icon

          const content = (
            <CardContent className="flex items-center gap-4 p-5">
              <div
                className={cn(
                  "flex h-11 w-11 shrink-0 items-center justify-center rounded-lg",
                  card.iconClassName,
                )}
              >
                <Icon className="h-5 w-5" />
              </div>
              <div className="min-w-0 flex-1">
                {card.customValue ? (
                  card.customValue
                ) : (
                  <p className="text-2xl font-semibold tracking-tight">{card.value ?? 0}</p>
                )}
                <Tooltip>
                  <TooltipTrigger asChild>
                    <p className="truncate text-sm text-muted-foreground">{card.label}</p>
                  </TooltipTrigger>
                  <TooltipContent side="bottom">
                    <p>{card.subtitle ?? card.label}</p>
                  </TooltipContent>
                </Tooltip>
              </div>
            </CardContent>
          )

          return (
            <motion.div
              key={card.label}
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3, delay: index * 0.06, ease: "easeOut" }}
            >
              {card.href ? (
                <Link to={card.href}>
                  <Card className="relative overflow-hidden transition-all duration-200 hover:scale-[1.02] hover:shadow-md cursor-pointer">
                    {content}
                  </Card>
                </Link>
              ) : (
                <Card className="relative overflow-hidden">{content}</Card>
              )}
            </motion.div>
          )
        })}
      </div>
    </TooltipProvider>
  )
}
