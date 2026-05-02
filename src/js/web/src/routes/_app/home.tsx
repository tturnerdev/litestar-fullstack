import { useQuery } from "@tanstack/react-query"
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router"
import {
  AlertCircle,
  ArrowRight,
  Bell,
  BellOff,
  Laptop,
  ListTodo,
  MessageSquare,
  Monitor,
  Phone,
  Plus,
  Printer,
  Settings,
  ShieldCheck,
  Tag,
  TicketCheck,
  TrendingUp,
  Users,
  type LucideIcon,
} from "lucide-react"
import { useMemo } from "react"
import { Area, AreaChart, ResponsiveContainer, Tooltip as RechartsTooltip, XAxis, YAxis } from "recharts"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { ConnectionsStatusCard } from "@/components/home/connections-status-card"
import { FeatureAreasGrid } from "@/components/home/feature-areas-grid"
import { GettingStarted } from "@/components/home/getting-started"
import { useGreeting } from "@/components/home/greeting"
import { QuickActionsCard } from "@/components/home/quick-actions-card"
import { RecentActivityCard } from "@/components/home/recent-activity-card"
import { StatCard } from "@/components/home/stat-card"
import { TeamsCard } from "@/components/home/teams-card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { EmptyState } from "@/components/ui/empty-state"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Skeleton } from "@/components/ui/skeleton"
import { useDevices } from "@/lib/api/hooks/devices"
import { useNotifications, useUnreadCount } from "@/lib/api/hooks/notifications"
import { useTickets } from "@/lib/api/hooks/support"
import { useActiveTasks } from "@/lib/api/hooks/tasks"
import { useAuthStore } from "@/lib/auth"
import { formatRelativeTimeShort } from "@/lib/date-utils"
import { useDocumentTitle } from "@/hooks/use-document-title"
import {
  type DashboardStats,
  type RecentActivity,
  getDashboardStats,
  getRecentActivity,
  listRoles,
  listTags,
  listTeams,
} from "@/lib/generated/api"

export const Route = createFileRoute("/_app/home")({
  component: HomePage,
})

// --- Recent Notifications Card ---

const notificationCategoryIcons: Record<string, LucideIcon> = {
  ticket: MessageSquare,
  team: Users,
  device: Laptop,
  system: Settings,
  voice: Phone,
  fax: Printer,
}

function getNotificationCategoryIcon(category: string): LucideIcon {
  return notificationCategoryIcons[category] ?? Bell
}

function getNotificationCategoryColor(category: string): { text: string; bg: string } {
  switch (category) {
    case "ticket":
    case "support":
      return { text: "text-blue-600 dark:text-blue-400", bg: "bg-blue-500/15" }
    case "team":
    case "teams":
      return { text: "text-purple-600 dark:text-purple-400", bg: "bg-purple-500/15" }
    case "device":
    case "devices":
      return { text: "text-green-600 dark:text-green-400", bg: "bg-green-500/15" }
    case "system":
      return { text: "text-orange-600 dark:text-orange-400", bg: "bg-orange-500/15" }
    case "voice":
      return { text: "text-cyan-600 dark:text-cyan-400", bg: "bg-cyan-500/15" }
    case "fax":
      return { text: "text-amber-600 dark:text-amber-400", bg: "bg-amber-500/15" }
    default:
      return { text: "text-muted-foreground", bg: "bg-muted" }
  }
}

function RecentNotificationsCard() {
  const navigate = useNavigate()
  const { data, isLoading } = useNotifications(1, 5)
  const notifications = data?.items?.filter((n) => !n.isRead).slice(0, 5) ?? []

  if (isLoading) {
    return (
      <Card>
        <CardHeader className="space-y-1 pb-4">
          <div className="flex items-center gap-2">
            <Bell className="h-4 w-4 text-muted-foreground" />
            <CardTitle className="text-lg">Recent Notifications</CardTitle>
          </div>
          <CardDescription>Your latest unread notifications</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {Array.from({ length: 3 }).map((_, i) => (
            // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
            <div key={`notif-skeleton-${i}`} className="flex items-center gap-3">
              <Skeleton className="h-7 w-7 shrink-0 rounded-full" />
              <div className="flex-1 space-y-1">
                <Skeleton className="h-4 w-3/4" />
                <Skeleton className="h-3 w-1/2" />
              </div>
              <Skeleton className="h-3 w-12" />
            </div>
          ))}
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader className="space-y-1 pb-4">
        <div className="flex items-center gap-2">
          <Bell className="h-4 w-4 text-muted-foreground" />
          <CardTitle className="text-lg">Recent Notifications</CardTitle>
        </div>
        <CardDescription>Your latest unread notifications</CardDescription>
      </CardHeader>
      <CardContent>
        {notifications.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-8 text-center">
            <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-muted">
              <BellOff className="h-6 w-6 text-muted-foreground" />
            </div>
            <p className="text-sm font-medium text-muted-foreground">No new notifications</p>
            <p className="mt-1 text-xs text-muted-foreground/70">You're all caught up.</p>
          </div>
        ) : (
          <div className="space-y-1">
            {notifications.map((notification) => {
              const Icon = getNotificationCategoryIcon(notification.category)
              const color = getNotificationCategoryColor(notification.category)

              return (
                <button
                  key={notification.id}
                  type="button"
                  className="flex w-full items-start gap-3 rounded-lg px-3 py-2.5 text-left transition-colors hover:bg-muted/50"
                  onClick={() => {
                    void navigate({ to: notification.actionUrl ?? "/notifications" })
                  }}
                >
                  <div className={`mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-full ${color.bg}`}>
                    <Icon className={`h-3.5 w-3.5 ${color.text}`} />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <p className="truncate text-sm font-medium">{notification.title}</p>
                      <Badge variant="secondary" className="h-5 shrink-0 px-1.5 py-0 text-[10px] font-medium capitalize">
                        {notification.category}
                      </Badge>
                    </div>
                    <p className="truncate text-xs text-muted-foreground">{notification.message}</p>
                  </div>
                  <span className="shrink-0 pt-0.5 text-xs text-muted-foreground">
                    {formatRelativeTimeShort(notification.createdAt)}
                  </span>
                </button>
              )
            })}
          </div>
        )}
        <div className="mt-4 border-t pt-3">
          <Link
            to="/notifications"
            className="flex items-center justify-center gap-1.5 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground"
          >
            View all notifications
            <ArrowRight className="h-3.5 w-3.5" />
          </Link>
        </div>
      </CardContent>
    </Card>
  )
}

function HomePage() {
  useDocumentTitle("Dashboard")
  const user = useAuthStore((state) => state.user)
  const isSuperuser = user?.isSuperuser ?? false
  const greeting = useGreeting()

  const { data: teamsRaw, isLoading: teamsLoading, isError: teamsError } = useQuery({
    queryKey: ["home", "teams"],
    queryFn: async () => {
      const response = await listTeams()
      const data = response.data
      if (Array.isArray(data)) return { items: data, total: data.length }
      return { items: data?.items ?? [], total: data?.total ?? 0 }
    },
  })

  const { data: tagsData, isLoading: tagsLoading, isError: tagsError } = useQuery({
    queryKey: ["home", "tags-count"],
    queryFn: async () => {
      const response = await listTags({ query: { currentPage: 1, pageSize: 1 } })
      return response.data as { total?: number } | undefined
    },
  })

  const { data: rolesData, isLoading: rolesLoading, isError: rolesError } = useQuery({
    queryKey: ["home", "roles-count"],
    queryFn: async () => {
      const response = await listRoles({ query: { currentPage: 1, pageSize: 1 } })
      return response.data as { total?: number } | undefined
    },
  })

  const { data: adminStats, isLoading: adminStatsLoading } = useQuery({
    queryKey: ["admin", "stats"],
    queryFn: async () => {
      const response = await getDashboardStats()
      return response.data as DashboardStats
    },
    enabled: isSuperuser,
  })

  const { data: activityData, isLoading: activityLoading } = useQuery({
    queryKey: ["admin", "activity"],
    queryFn: async () => {
      const response = await getRecentActivity({ query: { limit: 8 } })
      return response.data as RecentActivity
    },
    enabled: isSuperuser,
  })

  const { data: chartActivityData } = useQuery({
    queryKey: ["admin", "activity-chart"],
    queryFn: async () => {
      const response = await getRecentActivity({ query: { limit: 200, hours: 168 } })
      return response.data as RecentActivity
    },
    enabled: isSuperuser,
  })

  const chartData = useMemo(() => {
    const days: { date: string; label: string; count: number }[] = []
    const now = new Date()
    for (let i = 6; i >= 0; i--) {
      const d = new Date(now)
      d.setDate(d.getDate() - i)
      const dateKey = d.toISOString().slice(0, 10)
      const label = d.toLocaleDateString("en-US", { weekday: "short" })
      days.push({ date: dateKey, label, count: 0 })
    }
    if (chartActivityData?.activities) {
      for (const activity of chartActivityData.activities) {
        const dateKey = activity.createdAt.slice(0, 10)
        const day = days.find((d) => d.date === dateKey)
        if (day) day.count++
      }
    }
    return days
  }, [chartActivityData])

  // Operational stats
  const { data: devicesData, isLoading: devicesLoading } = useDevices({ page: 1, pageSize: 1 })
  const { data: openTicketsData, isLoading: ticketsLoading } = useTickets(1, 1, { status: "open" })
  const { data: unreadData, isLoading: unreadLoading } = useUnreadCount()
  const { data: activeTasksData, isLoading: activeTasksLoading } = useActiveTasks()

  const teams = teamsRaw?.items ?? []

  const hasError = teamsError || tagsError || rolesError

  if (hasError) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader
          eyebrow="Dashboard"
          title={greeting}
          description="Manage your teams, devices, and services from one place."
        />
        <EmptyState
          icon={AlertCircle}
          title="Unable to load dashboard"
          description="Something went wrong. Please try refreshing the page."
          action={
            <Button variant="outline" size="sm" onClick={() => window.location.reload()}>
              Refresh page
            </Button>
          }
        />
      </PageContainer>
    )
  }

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Dashboard"
        title={greeting}
        description="Manage your teams, devices, and services from one place."
        actions={
          <Button size="sm" asChild>
            <Link to="/teams/new">
              <Plus className="mr-2 h-4 w-4" /> Create team
            </Link>
          </Button>
        }
      />

      {/* Operational Stats Row */}
      <PageSection delay={0.05}>
        <div className="grid gap-4 grid-cols-2 lg:grid-cols-4">
          <StatCard
            label="Devices"
            value={devicesData?.total}
            icon={Monitor}
            iconClassName="bg-blue-500/10 text-blue-600 dark:text-blue-400"
            isLoading={devicesLoading}
            href="/devices"
            index={0}
          />
          <StatCard
            label="Open Tickets"
            value={openTicketsData?.total}
            icon={TicketCheck}
            iconClassName="bg-amber-500/10 text-amber-600 dark:text-amber-400"
            isLoading={ticketsLoading}
            href="/support"
            index={1}
          />
          <StatCard
            label="Notifications"
            value={unreadData?.count}
            icon={Bell}
            iconClassName="bg-rose-500/10 text-rose-600 dark:text-rose-400"
            isLoading={unreadLoading}
            href="/notifications"
            index={2}
          />
          <StatCard
            label="Active Tasks"
            value={activeTasksData?.length}
            icon={ListTodo}
            iconClassName="bg-indigo-500/10 text-indigo-600 dark:text-indigo-400"
            isLoading={activeTasksLoading}
            href="/tasks"
            index={3}
          />
        </div>
      </PageSection>

      {/* Organization Stats Row */}
      <PageSection delay={0.07}>
        <div className="grid gap-4 grid-cols-2 lg:grid-cols-4">
          <StatCard
            label="Teams"
            value={teamsRaw?.total ?? teams.length}
            icon={Users}
            iconClassName="bg-cyan-500/10 text-cyan-600 dark:text-cyan-400"
            isLoading={teamsLoading}
            href="/teams"
            index={0}
          />
          <StatCard
            label="Tags"
            value={tagsData?.total}
            icon={Tag}
            iconClassName="bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
            isLoading={tagsLoading}
            href="/tags"
            index={1}
          />
          <StatCard
            label="Roles"
            value={rolesData?.total}
            icon={ShieldCheck}
            iconClassName="bg-violet-500/10 text-violet-600 dark:text-violet-400"
            isLoading={rolesLoading}
            index={2}
          />
          {isSuperuser ? (
            <StatCard
              label="Total Users"
              value={adminStats?.totalUsers}
              icon={Users}
              iconClassName="bg-orange-500/10 text-orange-600 dark:text-orange-400"
              isLoading={adminStatsLoading}
              href="/admin"
              index={3}
            />
          ) : (
            <StatCard
              label="Team Members"
              value={teams.reduce((sum, t) => sum + (t.members?.length ?? 0), 0)}
              icon={Users}
              iconClassName="bg-orange-500/10 text-orange-600 dark:text-orange-400"
              isLoading={teamsLoading}
              index={3}
            />
          )}
        </div>
      </PageSection>

      {/* Feature Areas */}
      <PageSection delay={0.08}>
        <div className="space-y-3">
          <h2 className="text-lg font-semibold tracking-tight">Feature Areas</h2>
          <FeatureAreasGrid />
        </div>
      </PageSection>

      {/* Getting Started Checklist */}
      <PageSection delay={0.1}>
        <GettingStarted />
      </PageSection>

      {/* Main Content Grid */}
      <PageSection delay={0.12}>
        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
          <TeamsCard teams={teams} isLoading={teamsLoading} />
          <SectionErrorBoundary name="Recent Notifications">
            <RecentNotificationsCard />
          </SectionErrorBoundary>
          <SectionErrorBoundary name="Integration Status">
            <ConnectionsStatusCard />
          </SectionErrorBoundary>
        </div>
      </PageSection>

      {/* Quick Actions */}
      <PageSection delay={0.15}>
        <QuickActionsCard isSuperuser={isSuperuser} teamCount={teams.length} />
      </PageSection>

      {/* Admin Section: Recent Activity + Chart */}
      {isSuperuser && (
        <PageSection delay={0.18}>
          <div className="grid gap-6 md:grid-cols-2">
            <SectionErrorBoundary name="Recent Activity">
              <RecentActivityCard
                activities={activityData?.activities ?? []}
                isLoading={activityLoading}
                isAdmin={isSuperuser}
              />
            </SectionErrorBoundary>
            <SectionErrorBoundary name="Activity Chart">
              <Card>
                <CardHeader className="space-y-1 pb-2">
                  <div className="flex items-center gap-2">
                    <TrendingUp className="h-4 w-4 text-muted-foreground" />
                    <CardTitle className="text-lg">7-Day Activity</CardTitle>
                  </div>
                  <CardDescription>Events across the platform this week</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="h-[200px] w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={chartData} margin={{ top: 8, right: 8, bottom: 0, left: -20 }}>
                        <defs>
                          <linearGradient id="activityGradient" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor="hsl(var(--primary))" stopOpacity={0.3} />
                            <stop offset="95%" stopColor="hsl(var(--primary))" stopOpacity={0.02} />
                          </linearGradient>
                        </defs>
                        <XAxis
                          dataKey="label"
                          axisLine={false}
                          tickLine={false}
                          tick={{ fontSize: 12, fill: "hsl(var(--muted-foreground))" }}
                          dy={4}
                        />
                        <YAxis
                          axisLine={false}
                          tickLine={false}
                          tick={{ fontSize: 12, fill: "hsl(var(--muted-foreground))" }}
                          allowDecimals={false}
                        />
                        <RechartsTooltip
                          contentStyle={{
                            backgroundColor: "hsl(var(--popover))",
                            border: "1px solid hsl(var(--border))",
                            borderRadius: "var(--radius)",
                            fontSize: 13,
                            color: "hsl(var(--popover-foreground))",
                          }}
                          formatter={(value) => [String(value), "Events"]}
                          labelFormatter={(label) => String(label)}
                        />
                        <Area
                          type="monotone"
                          dataKey="count"
                          stroke="hsl(var(--primary))"
                          strokeWidth={2}
                          fill="url(#activityGradient)"
                        />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </CardContent>
              </Card>
            </SectionErrorBoundary>
          </div>
        </PageSection>
      )}
    </PageContainer>
  )
}
