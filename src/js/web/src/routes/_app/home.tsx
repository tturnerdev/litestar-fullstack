import { useQuery } from "@tanstack/react-query"
import { createFileRoute, Link } from "@tanstack/react-router"
import { AlertCircle, Plus, ShieldCheck, Tag, Users } from "lucide-react"
import { FeatureAreasGrid } from "@/components/home/feature-areas-grid"
import { GettingStarted } from "@/components/home/getting-started"
import { useGreeting } from "@/components/home/greeting"
import { QuickActionsCard } from "@/components/home/quick-actions-card"
import { RecentActivityCard } from "@/components/home/recent-activity-card"
import { StatCard } from "@/components/home/stat-card"
import { TeamsCard } from "@/components/home/teams-card"
import { Button } from "@/components/ui/button"
import { EmptyState } from "@/components/ui/empty-state"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { useAuthStore } from "@/lib/auth"
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

function HomePage() {
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

  const { data: adminStats, isLoading: adminStatsLoading, isError: adminStatsError } = useQuery({
    queryKey: ["admin", "stats"],
    queryFn: async () => {
      const response = await getDashboardStats()
      return response.data as DashboardStats
    },
    enabled: isSuperuser,
  })

  const { data: activityData, isLoading: activityLoading, isError: activityError } = useQuery({
    queryKey: ["admin", "activity"],
    queryFn: async () => {
      const response = await getRecentActivity({ query: { limit: 8 } })
      return response.data as RecentActivity
    },
    enabled: isSuperuser,
  })

  const teams = teamsRaw?.items ?? []

  const hasError = teamsError || tagsError || rolesError || adminStatsError || activityError

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

      {/* Stats Cards Row */}
      <PageSection delay={0.05}>
        <div className="grid gap-4 grid-cols-2 lg:grid-cols-4">
          <StatCard
            label="Teams"
            value={teamsRaw?.total ?? teams.length}
            icon={Users}
            iconClassName="bg-blue-500/10 text-blue-600 dark:text-blue-400"
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
        <div className="grid gap-6 md:grid-cols-2">
          <TeamsCard teams={teams} isLoading={teamsLoading} />
          <QuickActionsCard isSuperuser={isSuperuser} teamCount={teams.length} />
        </div>
      </PageSection>

      {/* Recent Activity (admin only) */}
      {isSuperuser && (
        <PageSection delay={0.18}>
          <RecentActivityCard
            activities={activityData?.activities ?? []}
            isLoading={activityLoading}
            isAdmin={isSuperuser}
          />
        </PageSection>
      )}
    </PageContainer>
  )
}
