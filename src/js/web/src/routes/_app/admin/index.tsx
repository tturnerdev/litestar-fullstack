import { createFileRoute } from "@tanstack/react-router"
import { AdminCharts } from "@/components/admin/admin-charts"
import { AdminNav } from "@/components/admin/admin-nav"
import { AdminQuickActions } from "@/components/admin/admin-quick-actions"
import { RecentActivity } from "@/components/admin/recent-activity"
import { StatsCards } from "@/components/admin/stats-cards"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"

export const Route = createFileRoute("/_app/admin/")({
  component: AdminDashboardPage,
})

function AdminDashboardPage() {
  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader eyebrow="Administration" title="Admin Console" description="Review activity, manage users, and oversee teams." />
      <AdminNav />
      <PageSection>
        <StatsCards />
      </PageSection>
      <PageSection delay={0.1}>
        <AdminCharts />
      </PageSection>
      <PageSection delay={0.2}>
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          <div className="lg:col-span-2">
            <RecentActivity />
          </div>
          <div>
            <AdminQuickActions />
          </div>
        </div>
      </PageSection>
    </PageContainer>
  )
}
