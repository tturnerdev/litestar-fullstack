import { createFileRoute } from "@tanstack/react-router"
import { AdminBreadcrumbs } from "@/components/admin/admin-breadcrumbs"
import { AdminNav } from "@/components/admin/admin-nav"
import { UserTable } from "@/components/admin/user-table"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"

export const Route = createFileRoute("/_app/admin/users/")({
  component: AdminUsersPage,
})

function AdminUsersPage() {
  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader eyebrow="Administration" title="Users" description="View and manage all users in the system." breadcrumbs={<AdminBreadcrumbs />} />
      <AdminNav />
      <PageSection>
        <UserTable />
      </PageSection>
    </PageContainer>
  )
}
