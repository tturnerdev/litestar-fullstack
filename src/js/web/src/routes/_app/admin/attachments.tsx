import { createFileRoute } from "@tanstack/react-router"
import { AdminNav } from "@/components/admin/admin-nav"
import { AttachmentTable } from "@/components/admin/attachment-table"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"

export const Route = createFileRoute("/_app/admin/attachments")({
  component: AdminAttachmentsPage,
})

function AdminAttachmentsPage() {
  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader eyebrow="Administration" title="Attachments" description="View and manage all uploaded files in the system." />
      <AdminNav />
      <PageSection>
        <AttachmentTable />
      </PageSection>
    </PageContainer>
  )
}
