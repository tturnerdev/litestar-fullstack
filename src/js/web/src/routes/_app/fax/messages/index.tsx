import { createFileRoute } from "@tanstack/react-router"
import { FaxMessageTable } from "@/components/fax/fax-message-table"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"

export const Route = createFileRoute("/_app/fax/messages/")({
  component: FaxMessagesPage,
})

function FaxMessagesPage() {
  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Communications"
        title="Fax Messages"
        description="View your fax history, filter by direction and status."
      />
      <PageSection>
        <FaxMessageTable />
      </PageSection>
    </PageContainer>
  )
}
