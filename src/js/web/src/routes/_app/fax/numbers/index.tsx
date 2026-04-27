import { createFileRoute } from "@tanstack/react-router"
import { FaxNumberTable } from "@/components/fax/fax-number-table"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"

export const Route = createFileRoute("/_app/fax/numbers/")({
  component: FaxNumbersPage,
})

function FaxNumbersPage() {
  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Communications"
        title="Fax Numbers"
        description="Manage your fax numbers and configure email delivery routes."
      />
      <PageSection>
        <FaxNumberTable />
      </PageSection>
    </PageContainer>
  )
}
