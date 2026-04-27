import { createFileRoute } from "@tanstack/react-router"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { PhoneNumberTable } from "@/components/voice/phone-number-table"

export const Route = createFileRoute("/_app/voice/phone-numbers")({
  component: PhoneNumbersPage,
})

function PhoneNumbersPage() {
  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader eyebrow="Voice" title="Phone Numbers" description="View and manage your assigned phone numbers." />
      <PageSection>
        <PhoneNumberTable />
      </PageSection>
    </PageContainer>
  )
}
