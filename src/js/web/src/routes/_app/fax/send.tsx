import { createFileRoute } from "@tanstack/react-router"
import { SendFaxForm } from "@/components/fax/send-fax-form"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"

export const Route = createFileRoute("/_app/fax/send")({
  component: SendFaxPage,
})

function SendFaxPage() {
  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Communications"
        title="Send Fax"
        description="Upload a PDF document and send it via fax."
      />
      <PageSection>
        <SendFaxForm />
      </PageSection>
    </PageContainer>
  )
}
