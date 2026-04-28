import { createFileRoute, Link } from "@tanstack/react-router"
import { ArrowLeft } from "lucide-react"
import { SendFaxForm } from "@/components/fax/send-fax-form"
import { Button } from "@/components/ui/button"
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
        actions={
          <Button variant="outline" size="sm" asChild>
            <Link to="/fax">
              <ArrowLeft className="mr-2 h-4 w-4" /> Back to fax
            </Link>
          </Button>
        }
      />
      <PageSection>
        <SendFaxForm />
      </PageSection>
    </PageContainer>
  )
}
