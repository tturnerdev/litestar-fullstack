import { createFileRoute, Link } from "@tanstack/react-router"
import { Send } from "lucide-react"
import { FaxMessageList } from "@/components/fax/fax-message-list"
import { Button } from "@/components/ui/button"
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
        actions={
          <Button asChild size="sm">
            <Link to="/fax/send">
              <Send className="mr-2 h-4 w-4" /> Send Fax
            </Link>
          </Button>
        }
      />
      <PageSection>
        <FaxMessageList />
      </PageSection>
    </PageContainer>
  )
}
