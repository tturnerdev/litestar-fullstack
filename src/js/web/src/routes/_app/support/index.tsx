import { createFileRoute, Link } from "@tanstack/react-router"
import { Plus } from "lucide-react"
import { TicketTable } from "@/components/support/ticket-table"
import { Button } from "@/components/ui/button"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"

export const Route = createFileRoute("/_app/support/")({
  component: SupportPage,
})

function SupportPage() {
  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Helpdesk"
        title="Tickets"
        description="View and manage support tickets."
        actions={
          <Button size="sm" asChild>
            <Link to="/support/new">
              <Plus className="mr-2 h-4 w-4" /> New Ticket
            </Link>
          </Button>
        }
      />
      <PageSection>
        <TicketTable />
      </PageSection>
    </PageContainer>
  )
}
