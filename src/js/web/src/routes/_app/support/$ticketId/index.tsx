import { createFileRoute, Link, useParams } from "@tanstack/react-router"
import { ArrowLeft } from "lucide-react"
import { TicketConversation } from "@/components/support/ticket-conversation"
import { TicketDetailHeader } from "@/components/support/ticket-detail-header"
import { TicketReplyForm } from "@/components/support/ticket-reply-form"
import { Button } from "@/components/ui/button"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Separator } from "@/components/ui/separator"
import { useTicket } from "@/lib/api/hooks/support"

export const Route = createFileRoute("/_app/support/$ticketId/")({
  component: TicketDetailPage,
})

function TicketDetailPage() {
  const { ticketId } = useParams({ from: "/_app/support/$ticketId/" as const })
  const { data: ticket, isLoading, isError } = useTicket(ticketId)

  if (isLoading) {
    return (
      <PageContainer className="flex-1">
        <div className="flex items-center justify-center py-16">
          <div className="flex flex-col items-center gap-3">
            <div className="h-8 w-8 animate-spin rounded-full border-2 border-primary border-t-transparent" />
            <p className="text-sm text-muted-foreground">Loading ticket...</p>
          </div>
        </div>
      </PageContainer>
    )
  }

  if (isError || !ticket) {
    return (
      <PageContainer className="flex-1">
        <div className="text-muted-foreground">
          {isError ? "We couldn't load this ticket. Try refreshing." : "Ticket not found"}
        </div>
      </PageContainer>
    )
  }

  const isClosed = ticket.status === "closed" || ticket.status === "resolved"

  return (
    <PageContainer className="flex-1 space-y-6">
      <PageHeader
        eyebrow="Helpdesk"
        title={ticket.subject}
        description={`${ticket.ticketNumber} · Created ${ticket.createdAt ? new Date(ticket.createdAt).toLocaleDateString() : ""}`}
        actions={
          <Button variant="outline" size="sm" asChild>
            <Link to="/support">
              <ArrowLeft className="mr-2 h-4 w-4" /> Back to Tickets
            </Link>
          </Button>
        }
      />

      <TicketDetailHeader ticket={ticket} />

      <PageSection>
        <div className="space-y-6">
          <TicketConversation ticketId={ticketId} />
          {!isClosed ? (
            <>
              <Separator />
              <TicketReplyForm ticketId={ticketId} />
            </>
          ) : (
            <div className="rounded-lg border border-dashed border-border/60 bg-muted/20 px-4 py-6 text-center">
              <p className="text-sm text-muted-foreground">
                This ticket is {ticket.status}. Reopen it to continue the conversation.
              </p>
            </div>
          )}
        </div>
      </PageSection>
    </PageContainer>
  )
}
