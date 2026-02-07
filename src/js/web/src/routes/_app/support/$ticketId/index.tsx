import { useParams } from "@tanstack/react-router"
import { createFileRoute, Link } from "@tanstack/react-router"
import { ArrowLeft, Lock, Unlock } from "lucide-react"
import { TicketConversation } from "@/components/support/ticket-conversation"
import { TicketPriorityBadge } from "@/components/support/ticket-priority-badge"
import { TicketReplyForm } from "@/components/support/ticket-reply-form"
import { TicketStatusBadge } from "@/components/support/ticket-status-badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Separator } from "@/components/ui/separator"
import { useCloseTicket, useReopenTicket, useTicket } from "@/lib/api/hooks/support"

export const Route = createFileRoute("/_app/support/$ticketId/")({
  component: TicketDetailPage,
})

function TicketDetailPage() {
  const { ticketId } = useParams({ from: "/_app/support/$ticketId/" as const })
  const { data: ticket, isLoading, isError } = useTicket(ticketId)
  const closeTicket = useCloseTicket(ticketId)
  const reopenTicket = useReopenTicket(ticketId)

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
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Helpdesk"
        title={ticket.subject}
        description={`${ticket.ticketNumber} · Created ${ticket.createdAt ? new Date(ticket.createdAt).toLocaleDateString() : ""}`}
        actions={
          <div className="flex items-center gap-3">
            <Button variant="outline" size="sm" asChild>
              <Link to="/support">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back
              </Link>
            </Button>
            {isClosed ? (
              <Button
                size="sm"
                variant="outline"
                onClick={() => reopenTicket.mutate()}
                disabled={reopenTicket.isPending}
              >
                <Unlock className="mr-2 h-4 w-4" />
                Reopen
              </Button>
            ) : (
              <Button
                size="sm"
                variant="outline"
                onClick={() => closeTicket.mutate()}
                disabled={closeTicket.isPending}
              >
                <Lock className="mr-2 h-4 w-4" />
                Close
              </Button>
            )}
          </div>
        }
      />

      <PageSection>
        <div className="grid gap-6 md:grid-cols-[1fr_280px]">
          {/* Conversation */}
          <div className="space-y-6">
            <TicketConversation ticketId={ticketId} />
            {!isClosed && (
              <>
                <Separator />
                <TicketReplyForm ticketId={ticketId} />
              </>
            )}
          </div>

          {/* Sidebar */}
          <div className="space-y-4">
            <Card className="border-border/60 bg-card/80">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium">Details</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3 text-sm">
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">Status</span>
                  <TicketStatusBadge status={ticket.status} />
                </div>
                <Separator />
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">Priority</span>
                  <TicketPriorityBadge priority={ticket.priority} />
                </div>
                <Separator />
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">Category</span>
                  <span className="text-foreground">{ticket.category ?? "—"}</span>
                </div>
                <Separator />
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">Messages</span>
                  <span className="text-foreground">{ticket.messageCount}</span>
                </div>
                {ticket.assignedTo && (
                  <>
                    <Separator />
                    <div className="flex items-center justify-between">
                      <span className="text-muted-foreground">Assigned to</span>
                      <span className="text-foreground">{ticket.assignedTo.name ?? ticket.assignedTo.email}</span>
                    </div>
                  </>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      </PageSection>
    </PageContainer>
  )
}
