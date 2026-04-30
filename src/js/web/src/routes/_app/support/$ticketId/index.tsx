import { createFileRoute, Link, useParams } from "@tanstack/react-router"
import { AlertCircle, ArrowLeft, MessageSquare, Pencil } from "lucide-react"
import { TicketConversation } from "@/components/support/ticket-conversation"
import { TicketDetailHeader } from "@/components/support/ticket-detail-header"
import { TicketPriorityBadge } from "@/components/support/ticket-priority-badge"
import { TicketReplyForm } from "@/components/support/ticket-reply-form"
import { TicketStatusBadge } from "@/components/support/ticket-status-badge"
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"
import { useTicket } from "@/lib/api/hooks/support"

export const Route = createFileRoute("/_app/support/$ticketId/")({
  component: TicketDetailPage,
})

// ── Loading Skeleton ─────────────────────────────────────────────────────

function TicketDetailSkeleton() {
  return (
    <PageContainer className="flex-1 space-y-6">
      {/* Header skeleton */}
      <div className="mb-8 flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
        <div className="space-y-3">
          <Skeleton className="h-3 w-16" />
          <Skeleton className="h-9 w-80" />
          <div className="flex items-center gap-2">
            <Skeleton className="h-4 w-24" />
            <Skeleton className="h-4 w-32" />
          </div>
        </div>
        <Skeleton className="h-9 w-36" />
      </div>

      {/* Info card skeleton */}
      <Card className="border-border/60">
        <CardContent className="py-4">
          <div className="flex items-center gap-4">
            <Skeleton className="h-5 w-20" />
            <Skeleton className="h-5 w-16" />
            <Skeleton className="h-5 w-16" />
            <div className="ml-auto flex gap-2">
              <Skeleton className="h-7 w-20" />
              <Skeleton className="h-7 w-16" />
              <Skeleton className="h-7 w-16" />
            </div>
          </div>
          <Separator className="my-4" />
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="space-y-2">
                <Skeleton className="h-3 w-16" />
                <Skeleton className="h-4 w-28" />
              </div>
            ))}
          </div>
          <Separator className="my-4" />
          <div className="flex gap-6">
            <Skeleton className="h-3 w-24" />
            <Skeleton className="h-3 w-24" />
          </div>
        </CardContent>
      </Card>

      {/* Messages skeleton */}
      <div className="space-y-4">
        <Skeleton className="h-4 w-20" />
        {Array.from({ length: 3 }).map((_, i) => (
          <Card key={i} className="border-border/60">
            <CardContent className="space-y-3 py-4">
              <div className="flex items-center gap-2">
                <Skeleton className="h-8 w-8 rounded-full" />
                <div className="space-y-1">
                  <Skeleton className="h-4 w-28" />
                  <Skeleton className="h-3 w-16" />
                </div>
              </div>
              <Skeleton className="h-4 w-full" />
              <Skeleton className="h-4 w-3/4" />
            </CardContent>
          </Card>
        ))}
      </div>
    </PageContainer>
  )
}

// ── Error State ──────────────────────────────────────────────────────────

function TicketNotFound({ message }: { message: string }) {
  return (
    <PageContainer className="flex-1">
      <div className="flex flex-col items-center justify-center py-24">
        <div className="flex h-16 w-16 items-center justify-center rounded-full bg-muted/50">
          <AlertCircle className="h-8 w-8 text-muted-foreground" />
        </div>
        <h2 className="mt-4 text-lg font-semibold">Unable to load ticket</h2>
        <p className="mt-1 max-w-sm text-center text-sm text-muted-foreground">{message}</p>
        <Button variant="outline" size="sm" asChild className="mt-6">
          <Link to="/support">
            <ArrowLeft className="mr-2 h-4 w-4" /> Back to Tickets
          </Link>
        </Button>
      </div>
    </PageContainer>
  )
}

// ── Main Page ────────────────────────────────────────────────────────────

function TicketDetailPage() {
  const { ticketId } = useParams({ from: "/_app/support/$ticketId/" as const })
  const { data: ticket, isLoading, isError } = useTicket(ticketId)

  if (isLoading) {
    return <TicketDetailSkeleton />
  }

  if (isError) {
    return <TicketNotFound message="We couldn't load this ticket. It may have been deleted or you may not have permission to view it. Try refreshing." />
  }

  if (!ticket) {
    return <TicketNotFound message="This ticket could not be found. It may have been deleted." />
  }

  const isClosed = ticket.status === "closed" || ticket.status === "resolved"

  return (
    <PageContainer className="flex-1 space-y-6">
      <PageHeader
        eyebrow="Helpdesk"
        title={ticket.subject}
        description={`${ticket.ticketNumber} · Created ${ticket.createdAt ? new Date(ticket.createdAt).toLocaleDateString(undefined, { weekday: "short", year: "numeric", month: "short", day: "numeric" }) : ""}`}
        breadcrumbs={
          <Breadcrumb>
            <BreadcrumbList>
              <BreadcrumbItem><BreadcrumbLink asChild><Link to="/home">Home</Link></BreadcrumbLink></BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem><BreadcrumbLink asChild><Link to="/support">Support</Link></BreadcrumbLink></BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem><BreadcrumbPage>{ticket.subject}</BreadcrumbPage></BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
        actions={
          <div className="flex items-center gap-3">
            <TicketStatusBadge status={ticket.status} />
            <TicketPriorityBadge priority={ticket.priority} />
            <Button variant="outline" size="sm" asChild>
              <Link to="/support/$ticketId/edit" params={{ ticketId }}>
                <Pencil className="mr-2 h-4 w-4" /> Edit
              </Link>
            </Button>
            <Button variant="outline" size="sm" asChild>
              <Link to="/support">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back to Tickets
              </Link>
            </Button>
          </div>
        }
      />

      {/* Ticket info card */}
      <PageSection delay={0.05}>
        <TicketDetailHeader ticket={ticket} />
      </PageSection>

      {/* Conversation */}
      <PageSection delay={0.1}>
        <Card className="border-border/60 bg-card/80">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-base">
              <MessageSquare className="h-4 w-4 text-muted-foreground" />
              Conversation
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-6">
              <TicketConversation ticketId={ticketId} />
              {!isClosed ? (
                <>
                  <Separator />
                  <TicketReplyForm ticketId={ticketId} />
                </>
              ) : (
                <div className="rounded-lg border border-dashed border-border/60 bg-muted/20 px-4 py-6 text-center">
                  <p className="text-sm font-medium text-muted-foreground">
                    This ticket is {ticket.status}.
                  </p>
                  <p className="mt-1 text-xs text-muted-foreground/70">
                    Reopen it to continue the conversation.
                  </p>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </PageSection>
    </PageContainer>
  )
}
