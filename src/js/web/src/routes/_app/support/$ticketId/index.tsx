import { createFileRoute, Link, useRouter } from "@tanstack/react-router"
import { useCallback, useState } from "react"
import {
  AlertCircle,
  AlertTriangle,
  ArrowLeft,
  Calendar,
  Check,
  ChevronDown,
  Clock,
  Copy,
  Hash,
  Loader2,
  Lock,
  Mail,
  MessageSquare,
  Pencil,
  Tag,
  Trash2,
  Unlock,
  User,
  Users,
} from "lucide-react"
import { TicketConversation } from "@/components/support/ticket-conversation"
import { TicketPriorityBadge } from "@/components/support/ticket-priority-badge"
import { TicketReplyForm } from "@/components/support/ticket-reply-form"
import { TicketStatusBadge } from "@/components/support/ticket-status-badge"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import {
  useCloseTicket,
  useDeleteTicket,
  useReopenTicket,
  useTicket,
  useUpdateTicket,
} from "@/lib/api/hooks/support"

export const Route = createFileRoute("/_app/support/$ticketId/")({
  component: TicketDetailPage,
})

// ── Constants ───────────────────────────────────────────────────────────

const categoryLabels: Record<string, string> = {
  billing: "Billing",
  technical: "Technical",
  account: "Account",
  device: "Device",
  voice: "Voice",
  fax: "Fax",
  general: "General",
}

const priorities = ["low", "medium", "high", "urgent"] as const

const statuses = [
  { value: "open", label: "Open" },
  { value: "in_progress", label: "In Progress" },
  { value: "waiting_on_customer", label: "Waiting on Customer" },
  { value: "waiting_on_support", label: "Waiting on Support" },
  { value: "resolved", label: "Resolved" },
  { value: "closed", label: "Closed" },
] as const

// ── Helpers ─────────────────────────────────────────────────────────────

function formatRelativeTime(dateStr: string | null | undefined): string {
  if (!dateStr) return "--"
  const date = new Date(dateStr)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffSec = Math.floor(diffMs / 1000)
  const diffMin = Math.floor(diffSec / 60)
  const diffHr = Math.floor(diffMin / 60)
  const diffDays = Math.floor(diffHr / 24)

  if (diffSec < 60) return "just now"
  if (diffMin < 60) return `${diffMin}m ago`
  if (diffHr < 24) return `${diffHr}h ago`
  if (diffDays < 7) return `${diffDays}d ago`
  return date.toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: date.getFullYear() !== now.getFullYear() ? "numeric" : undefined,
  })
}

function formatDateTime(value: string | null | undefined): string {
  if (!value) return "--"
  return new Date(value).toLocaleString()
}

// ── Copy Button ─────────────────────────────────────────────────────────

function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = useCallback(async () => {
    await navigator.clipboard.writeText(value)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }, [value])

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className="h-6 w-6 text-muted-foreground hover:text-foreground"
          onClick={handleCopy}
        >
          {copied ? (
            <Check className="h-3 w-3 text-emerald-500" />
          ) : (
            <Copy className="h-3 w-3" />
          )}
          <span className="sr-only">Copy {label}</span>
        </Button>
      </TooltipTrigger>
      <TooltipContent>{copied ? "Copied!" : `Copy ${label}`}</TooltipContent>
    </Tooltip>
  )
}

// ── Timestamp field ─────────────────────────────────────────────────────

function TimestampField({
  label,
  icon: Icon,
  value,
}: {
  label: string
  icon: React.ComponentType<{ className?: string }>
  value: string | null | undefined
}) {
  return (
    <div className="flex items-start gap-2.5">
      <div className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center">
        <Icon className="h-3.5 w-3.5 text-muted-foreground" />
      </div>
      <div className="min-w-0">
        <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
          {label}
        </p>
        {value ? (
          <Tooltip>
            <TooltipTrigger asChild>
              <p className="mt-0.5 cursor-default text-sm">
                {formatRelativeTime(value)}
              </p>
            </TooltipTrigger>
            <TooltipContent>{formatDateTime(value)}</TooltipContent>
          </Tooltip>
        ) : (
          <p className="mt-0.5 text-sm text-muted-foreground/70">--</p>
        )}
      </div>
    </div>
  )
}

// ── Loading Skeleton ────────────────────────────────────────────────────

function TicketDetailSkeleton() {
  return (
    <PageContainer className="flex-1 space-y-6">
      {/* Header skeleton */}
      <div className="mb-8 flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
        <div className="space-y-3">
          <Skeleton className="h-3 w-48" />
          <Skeleton className="h-9 w-80" />
          <Skeleton className="h-4 w-56" />
        </div>
        <div className="flex items-center gap-2">
          <Skeleton className="h-9 w-20" />
          <Skeleton className="h-9 w-24" />
          <Skeleton className="h-9 w-24" />
          <Skeleton className="h-9 w-20" />
        </div>
      </div>

      {/* Two column layout skeleton */}
      <div className="grid gap-6 lg:grid-cols-[1fr_320px]">
        {/* Main column */}
        <div className="space-y-4">
          <Card className="border-border/60">
            <CardContent className="space-y-4 py-6">
              {Array.from({ length: 3 }).map((_, i) => (
                <div key={i} className="space-y-3">
                  <div className="flex items-center gap-2">
                    <Skeleton className="h-8 w-8 rounded-full" />
                    <div className="space-y-1">
                      <Skeleton className="h-4 w-28" />
                      <Skeleton className="h-3 w-16" />
                    </div>
                  </div>
                  <Skeleton className="h-4 w-full" />
                  <Skeleton className="h-4 w-3/4" />
                </div>
              ))}
            </CardContent>
          </Card>
        </div>

        {/* Sidebar skeleton */}
        <div className="space-y-4">
          <Card className="border-border/60">
            <CardContent className="space-y-4 py-4">
              {Array.from({ length: 6 }).map((_, i) => (
                <div key={i} className="space-y-1.5">
                  <Skeleton className="h-3 w-16" />
                  <Skeleton className="h-5 w-24" />
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>
    </PageContainer>
  )
}

// ── Error State ─────────────────────────────────────────────────────────

function TicketNotFound({ message }: { message: string }) {
  return (
    <PageContainer className="flex-1">
      <div className="flex flex-col items-center justify-center py-24">
        <div className="flex h-16 w-16 items-center justify-center rounded-full bg-muted/50">
          <AlertCircle className="h-8 w-8 text-muted-foreground" />
        </div>
        <h2 className="mt-4 text-lg font-semibold">Unable to load ticket</h2>
        <p className="mt-1 max-w-sm text-center text-sm text-muted-foreground">
          {message}
        </p>
        <Button variant="outline" size="sm" asChild className="mt-6">
          <Link to="/support">
            <ArrowLeft className="mr-2 h-4 w-4" /> Back to Tickets
          </Link>
        </Button>
      </div>
    </PageContainer>
  )
}

// ── Main Page ───────────────────────────────────────────────────────────

function TicketDetailPage() {
  const { ticketId } = Route.useParams()
  const router = useRouter()
  const { data: ticket, isLoading, isError } = useTicket(ticketId)
  const closeTicket = useCloseTicket(ticketId)
  const reopenTicket = useReopenTicket(ticketId)
  const updateTicket = useUpdateTicket(ticketId)
  const deleteTicket = useDeleteTicket(ticketId)
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)

  if (isLoading) {
    return <TicketDetailSkeleton />
  }

  if (isError) {
    return (
      <TicketNotFound message="We couldn't load this ticket. It may have been deleted or you may not have permission to view it. Try refreshing." />
    )
  }

  if (!ticket) {
    return (
      <TicketNotFound message="This ticket could not be found. It may have been deleted." />
    )
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
              <BreadcrumbItem>
                <BreadcrumbLink asChild>
                  <Link to="/home">Home</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbLink asChild>
                  <Link to="/support">Support</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbPage>{ticket.subject}</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" asChild>
              <Link to="/support/$ticketId/edit" params={{ ticketId }}>
                <Pencil className="mr-2 h-4 w-4" /> Edit
              </Link>
            </Button>
            {isClosed ? (
              <Button
                size="sm"
                variant="outline"
                onClick={() => reopenTicket.mutate()}
                disabled={reopenTicket.isPending}
              >
                {reopenTicket.isPending ? (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                ) : (
                  <Unlock className="mr-2 h-4 w-4" />
                )}
                Reopen
              </Button>
            ) : (
              <Button
                size="sm"
                variant="outline"
                onClick={() => closeTicket.mutate()}
                disabled={closeTicket.isPending}
              >
                {closeTicket.isPending ? (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                ) : (
                  <Lock className="mr-2 h-4 w-4" />
                )}
                Close
              </Button>
            )}
            <Button
              size="sm"
              variant="outline"
              className="text-destructive hover:bg-destructive/10"
              onClick={() => setShowDeleteDialog(true)}
            >
              <Trash2 className="mr-2 h-4 w-4" /> Delete
            </Button>
            <Button variant="outline" size="sm" asChild>
              <Link to="/support">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back
              </Link>
            </Button>
          </div>
        }
      />

      {/* Two-column layout: conversation + sidebar */}
      <div className="grid gap-6 lg:grid-cols-[1fr_320px]">
        {/* Main column — Conversation */}
        <div className="min-w-0 space-y-6">
          <PageSection delay={0.05}>
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
                      <Button
                        size="sm"
                        variant="outline"
                        className="mt-3"
                        onClick={() => reopenTicket.mutate()}
                        disabled={reopenTicket.isPending}
                      >
                        {reopenTicket.isPending ? (
                          <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                        ) : (
                          <Unlock className="mr-2 h-4 w-4" />
                        )}
                        Reopen Ticket
                      </Button>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          </PageSection>
        </div>

        {/* Sidebar — Ticket metadata */}
        <div className="space-y-4">
          {/* Status & Priority */}
          <PageSection delay={0.1}>
            <Card className="border-border/60 bg-card/80">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium text-muted-foreground">
                  Details
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Status */}
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Status</span>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <button
                        type="button"
                        className="flex cursor-pointer items-center gap-1 rounded-md px-1 py-0.5 transition-colors hover:bg-muted/50"
                      >
                        <TicketStatusBadge status={ticket.status} />
                        <ChevronDown className="h-3 w-3 text-muted-foreground" />
                      </button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuLabel>Change Status</DropdownMenuLabel>
                      <DropdownMenuSeparator />
                      {statuses.map((s) => (
                        <DropdownMenuItem
                          key={s.value}
                          disabled={ticket.status === s.value}
                          onClick={() => {
                            if (s.value === "closed") {
                              closeTicket.mutate()
                            } else if (
                              (ticket.status === "closed" ||
                                ticket.status === "resolved") &&
                              s.value === "open"
                            ) {
                              reopenTicket.mutate()
                            } else {
                              updateTicket.mutate({ status: s.value })
                            }
                          }}
                        >
                          <TicketStatusBadge status={s.value} />
                        </DropdownMenuItem>
                      ))}
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>

                <Separator />

                {/* Priority */}
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Priority</span>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <button
                        type="button"
                        className="flex cursor-pointer items-center gap-1 rounded-md px-1 py-0.5 transition-colors hover:bg-muted/50"
                      >
                        <TicketPriorityBadge priority={ticket.priority} />
                        <ChevronDown className="h-3 w-3 text-muted-foreground" />
                      </button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuLabel>Change Priority</DropdownMenuLabel>
                      <DropdownMenuSeparator />
                      {priorities.map((p) => (
                        <DropdownMenuItem
                          key={p}
                          disabled={ticket.priority === p}
                          onClick={() => updateTicket.mutate({ priority: p })}
                        >
                          <TicketPriorityBadge priority={p} />
                        </DropdownMenuItem>
                      ))}
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>

                <Separator />

                {/* Category */}
                <div className="flex items-start gap-2.5">
                  <div className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center">
                    <Tag className="h-3.5 w-3.5 text-muted-foreground" />
                  </div>
                  <div className="min-w-0">
                    <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                      Category
                    </p>
                    <p className="mt-0.5 text-sm font-medium">
                      {ticket.category
                        ? (categoryLabels[ticket.category] ?? ticket.category)
                        : "None"}
                    </p>
                  </div>
                </div>

                <Separator />

                {/* Reporter */}
                <div className="flex items-start gap-2.5">
                  <div className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center">
                    <User className="h-3.5 w-3.5 text-muted-foreground" />
                  </div>
                  <div className="min-w-0">
                    <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                      Created By
                    </p>
                    <p className="mt-0.5 truncate text-sm font-medium">
                      {ticket.user?.name ?? ticket.user?.email ?? "Unknown"}
                    </p>
                    {ticket.user?.name && ticket.user?.email && (
                      <p className="truncate text-xs text-muted-foreground">
                        {ticket.user.email}
                      </p>
                    )}
                  </div>
                </div>

                {/* Assigned to */}
                <div className="flex items-start gap-2.5">
                  <div className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center">
                    <Users className="h-3.5 w-3.5 text-muted-foreground" />
                  </div>
                  <div className="min-w-0">
                    <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                      Assigned To
                    </p>
                    {ticket.assignedTo ? (
                      <>
                        <p className="mt-0.5 truncate text-sm font-medium">
                          {ticket.assignedTo.name ?? ticket.assignedTo.email}
                        </p>
                        {ticket.assignedTo.name && ticket.assignedTo.email && (
                          <p className="truncate text-xs text-muted-foreground">
                            {ticket.assignedTo.email}
                          </p>
                        )}
                      </>
                    ) : (
                      <p className="mt-0.5 text-sm text-muted-foreground/70">
                        Unassigned
                      </p>
                    )}
                  </div>
                </div>

                <Separator />

                {/* Messages count */}
                <div className="flex items-start gap-2.5">
                  <div className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center">
                    <Mail className="h-3.5 w-3.5 text-muted-foreground" />
                  </div>
                  <div className="min-w-0">
                    <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                      Messages
                    </p>
                    <p className="mt-0.5 text-sm font-medium">
                      {ticket.messageCount}
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </PageSection>

          {/* Timestamps & ID */}
          <PageSection delay={0.15}>
            <Card className="border-border/60 bg-card/80">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium text-muted-foreground">
                  Timeline
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <TimestampField
                  label="Created"
                  icon={Calendar}
                  value={ticket.createdAt}
                />
                {ticket.updatedAt && ticket.updatedAt !== ticket.createdAt && (
                  <TimestampField
                    label="Updated"
                    icon={Clock}
                    value={ticket.updatedAt}
                  />
                )}
                {ticket.closedAt && (
                  <TimestampField
                    label="Closed"
                    icon={Lock}
                    value={ticket.closedAt}
                  />
                )}
                {ticket.resolvedAt && (
                  <TimestampField
                    label="Resolved"
                    icon={Lock}
                    value={ticket.resolvedAt}
                  />
                )}

                <Separator />

                {/* Ticket ID with copy */}
                <div className="flex items-start gap-2.5">
                  <div className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center">
                    <Hash className="h-3.5 w-3.5 text-muted-foreground" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                      Ticket Number
                    </p>
                    <div className="mt-0.5 flex items-center gap-1">
                      <p className="font-mono text-xs">{ticket.ticketNumber}</p>
                      <CopyButton
                        value={ticket.ticketNumber}
                        label="ticket number"
                      />
                    </div>
                  </div>
                </div>

                {/* Ticket UUID with copy */}
                <div className="flex items-start gap-2.5">
                  <div className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center">
                    <Hash className="h-3.5 w-3.5 text-muted-foreground" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                      Ticket ID
                    </p>
                    <div className="mt-0.5 flex items-center gap-1">
                      <p className="truncate font-mono text-xs">{ticketId}</p>
                      <CopyButton value={ticketId} label="ticket ID" />
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </PageSection>

          {/* Danger zone */}
          <PageSection delay={0.2}>
            <Card className="border-destructive/30">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium text-destructive">
                  Danger Zone
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <p className="text-sm text-muted-foreground">
                    Permanently delete this ticket and all of its messages. This
                    action cannot be undone.
                  </p>
                  <Button
                    variant="destructive"
                    size="sm"
                    className="w-full"
                    onClick={() => setShowDeleteDialog(true)}
                  >
                    <Trash2 className="mr-2 h-4 w-4" /> Delete Ticket
                  </Button>
                </div>
              </CardContent>
            </Card>
          </PageSection>
        </div>
      </div>

      {/* Delete confirmation dialog */}
      <Dialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-destructive" />
              Delete ticket?
            </DialogTitle>
            <DialogDescription>
              This will permanently delete ticket{" "}
              <span className="font-medium text-foreground">
                {ticket.ticketNumber}
              </span>{" "}
              and all of its messages. This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setShowDeleteDialog(false)}
              disabled={deleteTicket.isPending}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={deleteTicket.isPending}
              onClick={() => {
                deleteTicket.mutate(undefined, {
                  onSuccess: () => {
                    setShowDeleteDialog(false)
                    router.navigate({ to: "/support" })
                  },
                })
              }}
            >
              {deleteTicket.isPending && (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              )}
              Delete Ticket
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </PageContainer>
  )
}
