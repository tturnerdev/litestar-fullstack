import { createFileRoute, Link, useRouter } from "@tanstack/react-router"
import { useCallback, useEffect, useMemo, useState } from "react"
import {
  AlertCircle,
  AlertTriangle,
  ArrowLeft,
  Calendar,
  Check,
  ChevronDown,
  ChevronRight,
  Clock,
  Copy,
  Hash,
  History,
  Loader2,
  Lock,
  Mail,
  MessageSquare,
  MoreHorizontal,
  Pencil,
  Plus,
  Tag,
  Trash2,
  Unlock,
  User,
  Users,
  X,
} from "lucide-react"
import { Badge } from "@/components/ui/badge"
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { EntityActivityPanel } from "@/components/shared/entity-activity-panel"
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
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Button, buttonVariants } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible"
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
import { CopyButton } from "@/components/ui/copy-button"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import {
  useCloseTicket,
  useDeleteTicket,
  useReopenTicket,
  useTicket,
  useUpdateTicket,
} from "@/lib/api/hooks/support"
import { useTags, type Tag as TagType } from "@/lib/api/hooks/tags"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { toast } from "sonner"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"

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
                {formatRelativeTimeShort(value)}
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

// ── Tag Manager ────────────────────────────────────────────────────────

interface TicketTag {
  id: string
  name: string
  slug: string
}

function TicketTagManager({
  ticketId,
  initialTags,
}: {
  ticketId: string
  initialTags: TicketTag[]
}) {
  const [tagPopoverOpen, setTagPopoverOpen] = useState(false)
  const [tagSearch, setTagSearch] = useState("")
  const [assignedTags, setAssignedTags] = useState<TicketTag[]>(initialTags)
  const updateTicket = useUpdateTicket(ticketId)

  // Sync local state when the ticket data refreshes from the server
  useEffect(() => {
    setAssignedTags(initialTags)
  }, [initialTags])

  const { data: tagsData } = useTags({ page: 1, pageSize: 100, search: tagSearch })
  const availableTags: TagType[] = tagsData?.items ?? []

  const assignedIds = useMemo(
    () => new Set(assignedTags.map((t) => t.id)),
    [assignedTags],
  )

  const handleToggleTag = useCallback(
    (tag: TagType) => {
      const isAssigned = assignedIds.has(tag.id)
      let nextTags: TicketTag[]

      if (isAssigned) {
        nextTags = assignedTags.filter((t) => t.id !== tag.id)
      } else {
        nextTags = [...assignedTags, { id: tag.id, name: tag.name, slug: tag.slug }]
      }

      // Optimistic update
      setAssignedTags(nextTags)

      updateTicket.mutate(
        { tagIds: nextTags.map((t) => t.id) },
        {
          onError: () => {
            // Revert on failure
            setAssignedTags(assignedTags)
          },
        },
      )
    },
    [assignedIds, assignedTags, updateTicket],
  )

  const handleRemoveTag = useCallback(
    (tagId: string) => {
      const nextTags = assignedTags.filter((t) => t.id !== tagId)

      // Optimistic update
      setAssignedTags(nextTags)

      updateTicket.mutate(
        { tagIds: nextTags.map((t) => t.id) },
        {
          onError: () => {
            // Revert on failure
            setAssignedTags(assignedTags)
          },
        },
      )
    },
    [assignedTags, updateTicket],
  )

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="flex h-5 w-5 shrink-0 items-center justify-center">
            <Tag className="h-3.5 w-3.5 text-muted-foreground" />
          </div>
          <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            Tags
          </p>
        </div>
        <Popover open={tagPopoverOpen} onOpenChange={setTagPopoverOpen}>
          <PopoverTrigger asChild>
            <Button
              variant="ghost"
              size="sm"
              className="h-6 w-6 p-0"
              aria-label="Add tag"
            >
              <Plus className="h-3.5 w-3.5" />
            </Button>
          </PopoverTrigger>
          <PopoverContent className="w-64 p-0" align="end">
            <Command shouldFilter={false}>
              <CommandInput
                placeholder="Search tags..."
                value={tagSearch}
                onValueChange={setTagSearch}
              />
              <CommandList>
                <CommandEmpty>No tags found.</CommandEmpty>
                <CommandGroup>
                  {availableTags.map((tag) => {
                    const isSelected = assignedIds.has(tag.id)
                    return (
                      <CommandItem
                        key={tag.id}
                        value={tag.id}
                        onSelect={() => handleToggleTag(tag)}
                      >
                        <div
                          className={`mr-2 flex h-4 w-4 shrink-0 items-center justify-center rounded-sm border ${
                            isSelected
                              ? "border-primary bg-primary text-primary-foreground"
                              : "border-muted-foreground/30"
                          }`}
                        >
                          {isSelected && <Check className="h-3 w-3" />}
                        </div>
                        <span className="truncate text-sm">{tag.name}</span>
                      </CommandItem>
                    )
                  })}
                </CommandGroup>
              </CommandList>
            </Command>
          </PopoverContent>
        </Popover>
      </div>

      {assignedTags.length > 0 ? (
        <div className="flex flex-wrap gap-1.5 pl-7">
          {assignedTags.map((tag) => (
            <Badge
              key={tag.id}
              variant="secondary"
              className="gap-1 px-2 py-0.5 text-[10px]"
            >
              {tag.name}
              <button
                type="button"
                className="ml-0.5 rounded-full p-0 hover:bg-muted-foreground/20"
                onClick={() => handleRemoveTag(tag.id)}
                aria-label={`Remove tag ${tag.name}`}
              >
                <X className="h-3 w-3" />
              </button>
            </Badge>
          ))}
        </div>
      ) : (
        <p className="pl-7 text-sm text-muted-foreground/70">No tags</p>
      )}
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
  useDocumentTitle(ticket?.subject ?? "Ticket Details")
  const closeTicket = useCloseTicket(ticketId)
  const reopenTicket = useReopenTicket(ticketId)
  const updateTicket = useUpdateTicket(ticketId)
  const deleteTicket = useDeleteTicket(ticketId)
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)
  const [activityOpen, setActivityOpen] = useState(false)

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
        description={`${ticket.ticketNumber} · Created ${formatDateTime(ticket.createdAt, "")}`}
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
            <Button variant="outline" size="sm" asChild>
              <Link to="/support">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back
              </Link>
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="icon" className="h-9 w-9">
                  <MoreHorizontal className="h-4 w-4" />
                  <span className="sr-only">More actions</span>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem
                  onClick={() => {
                    navigator.clipboard.writeText(ticket.ticketNumber)
                    toast.success("Copied ticket number")
                  }}
                >
                  <Copy className="mr-2 h-4 w-4" />
                  Copy Ticket ID
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                {isClosed ? (
                  <DropdownMenuItem
                    onClick={() => reopenTicket.mutate()}
                    disabled={reopenTicket.isPending}
                  >
                    {reopenTicket.isPending ? (
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    ) : (
                      <Unlock className="mr-2 h-4 w-4" />
                    )}
                    Reopen Ticket
                  </DropdownMenuItem>
                ) : (
                  <DropdownMenuItem
                    onClick={() => closeTicket.mutate()}
                    disabled={closeTicket.isPending}
                  >
                    {closeTicket.isPending ? (
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    ) : (
                      <Lock className="mr-2 h-4 w-4" />
                    )}
                    Close Ticket
                  </DropdownMenuItem>
                )}
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  className="text-destructive focus:text-destructive"
                  onClick={() => setShowDeleteDialog(true)}
                >
                  <Trash2 className="mr-2 h-4 w-4" />
                  Delete Ticket
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
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
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <p className="mt-0.5 truncate text-sm font-medium" title={ticket.user?.name ?? ticket.user?.email ?? "Unknown"}>
                          {ticket.user?.name ?? ticket.user?.email ?? "Unknown"}
                        </p>
                      </TooltipTrigger>
                      <TooltipContent>{ticket.user?.name ?? ticket.user?.email ?? "Unknown"}</TooltipContent>
                    </Tooltip>
                    {ticket.user?.name && ticket.user?.email && (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <p className="truncate text-xs text-muted-foreground" title={ticket.user.email}>
                            {ticket.user.email}
                          </p>
                        </TooltipTrigger>
                        <TooltipContent>{ticket.user.email}</TooltipContent>
                      </Tooltip>
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
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <p className="mt-0.5 truncate text-sm font-medium" title={ticket.assignedTo.name ?? ticket.assignedTo.email}>
                              {ticket.assignedTo.name ?? ticket.assignedTo.email}
                            </p>
                          </TooltipTrigger>
                          <TooltipContent>{ticket.assignedTo.name ?? ticket.assignedTo.email}</TooltipContent>
                        </Tooltip>
                        {ticket.assignedTo.name && ticket.assignedTo.email && (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <p className="truncate text-xs text-muted-foreground" title={ticket.assignedTo.email}>
                                {ticket.assignedTo.email}
                              </p>
                            </TooltipTrigger>
                            <TooltipContent>{ticket.assignedTo.email}</TooltipContent>
                          </Tooltip>
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

                <Separator />

                {/* Tags */}
                <TicketTagManager
                  ticketId={ticketId}
                  initialTags={[]}
                />
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

          {/* Activity Log — collapsed by default, lazy-loads when expanded */}
          <PageSection delay={0.2}>
            <Collapsible open={activityOpen} onOpenChange={setActivityOpen}>
              <Card className="border-border/60 bg-card/80">
                <CollapsibleTrigger asChild>
                  <CardHeader className="cursor-pointer select-none pb-3 transition-colors hover:bg-muted/30">
                    <CardTitle className="flex items-center gap-2 text-sm font-medium text-muted-foreground">
                      <History className="h-4 w-4" />
                      Activity Log
                      <ChevronRight
                        className={`ml-auto h-4 w-4 transition-transform duration-200 ${activityOpen ? "rotate-90" : ""}`}
                      />
                    </CardTitle>
                  </CardHeader>
                </CollapsibleTrigger>
                <CollapsibleContent>
                  <CardContent className="pt-0">
                    <EntityActivityPanel
                      targetType="ticket"
                      targetId={ticketId}
                      enabled={activityOpen}
                    />
                  </CardContent>
                </CollapsibleContent>
              </Card>
            </Collapsible>
          </PageSection>

          {/* Danger zone */}
          <PageSection delay={0.25}>
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
      <AlertDialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-destructive" />
              Delete ticket?
            </AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete ticket{" "}
              <span className="font-medium text-foreground">
                {ticket.ticketNumber}
              </span>{" "}
              and all of its messages. This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel
              onClick={() => setShowDeleteDialog(false)}
              disabled={deleteTicket.isPending}
            >
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              className={buttonVariants({ variant: "destructive" })}
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
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </PageContainer>
  )
}
