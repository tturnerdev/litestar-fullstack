import { createFileRoute, Link, useBlocker, useRouter } from "@tanstack/react-router"
import {
  AlertCircle,
  AlertTriangle,
  ArrowLeft,
  Calendar,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  CircleDot,
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
  Timer,
  Trash2,
  Unlock,
  User,
  UserPlus,
  Users,
  X,
} from "lucide-react"
import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { toast } from "sonner"
import { EntityActivityPanel } from "@/components/shared/entity-activity-panel"
import { TicketConversation } from "@/components/support/ticket-conversation"
import { TicketPriorityBadge } from "@/components/support/ticket-priority-badge"
import { TicketReplyForm } from "@/components/support/ticket-reply-form"
import { TicketStatusBadge } from "@/components/support/ticket-status-badge"
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
import { Badge } from "@/components/ui/badge"
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb"
import { Button, buttonVariants } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from "@/components/ui/command"
import { CopyButton } from "@/components/ui/copy-button"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { useAdminUsers } from "@/lib/api/hooks/admin"
import type { TicketMessage as TicketMessageType, Ticket as TicketType } from "@/lib/api/hooks/support"
import { useCloseTicket, useDeleteTicket, useReopenTicket, useTicket, useTicketMessages, useUpdateTicket } from "@/lib/api/hooks/support"
import { type Tag as TagType, useTags } from "@/lib/api/hooks/tags"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"

const UNASSIGNED_VALUE = "__unassigned__"

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

function TimestampField({ label, icon: Icon, value }: { label: string; icon: React.ComponentType<{ className?: string }>; value: string | null | undefined }) {
  return (
    <div className="flex items-start gap-2.5">
      <div className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center">
        <Icon className="h-3.5 w-3.5 text-muted-foreground" />
      </div>
      <div className="min-w-0">
        <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{label}</p>
        {value ? (
          <Tooltip>
            <TooltipTrigger asChild>
              <p className="mt-0.5 cursor-default text-sm">{formatRelativeTimeShort(value)}</p>
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

function TicketTagManager({ ticketId, initialTags }: { ticketId: string; initialTags: TicketTag[] }) {
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

  const assignedIds = useMemo(() => new Set(assignedTags.map((t) => t.id)), [assignedTags])

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
          <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Tags</p>
        </div>
        <Popover open={tagPopoverOpen} onOpenChange={setTagPopoverOpen}>
          <PopoverTrigger asChild>
            <Button variant="ghost" size="sm" className="h-6 w-6 p-0" aria-label="Add tag">
              <Plus className="h-3.5 w-3.5" />
            </Button>
          </PopoverTrigger>
          <PopoverContent className="w-64 p-0" align="end">
            <Command shouldFilter={false}>
              <CommandInput placeholder="Search tags..." value={tagSearch} onValueChange={setTagSearch} />
              <CommandList>
                <CommandEmpty>No tags found.</CommandEmpty>
                <CommandGroup>
                  {availableTags.map((tag) => {
                    const isSelected = assignedIds.has(tag.id)
                    return (
                      <CommandItem key={tag.id} value={tag.id} onSelect={() => handleToggleTag(tag)}>
                        <div
                          className={`mr-2 flex h-4 w-4 shrink-0 items-center justify-center rounded-sm border ${
                            isSelected ? "border-primary bg-primary text-primary-foreground" : "border-muted-foreground/30"
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
            <Badge key={tag.id} variant="secondary" className="gap-1 px-2 py-0.5 text-[10px]">
              {tag.name}
              <button type="button" className="ml-0.5 rounded-full p-0 hover:bg-muted-foreground/20" onClick={() => handleRemoveTag(tag.id)} aria-label={`Remove tag ${tag.name}`}>
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

// ── SLA Indicators ─────────────────────────────────────────────────────

function formatDuration(ms: number): string {
  const seconds = Math.floor(ms / 1000)
  const minutes = Math.floor(seconds / 60)
  const hours = Math.floor(minutes / 60)
  const days = Math.floor(hours / 24)

  if (days > 0) {
    const remHours = hours % 24
    return remHours > 0 ? `${days}d ${remHours}h` : `${days}d`
  }
  if (hours > 0) {
    const remMinutes = minutes % 60
    return remMinutes > 0 ? `${hours}h ${remMinutes}m` : `${hours}h`
  }
  if (minutes > 0) return `${minutes}m`
  return "< 1m"
}

type SlaColor = "green" | "yellow" | "red"

function getSlaColorClasses(color: SlaColor): string {
  switch (color) {
    case "green":
      return "text-green-600 dark:text-green-400"
    case "yellow":
      return "text-yellow-600 dark:text-yellow-400"
    case "red":
      return "text-red-600 dark:text-red-400"
  }
}

function getSlaIndicatorClasses(color: SlaColor): string {
  switch (color) {
    case "green":
      return "bg-green-500/15 text-green-600 dark:text-green-400"
    case "yellow":
      return "bg-yellow-500/15 text-yellow-600 dark:text-yellow-400"
    case "red":
      return "bg-red-500/15 text-red-600 dark:text-red-400"
  }
}

function getFirstResponseColor(ms: number): SlaColor {
  const hours = ms / (1000 * 60 * 60)
  if (hours < 1) return "green"
  if (hours < 4) return "yellow"
  return "red"
}

function getResolutionColor(ms: number): SlaColor {
  const hours = ms / (1000 * 60 * 60)
  if (hours < 24) return "green"
  if (hours < 72) return "yellow"
  return "red"
}

function getAgeColor(ms: number, isResolved: boolean): SlaColor {
  if (isResolved) return "green"
  const hours = ms / (1000 * 60 * 60)
  if (hours < 24) return "green"
  if (hours < 72) return "yellow"
  return "red"
}

function SlaIndicatorRow({ label, value, color }: { label: string; value: string; color: SlaColor }) {
  return (
    <div className="flex items-center justify-between gap-2">
      <span className="text-xs text-muted-foreground">{label}</span>
      <span className={`rounded-md px-1.5 py-0.5 text-xs font-semibold tabular-nums ${getSlaIndicatorClasses(color)}`}>{value}</span>
    </div>
  )
}

function SlaIndicators({ ticket, messages }: { ticket: TicketType; messages: TicketMessageType[] }) {
  const { age, ageColor, firstResponse, firstResponseColor, resolution, resolutionColor } = useMemo(() => {
    if (!ticket.createdAt) {
      return {
        age: null,
        ageColor: "green" as SlaColor,
        firstResponse: null,
        firstResponseColor: "green" as SlaColor,
        resolution: null,
        resolutionColor: "green" as SlaColor,
      }
    }

    const createdMs = new Date(ticket.createdAt).getTime()
    const nowMs = Date.now()
    const isResolved = ticket.status === "resolved" || ticket.status === "closed"

    // Age: time since creation (or until resolution/close)
    const endMs = ticket.resolvedAt ? new Date(ticket.resolvedAt).getTime() : ticket.closedAt ? new Date(ticket.closedAt).getTime() : nowMs
    const ageMs = endMs - createdMs
    const computedAge = ageMs > 0 ? ageMs : 0
    const computedAgeColor = getAgeColor(computedAge, isResolved)

    // First response: first non-system message after ticket creation
    let computedFirstResponse: number | null = null
    let computedFirstResponseColor: SlaColor = "green"
    const nonSystemMessages = messages.filter((m) => !m.isSystemMessage && m.createdAt)
    if (nonSystemMessages.length > 1) {
      // The first message is the ticket body itself; the second is the first response
      const firstReply = nonSystemMessages.slice(1).sort((a, b) => new Date(a.createdAt as string).getTime() - new Date(b.createdAt as string).getTime())[0]
      if (firstReply?.createdAt) {
        const replyMs = new Date(firstReply.createdAt).getTime() - createdMs
        if (replyMs > 0) {
          computedFirstResponse = replyMs
          computedFirstResponseColor = getFirstResponseColor(replyMs)
        }
      }
    }

    // Resolution time
    let computedResolution: number | null = null
    let computedResolutionColor: SlaColor = "green"
    if (ticket.resolvedAt) {
      const resMs = new Date(ticket.resolvedAt).getTime() - createdMs
      if (resMs > 0) {
        computedResolution = resMs
        computedResolutionColor = getResolutionColor(resMs)
      }
    }

    return {
      age: computedAge,
      ageColor: computedAgeColor,
      firstResponse: computedFirstResponse,
      firstResponseColor: computedFirstResponseColor,
      resolution: computedResolution,
      resolutionColor: computedResolutionColor,
    }
  }, [ticket, messages])

  if (age === null) return null

  const isResolved = ticket.status === "resolved" || ticket.status === "closed"

  return (
    <Card className="border-border/60 bg-card/80">
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm font-medium text-muted-foreground">
          <Timer className={`h-4 w-4 ${getSlaColorClasses(ageColor)}`} />
          SLA Metrics
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        <SlaIndicatorRow label={isResolved ? "Total age" : "Time open"} value={formatDuration(age)} color={ageColor} />
        <SlaIndicatorRow
          label="First response"
          value={firstResponse !== null ? formatDuration(firstResponse) : "--"}
          color={firstResponse !== null ? firstResponseColor : "green"}
        />
        <SlaIndicatorRow label="Resolution time" value={resolution !== null ? formatDuration(resolution) : "--"} color={resolution !== null ? resolutionColor : "green"} />
      </CardContent>
    </Card>
  )
}

// ── Lifecycle Timeline ──────────────────────────────────────────────────

interface TimelineEvent {
  id: string
  type: "created" | "message" | "status" | "assigned" | "resolved" | "closed" | "updated"
  timestamp: string
  label: string
  description?: string
  icon: React.ComponentType<{ className?: string }>
  dotColor: string
}

const statusLabels: Record<string, string> = {
  open: "Open",
  in_progress: "In Progress",
  waiting_on_customer: "Waiting on Customer",
  waiting_on_support: "Waiting on Support",
  resolved: "Resolved",
  closed: "Closed",
}

function buildTimelineEvents(ticket: TicketType, messages: TicketMessageType[]): TimelineEvent[] {
  const events: TimelineEvent[] = []

  // 1. Created
  if (ticket.createdAt) {
    const creatorName = ticket.user?.name ?? ticket.user?.email ?? "Unknown"
    events.push({
      id: "created",
      type: "created",
      timestamp: ticket.createdAt,
      label: "Ticket created",
      description: `by ${creatorName}`,
      icon: Plus,
      dotColor: "bg-green-500",
    })
  }

  // 2. Assignment (current)
  if (ticket.assignedTo) {
    const assigneeName = ticket.assignedTo.name ?? ticket.assignedTo.email
    // Place assignment slightly after creation
    const ts = ticket.createdAt ? new Date(new Date(ticket.createdAt).getTime() + 1).toISOString() : (ticket.updatedAt ?? ticket.createdAt ?? "")
    events.push({
      id: "assigned",
      type: "assigned",
      timestamp: ts,
      label: "Assigned",
      description: `to ${assigneeName}`,
      icon: UserPlus,
      dotColor: "bg-blue-500",
    })
  }

  // 3. Messages (non-system, with timestamp)
  for (const msg of messages) {
    if (msg.isSystemMessage || !msg.createdAt) continue
    const authorName = msg.author?.name ?? msg.author?.email ?? "Unknown"
    const isNote = msg.isInternalNote
    events.push({
      id: `msg-${msg.id}`,
      type: "message",
      timestamp: msg.createdAt,
      label: isNote ? "Internal note" : "Reply",
      description: `by ${authorName}`,
      icon: MessageSquare,
      dotColor: isNote ? "bg-amber-500" : "bg-indigo-500",
    })
  }

  // 4. Current status (if not open and not covered by resolved/closed)
  if (ticket.status !== "open" && ticket.status !== "resolved" && ticket.status !== "closed" && ticket.updatedAt) {
    events.push({
      id: "status-current",
      type: "status",
      timestamp: ticket.updatedAt,
      label: `Status changed`,
      description: `to ${statusLabels[ticket.status] ?? ticket.status}`,
      icon: CircleDot,
      dotColor: "bg-blue-500",
    })
  }

  // 5. Resolved
  if (ticket.resolvedAt) {
    events.push({
      id: "resolved",
      type: "resolved",
      timestamp: ticket.resolvedAt,
      label: "Ticket resolved",
      icon: CheckCircle2,
      dotColor: "bg-green-500",
    })
  }

  // 6. Closed
  if (ticket.closedAt) {
    events.push({
      id: "closed",
      type: "closed",
      timestamp: ticket.closedAt,
      label: "Ticket closed",
      icon: Lock,
      dotColor: "bg-zinc-500",
    })
  }

  // 7. Last updated (only if distinct from created, resolved, closed)
  if (ticket.updatedAt && ticket.updatedAt !== ticket.createdAt && ticket.updatedAt !== ticket.resolvedAt && ticket.updatedAt !== ticket.closedAt) {
    // Check if we already have a status event at this timestamp
    const hasStatusAtUpdated = events.some((e) => e.type === "status" && e.timestamp === ticket.updatedAt)
    if (!hasStatusAtUpdated) {
      events.push({
        id: "updated",
        type: "updated",
        timestamp: ticket.updatedAt,
        label: "Last updated",
        icon: Clock,
        dotColor: "bg-zinc-400",
      })
    }
  }

  // Sort chronologically
  events.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())

  return events
}

function TicketLifecycleTimeline({ ticket, messages }: { ticket: TicketType; messages: TicketMessageType[] }) {
  const events = useMemo(() => buildTimelineEvents(ticket, messages), [ticket, messages])

  if (events.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-6 text-center">
        <Clock className="mb-2 h-6 w-6 text-muted-foreground/40" />
        <p className="text-sm text-muted-foreground">No timeline events</p>
      </div>
    )
  }

  return (
    <div className="relative space-y-0">
      {events.map((event, index) => {
        const Icon = event.icon
        const isLast = index === events.length - 1

        return (
          <div key={event.id} className="relative flex gap-3 pb-5 last:pb-0">
            {/* Vertical connector line */}
            {!isLast && <div className="absolute left-3 top-7 h-[calc(100%-12px)] w-px bg-border" />}

            {/* Dot with icon */}
            <div className={`mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-white ${event.dotColor}`}>
              <Icon className="h-3 w-3" />
            </div>

            {/* Content */}
            <div className="min-w-0 flex-1 space-y-0.5">
              <p className="text-sm font-medium leading-snug">{event.label}</p>
              {event.description && <p className="text-xs text-muted-foreground">{event.description}</p>}
              <Tooltip>
                <TooltipTrigger asChild>
                  <p className="cursor-default text-xs text-muted-foreground/70">{formatRelativeTimeShort(event.timestamp)}</p>
                </TooltipTrigger>
                <TooltipContent>{formatDateTime(event.timestamp)}</TooltipContent>
              </Tooltip>
            </div>
          </div>
        )
      })}
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
                // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
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
                // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
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
  const { data: messagesData } = useTicketMessages(ticketId)
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)
  const [activityOpen, setActivityOpen] = useState(false)

  // ── Inline editing state ───────────────────────────────────────────────
  const { data: usersData } = useAdminUsers({ pageSize: 100 })
  const [editing, setEditing] = useState(false)
  const [editSubject, setEditSubject] = useState("")
  const [editCategory, setEditCategory] = useState("")
  const [editAssignedToId, setEditAssignedToId] = useState("")
  const justSavedRef = useRef(false)

  const editDirty = useMemo(() => {
    if (!ticket || !editing) return false
    return editSubject !== ticket.subject || editCategory !== (ticket.category ?? "") || editAssignedToId !== (ticket.assignedTo?.id ?? UNASSIGNED_VALUE)
  }, [editing, editSubject, editCategory, editAssignedToId, ticket])

  useBlocker({
    shouldBlockFn: () => editDirty && !justSavedRef.current,
    withResolver: true,
  })

  const handleStartEditing = useCallback(() => {
    if (!ticket) return
    setEditSubject(ticket.subject)
    setEditCategory(ticket.category ?? "")
    setEditAssignedToId(ticket.assignedTo?.id ?? UNASSIGNED_VALUE)
    setEditing(true)
  }, [ticket])

  const handleCancelEditing = useCallback(() => {
    setEditing(false)
  }, [])

  const handleSaveEditing = useCallback(() => {
    if (!ticket) return
    const payload: Record<string, unknown> = {}
    if (editSubject !== ticket.subject) payload.subject = editSubject
    const newCategory = editCategory || null
    if (newCategory !== (ticket.category ?? null)) payload.category = newCategory
    const newAssignedToId = editAssignedToId === UNASSIGNED_VALUE ? null : editAssignedToId
    const currentAssignedToId = ticket.assignedTo?.id ?? null
    if (newAssignedToId !== currentAssignedToId) payload.assignedToId = newAssignedToId

    if (Object.keys(payload).length === 0) {
      setEditing(false)
      return
    }

    justSavedRef.current = true
    updateTicket.mutate(payload, {
      onSuccess: () => {
        setEditing(false)
        justSavedRef.current = false
      },
      onError: () => {
        justSavedRef.current = false
      },
    })
  }, [ticket, editSubject, editCategory, editAssignedToId, updateTicket])

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
        title={
          editing ? <Input value={editSubject} onChange={(e) => setEditSubject(e.target.value)} className="h-9 text-lg font-semibold" maxLength={200} autoFocus /> : ticket.subject
        }
        description={
          <span className="inline-flex items-center gap-1">
            <span className="group/tktcopy inline-flex items-center gap-0.5">
              {ticket.ticketNumber}
              <span className="opacity-0 transition-opacity group-hover/tktcopy:opacity-100">
                <CopyButton value={ticket.ticketNumber} label="ticket number" />
              </span>
            </span>
            <span>· Created {formatDateTime(ticket.createdAt, "")}</span>
          </span>
        }
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
            {editing ? (
              <>
                <Button variant="ghost" size="sm" onClick={handleCancelEditing} disabled={updateTicket.isPending}>
                  <X className="mr-2 h-4 w-4" /> Cancel
                </Button>
                <Button size="sm" onClick={handleSaveEditing} disabled={!editDirty || updateTicket.isPending}>
                  {updateTicket.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Check className="mr-2 h-4 w-4" />}
                  Save
                </Button>
              </>
            ) : (
              <Button variant="outline" size="sm" onClick={handleStartEditing}>
                <Pencil className="mr-2 h-4 w-4" /> Edit
              </Button>
            )}
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
                  <DropdownMenuItem onClick={() => reopenTicket.mutate()} disabled={reopenTicket.isPending}>
                    {reopenTicket.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Unlock className="mr-2 h-4 w-4" />}
                    Reopen Ticket
                  </DropdownMenuItem>
                ) : (
                  <DropdownMenuItem onClick={() => closeTicket.mutate()} disabled={closeTicket.isPending}>
                    {closeTicket.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Lock className="mr-2 h-4 w-4" />}
                    Close Ticket
                  </DropdownMenuItem>
                )}
                <DropdownMenuSeparator />
                <DropdownMenuItem className="text-destructive focus:text-destructive" onClick={() => setShowDeleteDialog(true)}>
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
            <SectionErrorBoundary name="Conversation">
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
                        <p className="text-sm font-medium text-muted-foreground">This ticket is {ticket.status}.</p>
                        <p className="mt-1 text-xs text-muted-foreground/70">Reopen it to continue the conversation.</p>
                        <Button size="sm" variant="outline" className="mt-3" onClick={() => reopenTicket.mutate()} disabled={reopenTicket.isPending}>
                          {reopenTicket.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Unlock className="mr-2 h-4 w-4" />}
                          Reopen Ticket
                        </Button>
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            </SectionErrorBoundary>
          </PageSection>
        </div>

        {/* Sidebar — Ticket metadata */}
        <div className="space-y-4">
          {/* Status & Priority */}
          <PageSection delay={0.1}>
            <SectionErrorBoundary name="Ticket Details">
              <Card className="border-border/60 bg-card/80">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-medium text-muted-foreground">Details</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  {/* Status */}
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">Status</span>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <button type="button" className="flex cursor-pointer items-center gap-1 rounded-md px-1 py-0.5 transition-colors hover:bg-muted/50">
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
                              } else if ((ticket.status === "closed" || ticket.status === "resolved") && s.value === "open") {
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
                        <button type="button" className="flex cursor-pointer items-center gap-1 rounded-md px-1 py-0.5 transition-colors hover:bg-muted/50">
                          <TicketPriorityBadge priority={ticket.priority} />
                          <ChevronDown className="h-3 w-3 text-muted-foreground" />
                        </button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuLabel>Change Priority</DropdownMenuLabel>
                        <DropdownMenuSeparator />
                        {priorities.map((p) => (
                          <DropdownMenuItem key={p} disabled={ticket.priority === p} onClick={() => updateTicket.mutate({ priority: p })}>
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
                    <div className="min-w-0 flex-1">
                      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Category</p>
                      {editing ? (
                        <Select value={editCategory} onValueChange={setEditCategory}>
                          <SelectTrigger className="mt-1 h-8 text-sm">
                            <SelectValue placeholder="Select category" />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="">None</SelectItem>
                            {Object.entries(categoryLabels).map(([value, label]) => (
                              <SelectItem key={value} value={value}>
                                {label}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      ) : (
                        <p className="mt-0.5 text-sm font-medium">{ticket.category ? (categoryLabels[ticket.category] ?? ticket.category) : "None"}</p>
                      )}
                    </div>
                  </div>

                  <Separator />

                  {/* Reporter */}
                  <div className="flex items-start gap-2.5">
                    <div className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center">
                      <User className="h-3.5 w-3.5 text-muted-foreground" />
                    </div>
                    <div className="min-w-0">
                      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Created By</p>
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
                    <div className="min-w-0 flex-1">
                      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Assigned To</p>
                      {editing ? (
                        <Select value={editAssignedToId} onValueChange={setEditAssignedToId}>
                          <SelectTrigger className="mt-1 h-8 text-sm">
                            <SelectValue placeholder="Select assignee" />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value={UNASSIGNED_VALUE}>Unassigned</SelectItem>
                            {(usersData?.items ?? []).map((u) => (
                              <SelectItem key={u.id} value={u.id}>
                                {u.name || u.email}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      ) : ticket.assignedTo ? (
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
                        <p className="mt-0.5 text-sm text-muted-foreground/70">Unassigned</p>
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
                      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Messages</p>
                      <p className="mt-0.5 text-sm font-medium">{ticket.messageCount}</p>
                    </div>
                  </div>

                  <Separator />

                  {/* Tags */}
                  <TicketTagManager ticketId={ticketId} initialTags={[]} />
                </CardContent>
              </Card>
            </SectionErrorBoundary>
          </PageSection>

          {/* SLA Metrics */}
          <PageSection delay={0.12}>
            <SectionErrorBoundary name="SLA Metrics">
              <SlaIndicators ticket={ticket} messages={messagesData ?? []} />
            </SectionErrorBoundary>
          </PageSection>

          {/* Timestamps & ID */}
          <PageSection delay={0.15}>
            <SectionErrorBoundary name="Ticket Timeline">
              <Card className="border-border/60 bg-card/80">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-medium text-muted-foreground">Timeline</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <TimestampField label="Created" icon={Calendar} value={ticket.createdAt} />
                  {ticket.updatedAt && ticket.updatedAt !== ticket.createdAt && <TimestampField label="Updated" icon={Clock} value={ticket.updatedAt} />}
                  {ticket.closedAt && <TimestampField label="Closed" icon={Lock} value={ticket.closedAt} />}
                  {ticket.resolvedAt && <TimestampField label="Resolved" icon={Lock} value={ticket.resolvedAt} />}

                  <Separator />

                  {/* Ticket ID with copy */}
                  <div className="flex items-start gap-2.5">
                    <div className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center">
                      <Hash className="h-3.5 w-3.5 text-muted-foreground" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Ticket Number</p>
                      <div className="mt-0.5 flex items-center gap-1">
                        <p className="font-mono text-xs">{ticket.ticketNumber}</p>
                        <CopyButton value={ticket.ticketNumber} label="ticket number" />
                      </div>
                    </div>
                  </div>

                  {/* Ticket UUID with copy */}
                  <div className="flex items-start gap-2.5">
                    <div className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center">
                      <Hash className="h-3.5 w-3.5 text-muted-foreground" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Ticket ID</p>
                      <div className="mt-0.5 flex items-center gap-1">
                        <p className="truncate font-mono text-xs">{ticketId}</p>
                        <CopyButton value={ticketId} label="ticket ID" />
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </SectionErrorBoundary>
          </PageSection>

          {/* Lifecycle Timeline */}
          <PageSection delay={0.18}>
            <SectionErrorBoundary name="Lifecycle">
              <Card className="border-border/60 bg-card/80">
                <CardHeader className="pb-3">
                  <CardTitle className="flex items-center gap-2 text-sm font-medium text-muted-foreground">
                    <History className="h-4 w-4" />
                    Lifecycle
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <TicketLifecycleTimeline ticket={ticket} messages={messagesData ?? []} />
                </CardContent>
              </Card>
            </SectionErrorBoundary>
          </PageSection>

          {/* Activity Log — collapsed by default, lazy-loads when expanded */}
          <PageSection delay={0.22}>
            <SectionErrorBoundary name="Activity Log">
              <Collapsible open={activityOpen} onOpenChange={setActivityOpen}>
                <Card className="border-border/60 bg-card/80">
                  <CollapsibleTrigger asChild>
                    <CardHeader className="cursor-pointer select-none pb-3 transition-colors hover:bg-muted/30">
                      <CardTitle className="flex items-center gap-2 text-sm font-medium text-muted-foreground">
                        <History className="h-4 w-4" />
                        Activity Log
                        <ChevronRight className={`ml-auto h-4 w-4 transition-transform duration-200 ${activityOpen ? "rotate-90" : ""}`} />
                      </CardTitle>
                    </CardHeader>
                  </CollapsibleTrigger>
                  <CollapsibleContent>
                    <CardContent className="pt-0">
                      <EntityActivityPanel targetType="ticket" targetId={ticketId} enabled={activityOpen} />
                    </CardContent>
                  </CollapsibleContent>
                </Card>
              </Collapsible>
            </SectionErrorBoundary>
          </PageSection>

          {/* Danger zone */}
          <PageSection delay={0.27}>
            <SectionErrorBoundary name="Danger Zone">
              <Card className="border-destructive/30">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-medium text-destructive">Danger Zone</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    <p className="text-sm text-muted-foreground">Permanently delete this ticket and all of its messages. This action cannot be undone.</p>
                    <Button variant="destructive" size="sm" className="w-full" onClick={() => setShowDeleteDialog(true)}>
                      <Trash2 className="mr-2 h-4 w-4" /> Delete Ticket
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </SectionErrorBoundary>
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
              This will permanently delete ticket <span className="font-medium text-foreground">{ticket.ticketNumber}</span> and all of its messages. This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setShowDeleteDialog(false)} disabled={deleteTicket.isPending}>
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
              {deleteTicket.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Delete Ticket
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </PageContainer>
  )
}
