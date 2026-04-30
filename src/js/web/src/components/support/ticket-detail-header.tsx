import { useNavigate } from "@tanstack/react-router"
import {
  AlertTriangle,
  Calendar,
  Check,
  ChevronDown,
  Clock,
  Copy,
  Eye,
  EyeOff,
  Lock,
  Mail,
  Tag,
  Timer,
  Trash2,
  Unlock,
  User,
  Users,
} from "lucide-react"
import { useCallback, useEffect, useMemo, useState } from "react"
import { TicketPriorityBadge } from "@/components/support/ticket-priority-badge"
import { TicketStatusBadge } from "@/components/support/ticket-status-badge"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { Badge } from "@/components/ui/badge"
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
import { Card, CardContent } from "@/components/ui/card"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Separator } from "@/components/ui/separator"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import type { Ticket } from "@/lib/api/hooks/support"
import { useCloseTicket, useDeleteTicket, useReopenTicket, useUpdateTicket } from "@/lib/api/hooks/support"

interface TicketDetailHeaderProps {
  ticket: Ticket
}

const categoryLabels: Record<string, string> = {
  billing: "Billing",
  technical: "Technical",
  account: "Account",
  device: "Device",
  voice: "Voice",
  fax: "Fax",
  general: "General",
}

const categories = Object.keys(categoryLabels) as string[]

const priorities = ["low", "medium", "high", "urgent"] as const

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
  return date.toLocaleDateString(undefined, { month: "short", day: "numeric", year: date.getFullYear() !== now.getFullYear() ? "numeric" : undefined })
}

// ── SLA Helpers ───────────────────────────────────────────────────────────

function getHoursSinceCreation(createdAt: string | null | undefined): number {
  if (!createdAt) return 0
  return (Date.now() - new Date(createdAt).getTime()) / (1000 * 60 * 60)
}

function formatSlaTime(hours: number): string {
  if (hours < 1) return `${Math.floor(hours * 60)}m`
  if (hours < 24) return `${Math.floor(hours)}h`
  const days = Math.floor(hours / 24)
  const remainingHours = Math.floor(hours % 24)
  return remainingHours > 0 ? `${days}d ${remainingHours}h` : `${days}d`
}

function getSlaColor(hours: number): string {
  if (hours < 4) return "text-emerald-600 dark:text-emerald-400"
  if (hours < 24) return "text-amber-600 dark:text-amber-400"
  return "text-red-600 dark:text-red-400"
}

function getSlaBgColor(hours: number): string {
  if (hours < 4) return "bg-emerald-500/10 border-emerald-500/30"
  if (hours < 24) return "bg-amber-500/10 border-amber-500/30"
  return "bg-red-500/10 border-red-500/30"
}

// ── Assignee avatar helpers ───────────────────────────────────────────────

function getAvatarColor(identifier: string): string {
  const colors = [
    "bg-blue-500/15 text-blue-700 dark:text-blue-400",
    "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400",
    "bg-violet-500/15 text-violet-700 dark:text-violet-400",
    "bg-amber-500/15 text-amber-700 dark:text-amber-400",
    "bg-rose-500/15 text-rose-700 dark:text-rose-400",
    "bg-cyan-500/15 text-cyan-700 dark:text-cyan-400",
  ]
  let hash = 0
  for (let i = 0; i < identifier.length; i++) {
    hash = identifier.charCodeAt(i) + ((hash << 5) - hash)
  }
  return colors[Math.abs(hash) % colors.length]
}

// ── Component ─────────────────────────────────────────────────────────────

export function TicketDetailHeader({ ticket }: TicketDetailHeaderProps) {
  const navigate = useNavigate()
  const closeTicket = useCloseTicket(ticket.id)
  const reopenTicket = useReopenTicket(ticket.id)
  const updateTicket = useUpdateTicket(ticket.id)
  const deleteTicket = useDeleteTicket(ticket.id)
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)
  const [copied, setCopied] = useState(false)
  const [watching, setWatching] = useState(false)

  const isClosed = ticket.status === "closed" || ticket.status === "resolved"
  const isHighPriority = ticket.priority === "high" || ticket.priority === "urgent"
  const showSla = isHighPriority && !isClosed

  // Live-updating SLA timer for high/urgent open tickets
  const [slaHours, setSlaHours] = useState(() => getHoursSinceCreation(ticket.createdAt))

  useEffect(() => {
    if (!showSla) return
    setSlaHours(getHoursSinceCreation(ticket.createdAt))
    const interval = setInterval(() => {
      setSlaHours(getHoursSinceCreation(ticket.createdAt))
    }, 60_000) // update every minute
    return () => clearInterval(interval)
  }, [showSla, ticket.createdAt])

  const slaColor = useMemo(() => getSlaColor(slaHours), [slaHours])
  const slaBgColor = useMemo(() => getSlaBgColor(slaHours), [slaHours])

  const handleCopyTicketNumber = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(ticket.ticketNumber)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // Fallback -- silently ignore if clipboard API not available
    }
  }, [ticket.ticketNumber])

  return (
    <Card className="border-border/60 bg-card/80">
      <CardContent className="py-4">
        {/* Action bar */}
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-sm">
          {/* Ticket number with copy button */}
          <Tooltip>
            <TooltipTrigger asChild>
              <button
                type="button"
                onClick={handleCopyTicketNumber}
                className="group/copy flex items-center gap-1.5 rounded-md px-1.5 py-0.5 font-mono text-xs text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
              >
                {ticket.ticketNumber}
                {copied ? (
                  <Check className="h-3 w-3 text-emerald-500" />
                ) : (
                  <Copy className="h-3 w-3 opacity-0 transition-opacity group-hover/copy:opacity-100" />
                )}
              </button>
            </TooltipTrigger>
            <TooltipContent>{copied ? "Copied!" : "Copy ticket number"}</TooltipContent>
          </Tooltip>

          <Separator orientation="vertical" className="h-4" />
          <TicketStatusBadge status={ticket.status} />
          <Separator orientation="vertical" className="h-4" />
          <TicketPriorityBadge priority={ticket.priority} />

          {/* SLA indicator for high/urgent open tickets */}
          {showSla && (
            <>
              <Separator orientation="vertical" className="h-4" />
              <Tooltip>
                <TooltipTrigger asChild>
                  <Badge
                    variant="outline"
                    className={`gap-1 text-xs ${slaBgColor} ${slaColor}`}
                  >
                    <Timer className="h-3 w-3" />
                    {formatSlaTime(slaHours)}
                  </Badge>
                </TooltipTrigger>
                <TooltipContent>
                  <div className="text-xs">
                    <p className="font-medium">Time since opened</p>
                    <p className="text-muted-foreground">
                      {slaHours < 4
                        ? "Within SLA target (< 4h)"
                        : slaHours < 24
                          ? "Approaching SLA limit (< 24h)"
                          : "SLA target exceeded (> 24h)"}
                    </p>
                  </div>
                </TooltipContent>
              </Tooltip>
            </>
          )}

          <Separator orientation="vertical" className="ml-auto hidden h-4 sm:block" />

          <div className="ml-auto flex items-center gap-2 sm:ml-0">
            {/* Watch/Unwatch toggle */}
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant={watching ? "secondary" : "ghost"}
                  size="sm"
                  className="h-7 w-7 p-0"
                  onClick={() => setWatching((prev) => !prev)}
                >
                  {watching ? (
                    <Eye className="h-3.5 w-3.5" />
                  ) : (
                    <EyeOff className="h-3.5 w-3.5" />
                  )}
                </Button>
              </TooltipTrigger>
              <TooltipContent>
                {watching ? "Unwatch -- stop receiving notifications" : "Watch -- receive notifications for updates"}
              </TooltipContent>
            </Tooltip>

            <Separator orientation="vertical" className="h-4" />

            {/* Priority dropdown */}
            <Tooltip>
              <TooltipTrigger asChild>
                <span>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="outline" size="sm" className="h-7 text-xs">
                        Priority
                        <ChevronDown className="ml-1 h-3 w-3" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuLabel>Change Priority</DropdownMenuLabel>
                      <DropdownMenuSeparator />
                      {priorities.map((p) => (
                        <DropdownMenuItem
                          key={p}
                          onClick={() => updateTicket.mutate({ priority: p })}
                          disabled={ticket.priority === p}
                        >
                          <TicketPriorityBadge priority={p} />
                        </DropdownMenuItem>
                      ))}
                    </DropdownMenuContent>
                  </DropdownMenu>
                </span>
              </TooltipTrigger>
              <TooltipContent>Change the ticket priority level</TooltipContent>
            </Tooltip>

            {/* Category dropdown */}
            <Tooltip>
              <TooltipTrigger asChild>
                <span>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="outline" size="sm" className="h-7 text-xs">
                        <Tag className="mr-1 h-3 w-3" />
                        {ticket.category ? (categoryLabels[ticket.category] ?? ticket.category) : "Category"}
                        <ChevronDown className="ml-1 h-3 w-3" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuLabel>Change Category</DropdownMenuLabel>
                      <DropdownMenuSeparator />
                      {categories.map((cat) => (
                        <DropdownMenuItem
                          key={cat}
                          onClick={() => updateTicket.mutate({ category: cat })}
                          disabled={ticket.category === cat}
                        >
                          {categoryLabels[cat] ?? cat}
                        </DropdownMenuItem>
                      ))}
                    </DropdownMenuContent>
                  </DropdownMenu>
                </span>
              </TooltipTrigger>
              <TooltipContent>Change the ticket category</TooltipContent>
            </Tooltip>

            <Separator orientation="vertical" className="h-4" />

            {isClosed ? (
              <Button
                size="sm"
                variant="outline"
                className="h-7 text-xs"
                onClick={() => reopenTicket.mutate()}
                disabled={reopenTicket.isPending}
              >
                <Unlock className="mr-1.5 h-3 w-3" />
                Reopen
              </Button>
            ) : (
              <Button
                size="sm"
                variant="outline"
                className="h-7 text-xs"
                onClick={() => closeTicket.mutate()}
                disabled={closeTicket.isPending}
              >
                <Lock className="mr-1.5 h-3 w-3" />
                Close
              </Button>
            )}

            <Button
              size="sm"
              variant="outline"
              className="h-7 text-xs text-destructive hover:bg-destructive/10"
              onClick={() => setShowDeleteDialog(true)}
            >
              <Trash2 className="mr-1.5 h-3 w-3" />
              Delete
            </Button>
          </div>
        </div>

        <Separator className="my-4" />

        {/* Metadata grid */}
        <div className="grid gap-x-6 gap-y-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
          {/* Reporter */}
          <div className="flex items-start gap-2.5">
            <div className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center">
              <User className="h-3.5 w-3.5 text-muted-foreground" />
            </div>
            <div className="min-w-0">
              <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Reporter
              </p>
              <Tooltip>
                <TooltipTrigger asChild>
                  <p className="mt-0.5 truncate font-medium">
                    {ticket.user?.name ?? ticket.user?.email ?? "Unknown"}
                  </p>
                </TooltipTrigger>
                <TooltipContent>{ticket.user?.name ?? ticket.user?.email ?? "Unknown"}</TooltipContent>
              </Tooltip>
              {ticket.user?.name && ticket.user?.email && (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <p className="truncate text-xs text-muted-foreground">{ticket.user.email}</p>
                  </TooltipTrigger>
                  <TooltipContent>{ticket.user.email}</TooltipContent>
                </Tooltip>
              )}
            </div>
          </div>

          {/* Assigned to -- with avatar */}
          <div className="flex items-start gap-2.5">
            {ticket.assignedTo ? (
              <Avatar className="mt-0.5 h-5 w-5 text-[10px]">
                {ticket.assignedTo.avatarUrl ? (
                  <AvatarImage src={ticket.assignedTo.avatarUrl} alt={ticket.assignedTo.name ?? ""} />
                ) : null}
                <AvatarFallback
                  className={`text-[10px] font-medium ${getAvatarColor(ticket.assignedTo.id)}`}
                >
                  {(ticket.assignedTo.name?.[0] ?? ticket.assignedTo.email?.[0] ?? "?").toUpperCase()}
                </AvatarFallback>
              </Avatar>
            ) : (
              <div className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center">
                <Users className="h-3.5 w-3.5 text-muted-foreground" />
              </div>
            )}
            <div className="min-w-0">
              <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Assigned To
              </p>
              {ticket.assignedTo ? (
                <>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <p className="mt-0.5 truncate font-medium">
                        {ticket.assignedTo.name ?? ticket.assignedTo.email}
                      </p>
                    </TooltipTrigger>
                    <TooltipContent>{ticket.assignedTo.name ?? ticket.assignedTo.email}</TooltipContent>
                  </Tooltip>
                  {ticket.assignedTo.name && ticket.assignedTo.email && (
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <p className="truncate text-xs text-muted-foreground">
                          {ticket.assignedTo.email}
                        </p>
                      </TooltipTrigger>
                      <TooltipContent>{ticket.assignedTo.email}</TooltipContent>
                    </Tooltip>
                  )}
                </>
              ) : (
                <p className="mt-0.5 text-muted-foreground/70">Unassigned</p>
              )}
            </div>
          </div>

          {/* Category */}
          <div className="flex items-start gap-2.5">
            <div className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center">
              <Tag className="h-3.5 w-3.5 text-muted-foreground" />
            </div>
            <div className="min-w-0">
              <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Category
              </p>
              <p className="mt-0.5 font-medium">
                {ticket.category ? (categoryLabels[ticket.category] ?? ticket.category) : "None"}
              </p>
            </div>
          </div>

          {/* Messages */}
          <div className="flex items-start gap-2.5">
            <div className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center">
              <Mail className="h-3.5 w-3.5 text-muted-foreground" />
            </div>
            <div className="min-w-0">
              <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Messages
              </p>
              <p className="mt-0.5 font-medium">{ticket.messageCount}</p>
            </div>
          </div>
        </div>

        <Separator className="my-4" />

        {/* Timestamps row */}
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-xs text-muted-foreground">
          <Tooltip>
            <TooltipTrigger asChild>
              <div className="flex items-center gap-1.5 cursor-default">
                <Calendar className="h-3.5 w-3.5" />
                <span>Created {formatRelativeTime(ticket.createdAt)}</span>
              </div>
            </TooltipTrigger>
            <TooltipContent>
              {ticket.createdAt ? new Date(ticket.createdAt).toLocaleString() : "--"}
            </TooltipContent>
          </Tooltip>

          {ticket.updatedAt && ticket.updatedAt !== ticket.createdAt && (
            <Tooltip>
              <TooltipTrigger asChild>
                <div className="flex items-center gap-1.5 cursor-default">
                  <Clock className="h-3.5 w-3.5" />
                  <span>Updated {formatRelativeTime(ticket.updatedAt)}</span>
                </div>
              </TooltipTrigger>
              <TooltipContent>
                {new Date(ticket.updatedAt).toLocaleString()}
              </TooltipContent>
            </Tooltip>
          )}

          {ticket.closedAt && (
            <Tooltip>
              <TooltipTrigger asChild>
                <div className="flex items-center gap-1.5 cursor-default">
                  <Lock className="h-3.5 w-3.5" />
                  <span>Closed {formatRelativeTime(ticket.closedAt)}</span>
                </div>
              </TooltipTrigger>
              <TooltipContent>
                {new Date(ticket.closedAt).toLocaleString()}
              </TooltipContent>
            </Tooltip>
          )}

          {ticket.resolvedAt && (
            <Tooltip>
              <TooltipTrigger asChild>
                <div className="flex items-center gap-1.5 cursor-default">
                  <Lock className="h-3.5 w-3.5" />
                  <span>Resolved {formatRelativeTime(ticket.resolvedAt)}</span>
                </div>
              </TooltipTrigger>
              <TooltipContent>
                {new Date(ticket.resolvedAt).toLocaleString()}
              </TooltipContent>
            </Tooltip>
          )}
        </div>
      </CardContent>

      {/* Delete confirmation */}
      <AlertDialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-destructive" />
              Delete ticket
            </AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete ticket{" "}
              <span className="font-medium text-foreground">{ticket.ticketNumber}</span>? This will
              permanently remove the ticket and all of its messages. This action cannot be undone.
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
                    navigate({ to: "/support" })
                  },
                })
              }}
            >
              {deleteTicket.isPending ? "Deleting..." : "Delete ticket"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  )
}
