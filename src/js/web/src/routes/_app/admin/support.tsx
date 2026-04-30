import { useState } from "react"
import { createFileRoute, Link } from "@tanstack/react-router"
import { cn } from "@/lib/utils"
import {
  AlertCircle,
  ArrowRight,
  CheckCircle2,
  Clock,
  Loader2,
  Lock,
  Search,
  TicketCheck,
} from "lucide-react"
import { AdminBreadcrumbs } from "@/components/admin/admin-breadcrumbs"
import { AdminNav } from "@/components/admin/admin-nav"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Skeleton, SkeletonTable } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useAdminSupportStats, useAdminTickets } from "@/lib/api/hooks/admin"

export const Route = createFileRoute("/_app/admin/support")({
  component: AdminSupportPage,
})

const PAGE_SIZE = 25

const priorityVariant: Record<string, "default" | "secondary" | "outline" | "destructive"> = {
  low: "outline",
  medium: "secondary",
  high: "default",
  urgent: "destructive",
}

const statusLabel: Record<string, string> = {
  open: "Open",
  in_progress: "In Progress",
  waiting_on_customer: "Waiting (customer)",
  waiting_on_support: "Waiting (support)",
  resolved: "Resolved",
  closed: "Closed",
}

const statusVariant: Record<string, "default" | "secondary" | "outline" | "destructive"> = {
  open: "default",
  in_progress: "secondary",
  waiting_on_customer: "outline",
  waiting_on_support: "outline",
  resolved: "outline",
  closed: "outline",
}

const statConfig = [
  {
    key: "open" as const,
    label: "Open Tickets",
    subtitle: "Awaiting triage",
    icon: TicketCheck,
    color: "text-blue-600 dark:text-blue-400",
    bg: "bg-blue-500/10",
    hoverBg: "group-hover:bg-blue-500",
    to: "/support" as const,
  },
  {
    key: "inProgress" as const,
    label: "In Progress",
    subtitle: "Being worked on",
    icon: Loader2,
    color: "text-amber-600 dark:text-amber-400",
    bg: "bg-amber-500/10",
    hoverBg: "group-hover:bg-amber-500",
    to: "/support" as const,
  },
  {
    key: "resolved" as const,
    label: "Resolved",
    subtitle: "Successfully resolved",
    icon: CheckCircle2,
    color: "text-emerald-600 dark:text-emerald-400",
    bg: "bg-emerald-500/10",
    hoverBg: "group-hover:bg-emerald-500",
    to: "/support" as const,
  },
  {
    key: "closed" as const,
    label: "Closed",
    subtitle: "Completed and archived",
    icon: Lock,
    color: "text-violet-600 dark:text-violet-400",
    bg: "bg-violet-500/10",
    hoverBg: "group-hover:bg-violet-500",
    to: "/support" as const,
  },
]

function StatsCardSkeleton() {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <Skeleton className="h-4 w-24" />
        <Skeleton className="h-9 w-9 rounded-lg" />
      </CardHeader>
      <CardContent>
        <Skeleton className="h-8 w-16" />
        <Skeleton className="mt-2 h-3 w-32" />
      </CardContent>
    </Card>
  )
}

function formatTimeAgo(dateStr: string): string {
  const now = new Date()
  const date = new Date(dateStr)
  const diffMs = now.getTime() - date.getTime()
  const diffMins = Math.floor(diffMs / 60000)
  if (diffMins < 1) return "Just now"
  if (diffMins < 60) return `${diffMins}m ago`
  const diffHours = Math.floor(diffMins / 60)
  if (diffHours < 24) return `${diffHours}h ago`
  const diffDays = Math.floor(diffHours / 24)
  if (diffDays < 7) return `${diffDays}d ago`
  return date.toLocaleDateString()
}

function AdminSupportPage() {
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState("")

  const { data: stats, isLoading: statsLoading, isError: statsError } = useAdminSupportStats()
  const { data, isLoading, isError } = useAdminTickets(page, PAGE_SIZE, search || undefined)

  const tickets = data?.items ?? []
  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  const recentTickets = tickets.slice(0, 8)

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader eyebrow="Administration" title="Support" description="Monitor support tickets and response metrics across the organization." breadcrumbs={<AdminBreadcrumbs />} />
      <AdminNav />

      {/* Stat cards */}
      <PageSection>
        {statsLoading ? (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            {Array.from({ length: 4 }).map((_, i) => (
              // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
              <StatsCardSkeleton key={`support-stat-skeleton-${i}`} />
            ))}
          </div>
        ) : statsError ? (
          <Card>
            <CardContent className="flex items-center gap-3 py-6 text-muted-foreground">
              <AlertCircle className="h-5 w-5 text-destructive" />
              <span>Unable to load support statistics. Please try again later.</span>
            </CardContent>
          </Card>
        ) : (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            {statConfig.map((stat) => {
              const Icon = stat.icon
              const value = stats?.[stat.key] ?? 0
              return (
                <Link key={stat.key} to={stat.to} className="group">
                  <Card className="transition-all duration-200 group-hover:shadow-md group-hover:border-primary/30 group-hover:-translate-y-0.5">
                    <CardHeader className="flex flex-row items-center justify-between pb-2">
                      <CardTitle className="text-sm font-medium text-muted-foreground">{stat.label}</CardTitle>
                      <div
                        className={`flex h-9 w-9 items-center justify-center rounded-lg ${stat.bg} ${stat.color} transition-colors ${stat.hoverBg} group-hover:text-white`}
                      >
                        <Icon className="h-4 w-4" />
                      </div>
                    </CardHeader>
                    <CardContent>
                      <span className="text-3xl font-semibold tracking-tight">{value}</span>
                      <p className="mt-1.5 text-xs text-muted-foreground">{stat.subtitle}</p>
                    </CardContent>
                  </Card>
                </Link>
              )
            })}
          </div>
        )}
      </PageSection>

      {/* Recent tickets */}
      <PageSection delay={0.1}>
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-amber-500/10">
                  <Clock className="h-4 w-4 text-amber-600 dark:text-amber-400" />
                </div>
                <div>
                  <CardTitle>Recent Tickets</CardTitle>
                  <CardDescription>Latest support requests across all teams</CardDescription>
                </div>
              </div>
              <Link to="/support">
                <Button variant="outline" size="sm" className="gap-1.5">
                  View all
                  <ArrowRight className="h-3.5 w-3.5" />
                </Button>
              </Link>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            {isLoading ? (
              <SkeletonTable rows={5} />
            ) : isError ? (
              <div className="flex items-center gap-3 py-8 justify-center text-muted-foreground">
                <AlertCircle className="h-5 w-5 text-destructive" />
                <span>Unable to load tickets.</span>
              </div>
            ) : recentTickets.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                <TicketCheck className="h-10 w-10 mb-3 opacity-40" />
                <p className="font-medium">No recent tickets</p>
                <p className="text-sm mt-1">Support tickets will appear here once created.</p>
              </div>
            ) : (
              <Table aria-label="Recent support tickets">
                <TableHeader>
                  <TableRow>
                    <TableHead>Ticket #</TableHead>
                    <TableHead>Subject</TableHead>
                    <TableHead>Priority</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Created</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {recentTickets.map((ticket, index) => (
                    <TableRow key={ticket.id} className={cn("hover:bg-muted/50 transition-colors", index % 2 === 1 && "bg-muted/20")}>
                      <TableCell className="font-mono text-sm">{ticket.ticketNumber}</TableCell>
                      <TableCell className="font-medium max-w-[300px] truncate">
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <span>{ticket.subject}</span>
                          </TooltipTrigger>
                          <TooltipContent>{ticket.subject}</TooltipContent>
                        </Tooltip>
                      </TableCell>
                      <TableCell>
                        <Badge variant={priorityVariant[ticket.priority] ?? "outline"}>{ticket.priority}</Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant={statusVariant[ticket.status] ?? "outline"}>{statusLabel[ticket.status] ?? ticket.status}</Badge>
                      </TableCell>
                      <TableCell className="text-muted-foreground text-sm">{formatTimeAgo(ticket.createdAt)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </PageSection>

      {/* Full ticket list */}
      <PageSection delay={0.2}>
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-500/10">
                  <TicketCheck className="h-4 w-4 text-blue-600 dark:text-blue-400" />
                </div>
                <div>
                  <CardTitle>All Tickets</CardTitle>
                  <CardDescription>{total} ticket{total !== 1 ? "s" : ""} total</CardDescription>
                </div>
              </div>
              <div className="relative max-w-sm">
                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  placeholder="Search tickets..."
                  value={search}
                  onChange={(e) => {
                    setSearch(e.target.value)
                    setPage(1)
                  }}
                  className="pl-9"
                />
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            {isLoading ? (
              <SkeletonTable rows={8} />
            ) : isError ? (
              <div className="flex items-center gap-3 py-8 justify-center text-muted-foreground">
                <AlertCircle className="h-5 w-5 text-destructive" />
                <span>Unable to load tickets.</span>
              </div>
            ) : tickets.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                <Search className="h-10 w-10 mb-3 opacity-40" />
                <p className="font-medium">{search ? "No tickets match your search" : "No tickets found"}</p>
                <p className="text-sm mt-1">{search ? "Try a different search term." : "Support tickets will appear here once created."}</p>
              </div>
            ) : (
              <>
                <Table aria-label="All support tickets">
                  <TableHeader>
                    <TableRow>
                      <TableHead>Ticket #</TableHead>
                      <TableHead>Subject</TableHead>
                      <TableHead>Creator</TableHead>
                      <TableHead>Assigned To</TableHead>
                      <TableHead>Priority</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Created</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {tickets.map((ticket, index) => (
                      <TableRow key={ticket.id} className={cn("hover:bg-muted/50 transition-colors", index % 2 === 1 && "bg-muted/20")}>
                        <TableCell className="font-mono text-sm">{ticket.ticketNumber}</TableCell>
                        <TableCell className="font-medium max-w-[250px] truncate">
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <span>{ticket.subject}</span>
                            </TooltipTrigger>
                            <TooltipContent>{ticket.subject}</TooltipContent>
                          </Tooltip>
                        </TableCell>
                        <TableCell className="text-muted-foreground">{ticket.creatorEmail ?? "—"}</TableCell>
                        <TableCell className="text-muted-foreground">{ticket.assignedToEmail ?? "Unassigned"}</TableCell>
                        <TableCell>
                          <Badge variant={priorityVariant[ticket.priority] ?? "outline"}>{ticket.priority}</Badge>
                        </TableCell>
                        <TableCell>
                          <Badge variant={statusVariant[ticket.status] ?? "outline"}>{statusLabel[ticket.status] ?? ticket.status}</Badge>
                        </TableCell>
                        <TableCell className="text-muted-foreground">{new Date(ticket.createdAt).toLocaleString()}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
                {totalPages > 1 && (
                  <div className="flex items-center justify-between">
                    <p className="text-xs text-muted-foreground">
                      Page {page} of {totalPages} ({total} total)
                    </p>
                    <div className="flex gap-2">
                      <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page <= 1}>
                        Previous
                      </Button>
                      <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page >= totalPages}>
                        Next
                      </Button>
                    </div>
                  </div>
                )}
              </>
            )}
          </CardContent>
        </Card>
      </PageSection>
    </PageContainer>
  )
}
