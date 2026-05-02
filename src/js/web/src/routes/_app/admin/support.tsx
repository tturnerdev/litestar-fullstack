import { createFileRoute, Link, useNavigate } from "@tanstack/react-router"
import { AlertCircle, ArrowRight, CheckCircle2, Clock, Download, Loader2, Lock, Search, TicketCheck, X } from "lucide-react"
import { useCallback, useEffect, useState } from "react"
import { AdminBreadcrumbs } from "@/components/admin/admin-breadcrumbs"
import { AdminNav } from "@/components/admin/admin-nav"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { DataFreshness } from "@/components/ui/data-freshness"
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { Skeleton, SkeletonTable } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useDebouncedValue } from "@/hooks/use-debounced-value"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { useAdminSupportStats, useAdminTickets } from "@/lib/api/hooks/admin"
import { type CsvHeader, exportToCsv } from "@/lib/csv-export"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"
import type { AdminTicketSummary } from "@/lib/generated/api/types.gen"
import { cn } from "@/lib/utils"

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

const csvHeaders: CsvHeader<AdminTicketSummary>[] = [
  { label: "Ticket #", accessor: (t) => t.ticketNumber },
  { label: "Subject", accessor: (t) => t.subject },
  { label: "Status", accessor: (t) => t.status },
  { label: "Priority", accessor: (t) => t.priority },
  { label: "Category", accessor: (t) => t.category ?? "" },
  { label: "Creator", accessor: (t) => t.creatorEmail ?? "" },
  { label: "Assigned To", accessor: (t) => t.assignedToEmail ?? "" },
  { label: "Read by Agent", accessor: (t) => (t.isReadByAgent ? "Yes" : "No") },
  { label: "Created At", accessor: (t) => t.createdAt },
  { label: "Updated At", accessor: (t) => t.updatedAt },
  { label: "Closed At", accessor: (t) => t.closedAt ?? "" },
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

function AdminSupportPage() {
  useDocumentTitle("Admin Support")
  const navigate = useNavigate()
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState("")
  const debouncedSearch = useDebouncedValue(search)

  // biome-ignore lint/correctness/useExhaustiveDependencies: intentional — reset page when search changes
  useEffect(() => {
    setPage(1)
  }, [debouncedSearch])

  const { data: stats, isLoading: statsLoading, isError: statsError, refetch: refetchStats } = useAdminSupportStats()
  const { data, isLoading, isError, refetch: refetchTickets, dataUpdatedAt, isRefetching } = useAdminTickets(page, PAGE_SIZE, debouncedSearch || undefined)

  const handleRefreshAll = useCallback(() => {
    refetchStats()
    refetchTickets()
  }, [refetchStats, refetchTickets])

  const tickets = data?.items ?? []
  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  const recentTickets = tickets.slice(0, 8)

  const handleExport = useCallback(() => {
    if (!tickets.length) return
    exportToCsv("admin-support-tickets", csvHeaders, tickets)
  }, [tickets])

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Administration"
        title="Support"
        description="Monitor support tickets and response metrics across the organization."
        breadcrumbs={<AdminBreadcrumbs />}
        actions={
          <div className="flex items-center gap-2">
            <DataFreshness dataUpdatedAt={dataUpdatedAt} onRefresh={handleRefreshAll} isRefreshing={isRefetching} />
            <Button variant="outline" size="sm" onClick={handleExport} disabled={!tickets.length}>
              <Download className="mr-2 h-4 w-4" />
              Export
            </Button>
          </div>
        }
      />
      <AdminNav />

      {/* Stat cards */}
      <PageSection>
        <SectionErrorBoundary name="Support Statistics">
          {statsLoading ? (
            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              {Array.from({ length: 4 }).map((_, i) => (
                // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
                <StatsCardSkeleton key={`support-stat-skeleton-${i}`} />
              ))}
            </div>
          ) : statsError ? (
            <EmptyState
              icon={AlertCircle}
              title="Unable to load support statistics"
              description="Something went wrong. Please try again."
              action={
                <Button variant="outline" size="sm" onClick={() => refetchStats()}>
                  Try again
                </Button>
              }
            />
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
                          className={`flex h-9 w-9 items-center justify-center rounded-lg ${stat.bg} ${stat.color} transition-colors ${stat.hoverBg} group-hover:text-primary-foreground`}
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
        </SectionErrorBoundary>
      </PageSection>

      {/* Recent tickets */}
      <PageSection delay={0.1}>
        <SectionErrorBoundary name="Recent Tickets">
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
                <EmptyState
                  icon={AlertCircle}
                  title="Unable to load tickets"
                  description="Something went wrong. Please try again."
                  action={
                    <Button variant="outline" size="sm" onClick={() => refetchTickets()}>
                      Try again
                    </Button>
                  }
                />
              ) : recentTickets.length === 0 ? (
                <EmptyState icon={TicketCheck} title="No recent tickets" description="Support tickets will appear here once created." />
              ) : (
                <div className="overflow-x-auto">
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
                        <TableRow
                          key={ticket.id}
                          className={cn("cursor-pointer hover:bg-muted/50 transition-colors", index % 2 === 1 && "bg-muted/20")}
                          onClick={() => navigate({ to: "/support/$ticketId", params: { ticketId: ticket.id } })}
                          tabIndex={0}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") navigate({ to: "/support/$ticketId", params: { ticketId: ticket.id } })
                          }}
                        >
                          <TableCell className="font-mono text-sm">{ticket.ticketNumber}</TableCell>
                          <TableCell className="font-medium max-w-[300px] truncate" title={ticket.subject}>
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <span>{ticket.subject}</span>
                              </TooltipTrigger>
                              <TooltipContent>{ticket.subject}</TooltipContent>
                            </Tooltip>
                          </TableCell>
                          <TableCell>
                            <Badge variant={priorityVariant[ticket.priority] ?? "outline"} className="gap-1.5">
                              <span
                                className={cn("h-1.5 w-1.5 rounded-full", {
                                  "bg-gray-400": ticket.priority === "low",
                                  "bg-amber-500": ticket.priority === "medium",
                                  "bg-orange-500": ticket.priority === "high",
                                  "bg-red-500": ticket.priority === "urgent",
                                })}
                              />
                              {ticket.priority}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <Badge variant={statusVariant[ticket.status] ?? "outline"} className="gap-1.5">
                              <span
                                className={cn("h-1.5 w-1.5 rounded-full", {
                                  "bg-blue-500": ticket.status === "open",
                                  "bg-amber-500": ticket.status === "in_progress",
                                  "bg-violet-500": ticket.status === "waiting_on_customer" || ticket.status === "waiting_on_support",
                                  "bg-emerald-500": ticket.status === "resolved",
                                  "bg-gray-400": ticket.status === "closed",
                                })}
                              />
                              {statusLabel[ticket.status] ?? ticket.status}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-muted-foreground text-sm">{formatRelativeTimeShort(ticket.createdAt)}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </CardContent>
          </Card>
        </SectionErrorBoundary>
      </PageSection>

      {/* Full ticket list */}
      <PageSection delay={0.2}>
        <SectionErrorBoundary name="All Tickets">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between gap-4">
                <div className="flex items-center gap-3">
                  <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-500/10">
                    <TicketCheck className="h-4 w-4 text-blue-600 dark:text-blue-400" />
                  </div>
                  <div>
                    <CardTitle>All Tickets</CardTitle>
                    <CardDescription>
                      {total} ticket{total !== 1 ? "s" : ""} total
                    </CardDescription>
                  </div>
                </div>
                <div className="relative max-w-sm">
                  <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                  <Input placeholder="Search tickets..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-9 pr-8" />
                  {search && (
                    <button
                      type="button"
                      onClick={() => setSearch("")}
                      className="absolute right-2 top-1/2 -translate-y-1/2 rounded-sm p-0.5 text-muted-foreground hover:text-foreground"
                    >
                      <X className="h-3.5 w-3.5" />
                      <span className="sr-only">Clear search</span>
                    </button>
                  )}
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {isLoading ? (
                <SkeletonTable rows={8} />
              ) : isError ? (
                <EmptyState
                  icon={AlertCircle}
                  title="Unable to load tickets"
                  description="Something went wrong. Please try again."
                  action={
                    <Button variant="outline" size="sm" onClick={() => refetchTickets()}>
                      Try again
                    </Button>
                  }
                />
              ) : tickets.length === 0 ? (
                <EmptyState
                  icon={Search}
                  variant="no-results"
                  title="No tickets found"
                  description="No tickets match your search. Try a different search term."
                  action={
                    <Button variant="outline" size="sm" onClick={() => setSearch("")}>
                      Clear search
                    </Button>
                  }
                />
              ) : (
                <>
                  <div className="overflow-x-auto">
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
                          <TableRow
                            key={ticket.id}
                            className={cn("cursor-pointer hover:bg-muted/50 transition-colors", index % 2 === 1 && "bg-muted/20")}
                            onClick={() => navigate({ to: "/support/$ticketId", params: { ticketId: ticket.id } })}
                            tabIndex={0}
                            onKeyDown={(e) => {
                              if (e.key === "Enter") navigate({ to: "/support/$ticketId", params: { ticketId: ticket.id } })
                            }}
                          >
                            <TableCell className="font-mono text-sm">{ticket.ticketNumber}</TableCell>
                            <TableCell className="font-medium max-w-[250px] truncate" title={ticket.subject}>
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
                              <Badge variant={priorityVariant[ticket.priority] ?? "outline"} className="gap-1.5">
                                <span
                                  className={cn("h-1.5 w-1.5 rounded-full", {
                                    "bg-gray-400": ticket.priority === "low",
                                    "bg-amber-500": ticket.priority === "medium",
                                    "bg-orange-500": ticket.priority === "high",
                                    "bg-red-500": ticket.priority === "urgent",
                                  })}
                                />
                                {ticket.priority}
                              </Badge>
                            </TableCell>
                            <TableCell>
                              <Badge variant={statusVariant[ticket.status] ?? "outline"} className="gap-1.5">
                                <span
                                  className={cn("h-1.5 w-1.5 rounded-full", {
                                    "bg-blue-500": ticket.status === "open",
                                    "bg-amber-500": ticket.status === "in_progress",
                                    "bg-violet-500": ticket.status === "waiting_on_customer" || ticket.status === "waiting_on_support",
                                    "bg-emerald-500": ticket.status === "resolved",
                                    "bg-gray-400": ticket.status === "closed",
                                  })}
                                />
                                {statusLabel[ticket.status] ?? ticket.status}
                              </Badge>
                            </TableCell>
                            <TableCell className="text-muted-foreground">
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <span>{formatRelativeTimeShort(ticket.createdAt)}</span>
                                </TooltipTrigger>
                                <TooltipContent>{formatDateTime(ticket.createdAt)}</TooltipContent>
                              </Tooltip>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
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
        </SectionErrorBoundary>
      </PageSection>
    </PageContainer>
  )
}
