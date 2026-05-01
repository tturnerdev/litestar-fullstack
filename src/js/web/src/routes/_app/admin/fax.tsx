import { useCallback, useState } from "react"
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router"
import { cn } from "@/lib/utils"
import {
  AlertCircle,
  ArrowRight,
  Download,
  FileText,
  Inbox,
  Printer,
  Search,
  Send,
  X,
  XCircle,
} from "lucide-react"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { AdminBreadcrumbs } from "@/components/admin/admin-breadcrumbs"
import { AdminNav } from "@/components/admin/admin-nav"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Skeleton, SkeletonTable } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { EmptyState } from "@/components/ui/empty-state"
import { useAdminFaxMessages, useAdminFaxNumbers, useAdminFaxStats } from "@/lib/api/hooks/admin"
import { exportToCsv, type CsvHeader } from "@/lib/csv-export"
import { formatDateTime } from "@/lib/date-utils"
import type { AdminFaxNumberSummary } from "@/lib/generated/api"

export const Route = createFileRoute("/_app/admin/fax")({
  component: AdminFaxPage,
})

const PAGE_SIZE = 25

const csvHeaders: CsvHeader<AdminFaxNumberSummary>[] = [
  { label: "Number", accessor: (f) => f.number },
  { label: "Label", accessor: (f) => f.label ?? "" },
  { label: "Active", accessor: (f) => (f.isActive ? "Yes" : "No") },
  { label: "Owner", accessor: (f) => f.ownerEmail ?? "" },
  { label: "Team", accessor: (f) => f.teamName ?? "" },
  { label: "Created At", accessor: (f) => f.createdAt },
]

const statusVariant: Record<string, "default" | "secondary" | "outline" | "destructive"> = {
  completed: "default",
  delivered: "default",
  sending: "secondary",
  queued: "outline",
  failed: "destructive",
}

const statConfig = [
  {
    key: "totalNumbers" as const,
    label: "Fax Numbers",
    subtitle: "All registered fax lines",
    icon: Printer,
    color: "text-blue-600 dark:text-blue-400",
    bg: "bg-blue-500/10",
    hoverBg: "group-hover:bg-blue-500",
    to: "/fax/numbers" as const,
  },
  {
    key: "activeNumbers" as const,
    label: "Active Numbers",
    subtitle: "Currently in service",
    icon: Inbox,
    color: "text-emerald-600 dark:text-emerald-400",
    bg: "bg-emerald-500/10",
    hoverBg: "group-hover:bg-emerald-500",
    to: "/fax/numbers" as const,
  },
  {
    key: "messagesToday" as const,
    label: "Messages Today",
    subtitle: "Sent and received today",
    icon: Send,
    color: "text-violet-600 dark:text-violet-400",
    bg: "bg-violet-500/10",
    hoverBg: "group-hover:bg-violet-500",
    to: "/fax" as const,
  },
  {
    key: "failedToday" as const,
    label: "Failed Today",
    subtitle: "Delivery failures today",
    icon: XCircle,
    color: "text-red-600 dark:text-red-400",
    bg: "bg-red-500/10",
    hoverBg: "group-hover:bg-red-500",
    to: "/fax" as const,
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

function AdminFaxPage() {
  useDocumentTitle("Admin Fax")
  const navigate = useNavigate()
  const [numberPage, setNumberPage] = useState(1)
  const [numberSearch, setNumberSearch] = useState("")

  const { data: stats, isLoading: statsLoading, isError: statsError, refetch: refetchStats } = useAdminFaxStats()
  const { data: numberData, isLoading: numbersLoading, isError: numbersError, refetch: refetchNumbers } = useAdminFaxNumbers(numberPage, PAGE_SIZE, numberSearch || undefined)
  const { data: messages, isLoading: messagesLoading, isError: messagesError, refetch: refetchMessages } = useAdminFaxMessages()

  const faxNumbers = numberData?.items ?? []
  const numberTotal = numberData?.total ?? 0
  const numberTotalPages = Math.max(1, Math.ceil(numberTotal / PAGE_SIZE))

  const faxMessages = Array.isArray(messages) ? messages : []
  const recentMessages = faxMessages.slice(0, 10)

  const handleExport = useCallback(() => {
    if (!faxNumbers.length) return
    exportToCsv("admin-fax-numbers", csvHeaders, faxNumbers)
  }, [faxNumbers])

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Administration"
        title="Fax"
        description="Monitor fax numbers, messages, and delivery across the organization."
        breadcrumbs={<AdminBreadcrumbs />}
        actions={
          <Button variant="outline" size="sm" onClick={handleExport} disabled={!faxNumbers.length}>
            <Download className="mr-2 h-4 w-4" />
            Export
          </Button>
        }
      />
      <AdminNav />

      {/* Stat cards */}
      <PageSection>
        {statsLoading ? (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            {Array.from({ length: 4 }).map((_, i) => (
              // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
              <StatsCardSkeleton key={`fax-stat-skeleton-${i}`} />
            ))}
          </div>
        ) : statsError ? (
          <EmptyState
            icon={AlertCircle}
            title="Unable to load fax statistics"
            description="Something went wrong. Please try again."
            action={<Button variant="outline" size="sm" onClick={() => refetchStats()}>Try again</Button>}
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
      </PageSection>

      {/* Recent fax activity */}
      <PageSection delay={0.1}>
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-violet-500/10">
                  <FileText className="h-4 w-4 text-violet-600 dark:text-violet-400" />
                </div>
                <div>
                  <CardTitle>Recent Fax Activity</CardTitle>
                  <CardDescription>Latest fax messages across all numbers</CardDescription>
                </div>
              </div>
              <Link to="/fax">
                <Button variant="outline" size="sm" className="gap-1.5">
                  View all
                  <ArrowRight className="h-3.5 w-3.5" />
                </Button>
              </Link>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            {messagesLoading ? (
              <SkeletonTable rows={5} />
            ) : messagesError ? (
              <EmptyState
                icon={AlertCircle}
                title="Unable to load fax messages"
                description="Something went wrong. Please try again."
                action={<Button variant="outline" size="sm" onClick={() => refetchMessages()}>Try again</Button>}
              />
            ) : recentMessages.length === 0 ? (
              <EmptyState
                icon={FileText}
                title="No recent fax activity"
                description="Fax messages will appear here once sent or received."
              />
            ) : (
              <div className="overflow-x-auto">
                <Table aria-label="Recent fax activity">
                  <TableHeader>
                    <TableRow>
                      <TableHead>Direction</TableHead>
                      <TableHead>Fax Number</TableHead>
                      <TableHead>Remote Number</TableHead>
                      <TableHead>Pages</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Received</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {recentMessages.map((msg, index) => (
                      <TableRow key={msg.id} className={cn("cursor-pointer hover:bg-muted/50 transition-colors", index % 2 === 1 && "bg-muted/20")} onClick={() => navigate({ to: "/fax/messages/$messageId", params: { messageId: msg.id } })}>
                        <TableCell>
                          <Badge variant={msg.direction === "inbound" ? "outline" : "secondary"}>
                            <span className="flex items-center gap-1">
                              {msg.direction === "inbound" ? <Inbox className="h-3 w-3" /> : <Send className="h-3 w-3" />}
                              {msg.direction}
                            </span>
                          </Badge>
                        </TableCell>
                        <TableCell className="font-mono font-medium">{msg.faxNumber}</TableCell>
                        <TableCell className="font-mono text-muted-foreground">{msg.remoteNumber}</TableCell>
                        <TableCell className="text-muted-foreground">{msg.pageCount}</TableCell>
                        <TableCell>
                          <Badge variant={statusVariant[msg.status] ?? "outline"} className="gap-1.5">
                            <span className={cn("h-1.5 w-1.5 rounded-full", {
                              "bg-emerald-500": msg.status === "completed" || msg.status === "delivered",
                              "bg-amber-500": msg.status === "sending",
                              "bg-gray-400": msg.status === "queued",
                              "bg-red-500": msg.status === "failed",
                            })} />
                            {msg.status}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-muted-foreground">{formatDateTime(msg.receivedAt)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>
      </PageSection>

      {/* Fax numbers */}
      <PageSection delay={0.2}>
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-500/10">
                  <Printer className="h-4 w-4 text-blue-600 dark:text-blue-400" />
                </div>
                <div>
                  <CardTitle>Fax Numbers</CardTitle>
                  <CardDescription>{numberTotal} number{numberTotal !== 1 ? "s" : ""} total</CardDescription>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <div className="relative max-w-sm">
                  <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                  <Input
                    placeholder="Search numbers..."
                    value={numberSearch}
                    onChange={(e) => {
                      setNumberSearch(e.target.value)
                      setNumberPage(1)
                    }}
                    className="pl-9 pr-8"
                  />
                  {numberSearch && (
                    <button
                      type="button"
                      onClick={() => {
                        setNumberSearch("")
                        setNumberPage(1)
                      }}
                      className="absolute right-2 top-1/2 -translate-y-1/2 rounded-sm p-0.5 text-muted-foreground hover:text-foreground"
                    >
                      <X className="h-3.5 w-3.5" />
                      <span className="sr-only">Clear search</span>
                    </button>
                  )}
                </div>
                <Link to="/fax/numbers">
                  <Button variant="outline" size="sm" className="gap-1.5">
                    Manage
                    <ArrowRight className="h-3.5 w-3.5" />
                  </Button>
                </Link>
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            {numbersLoading ? (
              <SkeletonTable rows={5} />
            ) : numbersError ? (
              <EmptyState
                icon={AlertCircle}
                title="Unable to load fax numbers"
                description="Something went wrong. Please try again."
                action={<Button variant="outline" size="sm" onClick={() => refetchNumbers()}>Try again</Button>}
              />
            ) : faxNumbers.length === 0 ? (
              <EmptyState
                icon={Search}
                variant="no-results"
                title="No fax numbers found"
                description="No fax numbers match your search. Try a different search term."
                action={
                  <Button variant="outline" size="sm" onClick={() => setNumberSearch("")}>
                    Clear search
                  </Button>
                }
              />
            ) : (
              <>
                <div className="overflow-x-auto">
                  <Table aria-label="Fax numbers">
                    <TableHeader>
                      <TableRow>
                        <TableHead>Number</TableHead>
                        <TableHead>Label</TableHead>
                        <TableHead>Team</TableHead>
                        <TableHead>Owner</TableHead>
                        <TableHead>Status</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {faxNumbers.map((fn, index) => (
                        <TableRow key={fn.id} className={cn("cursor-pointer hover:bg-muted/50 transition-colors", index % 2 === 1 && "bg-muted/20")} onClick={() => navigate({ to: "/fax/numbers/$faxNumberId", params: { faxNumberId: fn.id } })}>
                          <TableCell className="font-mono font-medium">{fn.number}</TableCell>
                          <TableCell className="text-muted-foreground">{fn.label ?? "—"}</TableCell>
                          <TableCell className="text-muted-foreground">{fn.teamName ?? "—"}</TableCell>
                          <TableCell className="text-muted-foreground">{fn.ownerEmail ?? "Unassigned"}</TableCell>
                          <TableCell>
                            <Badge variant={fn.isActive ? "default" : "secondary"} className="gap-1.5">
                              <span className={cn("h-1.5 w-1.5 rounded-full", fn.isActive ? "bg-emerald-500" : "bg-gray-400")} />
                              {fn.isActive ? "Active" : "Inactive"}
                            </Badge>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
                {numberTotalPages > 1 && (
                  <div className="flex items-center justify-between">
                    <p className="text-xs text-muted-foreground">
                      Page {numberPage} of {numberTotalPages} ({numberTotal} total)
                    </p>
                    <div className="flex gap-2">
                      <Button variant="outline" size="sm" onClick={() => setNumberPage((p) => Math.max(1, p - 1))} disabled={numberPage <= 1}>
                        Previous
                      </Button>
                      <Button variant="outline" size="sm" onClick={() => setNumberPage((p) => Math.min(numberTotalPages, p + 1))} disabled={numberPage >= numberTotalPages}>
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
