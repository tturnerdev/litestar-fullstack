import { useState } from "react"
import { createFileRoute, Link } from "@tanstack/react-router"
import {
  AlertCircle,
  ArrowRight,
  FileText,
  Inbox,
  Printer,
  Search,
  Send,
  XCircle,
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
import { useAdminFaxMessages, useAdminFaxNumbers, useAdminFaxStats } from "@/lib/api/hooks/admin"

export const Route = createFileRoute("/_app/admin/fax")({
  component: AdminFaxPage,
})

const PAGE_SIZE = 25

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
  const [numberPage, setNumberPage] = useState(1)
  const [numberSearch, setNumberSearch] = useState("")

  const { data: stats, isLoading: statsLoading, isError: statsError } = useAdminFaxStats()
  const { data: numberData, isLoading: numbersLoading, isError: numbersError } = useAdminFaxNumbers(numberPage, PAGE_SIZE, numberSearch || undefined)
  const { data: messages, isLoading: messagesLoading, isError: messagesError } = useAdminFaxMessages()

  const faxNumbers = numberData?.items ?? []
  const numberTotal = numberData?.total ?? 0
  const numberTotalPages = Math.max(1, Math.ceil(numberTotal / PAGE_SIZE))

  const faxMessages = Array.isArray(messages) ? messages : []
  const recentMessages = faxMessages.slice(0, 10)

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader eyebrow="Administration" title="Fax" description="Monitor fax numbers, messages, and delivery across the organization." breadcrumbs={<AdminBreadcrumbs />} />
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
          <Card>
            <CardContent className="flex items-center gap-3 py-6 text-muted-foreground">
              <AlertCircle className="h-5 w-5 text-destructive" />
              <span>Unable to load fax statistics. Please try again later.</span>
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
              <div className="flex items-center gap-3 py-8 justify-center text-muted-foreground">
                <AlertCircle className="h-5 w-5 text-destructive" />
                <span>Unable to load fax messages.</span>
              </div>
            ) : recentMessages.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                <FileText className="h-10 w-10 mb-3 opacity-40" />
                <p className="font-medium">No recent fax activity</p>
                <p className="text-sm mt-1">Fax messages will appear here once sent or received.</p>
              </div>
            ) : (
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
                  {recentMessages.map((msg) => (
                    <TableRow key={msg.id} className="hover:bg-muted/50 transition-colors">
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
                        <Badge variant={statusVariant[msg.status] ?? "outline"}>{msg.status}</Badge>
                      </TableCell>
                      <TableCell className="text-muted-foreground">{new Date(msg.receivedAt).toLocaleString()}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
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
                    className="pl-9"
                  />
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
              <div className="flex items-center gap-3 py-8 justify-center text-muted-foreground">
                <AlertCircle className="h-5 w-5 text-destructive" />
                <span>Unable to load fax numbers.</span>
              </div>
            ) : faxNumbers.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                <Printer className="h-10 w-10 mb-3 opacity-40" />
                <p className="font-medium">{numberSearch ? "No numbers match your search" : "No fax numbers found"}</p>
                <p className="text-sm mt-1">{numberSearch ? "Try a different search term." : "Fax numbers will appear here once added."}</p>
              </div>
            ) : (
              <>
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
                    {faxNumbers.map((fn) => (
                      <TableRow key={fn.id} className="hover:bg-muted/50 transition-colors">
                        <TableCell className="font-mono font-medium">{fn.number}</TableCell>
                        <TableCell className="text-muted-foreground">{fn.label ?? "—"}</TableCell>
                        <TableCell className="text-muted-foreground">{fn.teamName ?? "—"}</TableCell>
                        <TableCell className="text-muted-foreground">{fn.ownerEmail ?? "Unassigned"}</TableCell>
                        <TableCell>
                          <Badge variant={fn.isActive ? "default" : "secondary"}>{fn.isActive ? "Active" : "Inactive"}</Badge>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
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
