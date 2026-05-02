import { createFileRoute, Link } from "@tanstack/react-router"
import {
  AlertTriangle,
  FileText,
  Hash,
  Inbox,
  Mail,
  Send,
  TrendingUp,
  type LucideIcon,
} from "lucide-react"
import { useMemo } from "react"
import { Area, AreaChart, ResponsiveContainer, Tooltip as RechartsTooltip, XAxis, YAxis } from "recharts"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonCard } from "@/components/ui/skeleton"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { useFaxMessages, useFaxNumbers } from "@/lib/api/hooks/fax"
import { formatDateTime } from "@/lib/date-utils"

interface FaxShortcut {
  key: string
  label: string
  to: string
  icon: LucideIcon
  iconBg: string
  iconText: string
}

const faxShortcuts: FaxShortcut[] = [
  {
    key: "send-fax",
    label: "Send Fax",
    to: "/fax/send",
    icon: Send,
    iconBg: "bg-emerald-500/10 group-hover:bg-emerald-500",
    iconText: "text-emerald-600 dark:text-emerald-400 group-hover:text-white dark:group-hover:text-white",
  },
  {
    key: "manage-numbers",
    label: "Manage Numbers",
    to: "/fax/numbers",
    icon: Hash,
    iconBg: "bg-primary/10 group-hover:bg-primary",
    iconText: "text-primary group-hover:text-primary-foreground",
  },
  {
    key: "view-messages",
    label: "View Messages",
    to: "/fax/messages",
    icon: Mail,
    iconBg: "bg-blue-500/10 group-hover:bg-blue-500",
    iconText: "text-blue-600 dark:text-blue-400 group-hover:text-white dark:group-hover:text-white",
  },
  {
    key: "email-routes",
    label: "Email Routes",
    to: "/fax/email-routes",
    icon: Mail,
    iconBg: "bg-amber-500/10 group-hover:bg-amber-500",
    iconText: "text-amber-600 dark:text-amber-400 group-hover:text-white dark:group-hover:text-white",
  },
]

export const Route = createFileRoute("/_app/fax/")({
  component: FaxOverviewPage,
})

function FaxOverviewPage() {
  useDocumentTitle("Fax")
  const { data: numbers, isLoading: numbersLoading } = useFaxNumbers(1, 100)
  const { data: messages, isLoading: messagesLoading } = useFaxMessages({
    page: 1,
    pageSize: 100,
  })

  const isLoading = numbersLoading || messagesLoading

  const activeCount = numbers?.items.filter((n) => n.isActive).length ?? 0
  const failedCount = messages?.items.filter((m) => m.status === "failed").length ?? 0
  const inboundCount = messages?.items.filter((m) => m.direction === "inbound").length ?? 0
  const outboundCount = messages?.items.filter((m) => m.direction === "outbound").length ?? 0

  const volumeChartData = useMemo(() => {
    const days: { date: string; label: string; inbound: number; outbound: number }[] = []
    const now = new Date()
    for (let i = 6; i >= 0; i--) {
      const d = new Date(now)
      d.setDate(d.getDate() - i)
      const dateKey = d.toISOString().slice(0, 10)
      const label = d.toLocaleDateString("en-US", { weekday: "short" })
      days.push({ date: dateKey, label, inbound: 0, outbound: 0 })
    }
    if (messages?.items) {
      for (const msg of messages.items) {
        const timestamp = msg.receivedAt ?? msg.createdAt
        if (!timestamp) continue
        const dateKey = timestamp.slice(0, 10)
        const day = days.find((d) => d.date === dateKey)
        if (day) {
          if (msg.direction === "inbound") {
            day.inbound++
          } else {
            day.outbound++
          }
        }
      }
    }
    return days
  }, [messages])

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Communications"
        title="Fax"
        description="Manage your fax numbers, view message history, and send faxes."
      />

      <PageSection delay={0.1}>
        {isLoading ? (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            {Array.from({ length: 4 }).map((_, index) => (
              // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
              <SkeletonCard key={`fax-stats-skeleton-${index}`} />
            ))}
          </div>
        ) : (
          <SectionErrorBoundary name="Fax Statistics">
            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              <Card>
                <CardHeader className="flex flex-row items-center justify-between">
                  <CardTitle className="text-sm text-muted-foreground">Fax Numbers</CardTitle>
                  <Hash className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-3xl font-semibold">{numbers?.total ?? 0}</div>
                  <p className="text-xs text-muted-foreground mt-1">
                    {activeCount} active
                  </p>
                </CardContent>
              </Card>
              <Card>
                <CardHeader className="flex flex-row items-center justify-between">
                  <CardTitle className="text-sm text-muted-foreground">Total Messages</CardTitle>
                  <FileText className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-3xl font-semibold">{messages?.total ?? 0}</div>
                  <p className="text-xs text-muted-foreground mt-1">
                    {inboundCount} inbound, {outboundCount} outbound
                  </p>
                </CardContent>
              </Card>
              <Card>
                <CardHeader className="flex flex-row items-center justify-between">
                  <CardTitle className="text-sm text-muted-foreground">Inbound</CardTitle>
                  <Inbox className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-3xl font-semibold">{inboundCount}</div>
                  <p className="text-xs text-muted-foreground mt-1">received faxes</p>
                </CardContent>
              </Card>
              <Card>
                <CardHeader className="flex flex-row items-center justify-between">
                  <CardTitle className="text-sm text-muted-foreground">Failed</CardTitle>
                  <AlertTriangle className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-3xl font-semibold">{failedCount}</div>
                  <p className="text-xs text-muted-foreground mt-1">
                    {failedCount === 0 ? "all clear" : "need attention"}
                  </p>
                </CardContent>
              </Card>
            </div>
          </SectionErrorBoundary>
        )}
      </PageSection>

      <PageSection delay={0.12}>
        <SectionErrorBoundary name="Quick Actions">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {faxShortcuts.map((shortcut) => (
              <Link key={shortcut.key} to={shortcut.to}>
                <Card className="group cursor-pointer transition-all duration-200 hover:scale-[1.02] hover:shadow-md">
                  <CardContent className="flex flex-col items-center gap-2.5 px-3 py-4">
                    <div
                      className={`flex h-10 w-10 items-center justify-center rounded-lg transition-colors ${shortcut.iconBg} ${shortcut.iconText}`}
                    >
                      <shortcut.icon className="h-5 w-5" />
                    </div>
                    <span className="text-center text-xs font-medium text-muted-foreground group-hover:text-foreground">
                      {shortcut.label}
                    </span>
                  </CardContent>
                </Card>
              </Link>
            ))}
          </div>
        </SectionErrorBoundary>
      </PageSection>

      <PageSection delay={0.15}>
        <SectionErrorBoundary name="Message Volume">
          <Card>
            <CardHeader className="space-y-1 pb-2">
              <div className="flex items-center gap-2">
                <TrendingUp className="h-4 w-4 text-muted-foreground" />
                <CardTitle className="text-lg">Message Volume</CardTitle>
              </div>
              <CardDescription>Inbound and outbound fax messages over the last 7 days</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="h-[200px] w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={volumeChartData} margin={{ top: 8, right: 8, bottom: 0, left: -20 }}>
                    <defs>
                      <linearGradient id="faxInboundGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="hsl(var(--primary))" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="hsl(var(--primary))" stopOpacity={0.02} />
                      </linearGradient>
                      <linearGradient id="faxOutboundGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="hsl(var(--chart-2, 220 70% 50%))" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="hsl(var(--chart-2, 220 70% 50%))" stopOpacity={0.02} />
                      </linearGradient>
                    </defs>
                    <XAxis
                      dataKey="label"
                      axisLine={false}
                      tickLine={false}
                      tick={{ fontSize: 12, fill: "hsl(var(--muted-foreground))" }}
                      dy={4}
                    />
                    <YAxis
                      axisLine={false}
                      tickLine={false}
                      tick={{ fontSize: 12, fill: "hsl(var(--muted-foreground))" }}
                      allowDecimals={false}
                    />
                    <RechartsTooltip
                      contentStyle={{
                        backgroundColor: "hsl(var(--popover))",
                        border: "1px solid hsl(var(--border))",
                        borderRadius: "var(--radius)",
                        fontSize: 13,
                        color: "hsl(var(--popover-foreground))",
                      }}
                      labelFormatter={(label) => String(label)}
                    />
                    <Area
                      type="monotone"
                      dataKey="inbound"
                      name="Inbound"
                      stroke="hsl(var(--primary))"
                      strokeWidth={2}
                      fill="url(#faxInboundGradient)"
                      stackId="fax"
                    />
                    <Area
                      type="monotone"
                      dataKey="outbound"
                      name="Outbound"
                      stroke="hsl(var(--chart-2, 220 70% 50%))"
                      strokeWidth={2}
                      fill="url(#faxOutboundGradient)"
                      stackId="fax"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>
        </SectionErrorBoundary>
      </PageSection>

      {!isLoading && messages && messages.items.length > 0 && (
        <PageSection delay={0.35}>
          <SectionErrorBoundary name="Recent Messages">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between">
                <CardTitle className="text-lg">Recent Messages</CardTitle>
                <Link
                  to="/fax/messages"
                  className="text-sm text-primary hover:underline"
                >
                  View all
                </Link>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {messages.items.slice(0, 5).map((msg) => (
                    <Link
                      key={msg.id}
                      to="/fax/messages/$messageId"
                      params={{ messageId: msg.id }}
                      className="group flex items-center gap-3 rounded-lg border border-border/40 p-3 transition-all hover:bg-muted/30 hover:shadow-sm"
                    >
                      <div
                        className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-md ${
                          msg.direction === "inbound"
                            ? "bg-blue-500/10 text-blue-600 dark:text-blue-400"
                            : "bg-violet-500/10 text-violet-600 dark:text-violet-400"
                        }`}
                      >
                        {msg.direction === "inbound" ? (
                          <Inbox className="h-4 w-4" />
                        ) : (
                          <Send className="h-4 w-4" />
                        )}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium">
                          {msg.direction === "inbound" ? "From" : "To"}{" "}
                          <span className="font-mono">{msg.remoteNumber}</span>
                        </p>
                        <p className="text-xs text-muted-foreground">
                          {msg.pageCount} page{msg.pageCount !== 1 ? "s" : ""} &middot;{" "}
                          {formatDateTime(msg.receivedAt, "--")}
                        </p>
                      </div>
                      <span
                        className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${
                          msg.status === "failed"
                            ? "bg-red-500/15 text-red-600 dark:text-red-400"
                            : msg.status === "sending"
                              ? "bg-amber-500/15 text-amber-600 dark:text-amber-400"
                              : "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400"
                        }`}
                      >
                        {msg.status}
                      </span>
                    </Link>
                  ))}
                </div>
              </CardContent>
            </Card>
          </SectionErrorBoundary>
        </PageSection>
      )}
    </PageContainer>
  )
}
