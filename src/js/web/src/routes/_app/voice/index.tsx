import { createFileRoute, Link } from "@tanstack/react-router"
import { ArrowRight, BellOff, Home, Mail, Phone, PhoneForwarded, PhoneOff, TrendingUp, Voicemail } from "lucide-react"
import { useMemo } from "react"
import { Bar, BarChart, CartesianGrid, Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip as RechartsTooltip, XAxis, YAxis } from "recharts"
import { Badge } from "@/components/ui/badge"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Separator } from "@/components/ui/separator"
import { SkeletonCard } from "@/components/ui/skeleton"
import { useDocumentTitle } from "@/hooks/use-document-title"
import {
  useDndSettings,
  useExtensions,
  usePhoneNumbers,
  useVoicemailMessages,
  useVoicemailSettings,
} from "@/lib/api/hooks/voice"
import { useCallQueues, useRingGroups } from "@/lib/api/hooks/call-routing"

export const Route = createFileRoute("/_app/voice/")({
  component: VoiceOverviewPage,
})

function VoiceOverviewPage() {
  useDocumentTitle("Voice")
  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Voice"
        title="Voice Overview"
        description="Manage your phone numbers, extensions, voicemail, forwarding, and DND settings."
        breadcrumbs={<VoiceBreadcrumbs />}
      />
      <PageSection>
        <SummaryCards />
      </PageSection>
      <PageSection delay={0.1}>
        <VoiceResourceCharts />
      </PageSection>
      <PageSection delay={0.15}>
        <StatusOverview />
      </PageSection>
      <PageSection delay={0.25}>
        <div className="space-y-2">
          <h2 className="text-lg font-semibold tracking-tight">Quick Actions</h2>
          <p className="text-sm text-muted-foreground">Jump to the section you need</p>
        </div>
        <QuickLinks />
      </PageSection>
      <PageSection delay={0.35}>
        <RecentExtensions />
      </PageSection>
    </PageContainer>
  )
}

// ---------------------------------------------------------------------------
// Breadcrumbs
// ---------------------------------------------------------------------------

function VoiceBreadcrumbs() {
  return (
    <Breadcrumb>
      <BreadcrumbList>
        <BreadcrumbItem>
          <BreadcrumbLink asChild>
            <Link to="/home">
              <Home className="h-3.5 w-3.5" />
            </Link>
          </BreadcrumbLink>
        </BreadcrumbItem>
        <BreadcrumbSeparator />
        <BreadcrumbItem>
          <BreadcrumbPage>Voice</BreadcrumbPage>
        </BreadcrumbItem>
      </BreadcrumbList>
    </Breadcrumb>
  )
}

// ---------------------------------------------------------------------------
// Summary Stat Cards
// ---------------------------------------------------------------------------

function SummaryCards() {
  const { data: phoneData, isLoading: phonesLoading } = usePhoneNumbers(1, 100)
  const { data: extData, isLoading: extsLoading } = useExtensions(1, 100)

  if (phonesLoading || extsLoading) {
    return (
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {Array.from({ length: 4 }).map((_, index) => (
          // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
          <SkeletonCard key={`voice-skeleton-${index}`} />
        ))}
      </div>
    )
  }

  const phoneCount = phoneData?.total ?? 0
  const extCount = extData?.total ?? 0
  const activePhones = phoneData?.items.filter((p) => p.isActive).length ?? 0
  const activeExts = extData?.items.filter((e) => e.isActive).length ?? 0

  return (
    <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">Phone Numbers</CardTitle>
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-500/10">
            <Phone className="h-4 w-4 text-blue-500" />
          </div>
        </CardHeader>
        <CardContent>
          <div className="text-3xl font-semibold">{phoneCount}</div>
          <p className="text-xs text-muted-foreground">
            {activePhones} active{phoneCount > 0 && ` of ${phoneCount}`}
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">Extensions</CardTitle>
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-green-500/10">
            <PhoneForwarded className="h-4 w-4 text-green-500" />
          </div>
        </CardHeader>
        <CardContent>
          <div className="text-3xl font-semibold">{extCount}</div>
          <p className="text-xs text-muted-foreground">
            {activeExts} active{extCount > 0 && ` of ${extCount}`}
          </p>
        </CardContent>
      </Card>

      {extData && extData.items.length > 0 ? (
        <VoicemailSummaryCard extensionId={extData.items[0].id} />
      ) : (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Voicemail</CardTitle>
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-purple-500/10">
              <Voicemail className="h-4 w-4 text-purple-500" />
            </div>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-semibold">--</div>
            <p className="text-xs text-muted-foreground">No extensions</p>
          </CardContent>
        </Card>
      )}

      {extData && extData.items.length > 0 ? (
        <DndSummaryCard extensionId={extData.items[0].id} />
      ) : (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">DND Status</CardTitle>
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-orange-500/10">
              <BellOff className="h-4 w-4 text-orange-500" />
            </div>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-semibold">--</div>
            <p className="text-xs text-muted-foreground">No extensions</p>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

function VoicemailSummaryCard({ extensionId }: { extensionId: string }) {
  const { data: vmSettings } = useVoicemailSettings(extensionId)
  const { data: vmMessages } = useVoicemailMessages(extensionId, 1, 100)

  const unreadCount = vmMessages?.items.filter((m) => !m.isRead).length ?? 0
  const totalCount = vmMessages?.total ?? 0
  const isEnabled = vmSettings?.isEnabled ?? false

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">Voicemail</CardTitle>
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-purple-500/10">
          <Voicemail className="h-4 w-4 text-purple-500" />
        </div>
      </CardHeader>
      <CardContent>
        <div className="text-3xl font-semibold">{unreadCount > 0 ? unreadCount : totalCount}</div>
        <p className="text-xs text-muted-foreground">
          {unreadCount > 0 ? `${unreadCount} unread of ${totalCount}` : `${totalCount} total messages`}
        </p>
        {!isEnabled && (
          <Badge variant="outline" className="mt-1 text-xs">
            Disabled
          </Badge>
        )}
      </CardContent>
    </Card>
  )
}

function DndSummaryCard({ extensionId }: { extensionId: string }) {
  const { data } = useDndSettings(extensionId)

  const isEnabled = data?.isEnabled ?? false
  const mode = data?.mode ?? "off"

  const modeLabels: Record<string, string> = {
    always: "Always on",
    scheduled: "Scheduled",
    off: "Off",
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">DND Status</CardTitle>
        <div className={`flex h-8 w-8 items-center justify-center rounded-lg ${isEnabled ? "bg-destructive/10" : "bg-orange-500/10"}`}>
          <BellOff className={`h-4 w-4 ${isEnabled ? "text-destructive" : "text-orange-500"}`} />
        </div>
      </CardHeader>
      <CardContent>
        <div className="text-3xl font-semibold">{isEnabled ? "On" : "Off"}</div>
        <p className="text-xs text-muted-foreground">{modeLabels[mode] ?? mode}</p>
      </CardContent>
    </Card>
  )
}

// ---------------------------------------------------------------------------
// Voice Resource Charts
// ---------------------------------------------------------------------------

const PIE_COLORS = [
  "hsl(var(--primary))",
  "hsl(var(--chart-2, 220 70% 50%))",
  "hsl(var(--chart-3, 30 80% 55%))",
  "hsl(var(--chart-4, 280 65% 60%))",
  "hsl(var(--chart-5, 160 60% 45%))",
]

function VoiceResourceCharts() {
  const { data: phoneData, isLoading: phonesLoading } = usePhoneNumbers(1, 100)
  const { data: extData, isLoading: extsLoading } = useExtensions(1, 100)
  const { data: queueData, isLoading: queuesLoading } = useCallQueues({ page: 1, pageSize: 100 })
  const { data: ringGroupData, isLoading: ringsLoading } = useRingGroups({ page: 1, pageSize: 100 })

  const isLoading = phonesLoading || extsLoading || queuesLoading || ringsLoading

  const resourceBarData = useMemo(() => {
    if (isLoading) return []
    return [
      {
        name: "Phone Numbers",
        active: phoneData?.items.filter((p) => p.isActive).length ?? 0,
        inactive: (phoneData?.total ?? 0) - (phoneData?.items.filter((p) => p.isActive).length ?? 0),
      },
      {
        name: "Extensions",
        active: extData?.items.filter((e) => e.isActive).length ?? 0,
        inactive: (extData?.total ?? 0) - (extData?.items.filter((e) => e.isActive).length ?? 0),
      },
      {
        name: "Call Queues",
        active: queueData?.total ?? 0,
        inactive: 0,
      },
      {
        name: "Ring Groups",
        active: ringGroupData?.total ?? 0,
        inactive: 0,
      },
    ]
  }, [isLoading, phoneData, extData, queueData, ringGroupData])

  const distributionData = useMemo(() => {
    if (isLoading) return []
    const items = [
      { name: "Phone Numbers", value: phoneData?.total ?? 0 },
      { name: "Extensions", value: extData?.total ?? 0 },
      { name: "Call Queues", value: queueData?.total ?? 0 },
      { name: "Ring Groups", value: ringGroupData?.total ?? 0 },
    ]
    return items.filter((item) => item.value > 0)
  }, [isLoading, phoneData, extData, queueData, ringGroupData])

  const totalResources = distributionData.reduce((sum, d) => sum + d.value, 0)

  if (isLoading) {
    return (
      <div className="grid gap-4 lg:grid-cols-2">
        <SkeletonCard className="h-[320px]" />
        <SkeletonCard className="h-[320px]" />
      </div>
    )
  }

  if (totalResources === 0) return null

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader className="space-y-1 pb-2">
          <div className="flex items-center gap-2">
            <TrendingUp className="h-4 w-4 text-muted-foreground" />
            <CardTitle className="text-lg">Resource Status</CardTitle>
          </div>
          <CardDescription>Active vs. inactive count across voice resource types</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-[220px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={resourceBarData} layout="vertical" margin={{ top: 4, right: 12, bottom: 0, left: 0 }}>
                <CartesianGrid horizontal={false} strokeDasharray="3 3" stroke="hsl(var(--border))" />
                <XAxis
                  type="number"
                  axisLine={false}
                  tickLine={false}
                  tick={{ fontSize: 12, fill: "hsl(var(--muted-foreground))" }}
                  allowDecimals={false}
                />
                <YAxis
                  dataKey="name"
                  type="category"
                  axisLine={false}
                  tickLine={false}
                  tick={{ fontSize: 12, fill: "hsl(var(--muted-foreground))" }}
                  width={100}
                />
                <RechartsTooltip
                  contentStyle={{
                    backgroundColor: "hsl(var(--popover))",
                    border: "1px solid hsl(var(--border))",
                    borderRadius: "var(--radius)",
                    fontSize: 13,
                    color: "hsl(var(--popover-foreground))",
                  }}
                />
                <Legend
                  verticalAlign="top"
                  align="right"
                  iconType="circle"
                  iconSize={8}
                  wrapperStyle={{ fontSize: 12, paddingBottom: 8 }}
                />
                <Bar dataKey="active" name="Active" stackId="status" fill="hsl(142 71% 45%)" radius={[0, 0, 0, 0]} />
                <Bar dataKey="inactive" name="Inactive" stackId="status" fill="hsl(var(--muted-foreground) / 0.3)" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="space-y-1 pb-2">
          <div className="flex items-center gap-2">
            <Phone className="h-4 w-4 text-muted-foreground" />
            <CardTitle className="text-lg">Resource Distribution</CardTitle>
          </div>
          <CardDescription>
            {totalResources} total resource{totalResources !== 1 ? "s" : ""} provisioned
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-6">
            <div className="h-[200px] w-[200px] shrink-0">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={distributionData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={85}
                    paddingAngle={2}
                    strokeWidth={0}
                  >
                    {distributionData.map((_entry, index) => (
                      // biome-ignore lint/suspicious/noArrayIndexKey: Static pie segments
                      <Cell key={`pie-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                    ))}
                  </Pie>
                  <RechartsTooltip
                    contentStyle={{
                      backgroundColor: "hsl(var(--popover))",
                      border: "1px solid hsl(var(--border))",
                      borderRadius: "var(--radius)",
                      fontSize: 13,
                      color: "hsl(var(--popover-foreground))",
                    }}
                    formatter={(value) => [String(value), ""]}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="flex flex-col gap-2.5">
              {distributionData.map((entry, index) => (
                <div key={entry.name} className="flex items-center gap-2.5">
                  <span
                    className="inline-block h-3 w-3 shrink-0 rounded-full"
                    style={{ backgroundColor: PIE_COLORS[index % PIE_COLORS.length] }}
                  />
                  <span className="text-sm text-muted-foreground">{entry.name}</span>
                  <span className="ml-auto text-sm font-semibold tabular-nums">{entry.value}</span>
                </div>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Status Overview
// ---------------------------------------------------------------------------

function StatusOverview() {
  const { data: phoneData, isLoading: phonesLoading } = usePhoneNumbers(1, 100)
  const { data: extData, isLoading: extsLoading } = useExtensions(1, 100)

  if (phonesLoading || extsLoading) {
    return null
  }

  const activePhones = phoneData?.items.filter((p) => p.isActive).length ?? 0
  const inactivePhones = (phoneData?.total ?? 0) - activePhones
  const activeExts = extData?.items.filter((e) => e.isActive).length ?? 0
  const inactiveExts = (extData?.total ?? 0) - activeExts
  const totalPhones = phoneData?.total ?? 0
  const totalExts = extData?.total ?? 0

  if (totalPhones === 0 && totalExts === 0) return null

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Status Overview</CardTitle>
        <CardDescription>Active vs. inactive breakdown across your voice resources</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="grid gap-6 sm:grid-cols-2">
          {totalPhones > 0 && (
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <Phone className="h-4 w-4 text-blue-500" />
                <span className="text-sm font-medium">Phone Numbers</span>
              </div>
              <div className="space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">Active</span>
                  <span className="font-medium text-green-600">{activePhones}</span>
                </div>
                <div className="h-2 overflow-hidden rounded-full bg-muted">
                  <div
                    className="h-full rounded-full bg-green-500 transition-all duration-500"
                    style={{ width: totalPhones > 0 ? `${(activePhones / totalPhones) * 100}%` : "0%" }}
                  />
                </div>
                {inactivePhones > 0 && (
                  <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                    <PhoneOff className="h-3 w-3" />
                    {inactivePhones} inactive
                  </div>
                )}
              </div>
            </div>
          )}
          {totalPhones > 0 && totalExts > 0 && <Separator className="sm:hidden" />}
          {totalExts > 0 && (
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <PhoneForwarded className="h-4 w-4 text-green-500" />
                <span className="text-sm font-medium">Extensions</span>
              </div>
              <div className="space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">Active</span>
                  <span className="font-medium text-green-600">{activeExts}</span>
                </div>
                <div className="h-2 overflow-hidden rounded-full bg-muted">
                  <div
                    className="h-full rounded-full bg-green-500 transition-all duration-500"
                    style={{ width: totalExts > 0 ? `${(activeExts / totalExts) * 100}%` : "0%" }}
                  />
                </div>
                {inactiveExts > 0 && (
                  <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                    <PhoneOff className="h-3 w-3" />
                    {inactiveExts} inactive
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  )
}

// ---------------------------------------------------------------------------
// Quick Action Cards
// ---------------------------------------------------------------------------

function QuickLinks() {
  const links = [
    {
      label: "Phone Numbers",
      description: "View and manage your assigned phone numbers, labels, and caller ID settings.",
      to: "/voice/phone-numbers" as const,
      icon: Phone,
      color: "text-blue-500",
      bg: "bg-blue-500/10",
    },
    {
      label: "Extensions",
      description: "Configure extensions, voicemail, forwarding rules, and DND schedules.",
      to: "/voice/extensions" as const,
      icon: PhoneForwarded,
      color: "text-green-500",
      bg: "bg-green-500/10",
    },
  ]

  return (
    <div className="grid gap-4 md:grid-cols-2">
      {links.map((link) => (
        <Card key={link.to} hover>
          <CardHeader className="flex flex-row items-center gap-3">
            <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg ${link.bg}`}>
              <link.icon className={`h-5 w-5 ${link.color}`} />
            </div>
            <div className="min-w-0">
              <CardTitle className="text-base">{link.label}</CardTitle>
              <CardDescription>{link.description}</CardDescription>
            </div>
          </CardHeader>
          <CardContent className="flex items-center justify-end">
            <Button asChild variant="outline" size="sm">
              <Link to={link.to}>
                Manage <ArrowRight className="ml-2 h-4 w-4" />
              </Link>
            </Button>
          </CardContent>
        </Card>
      ))}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Recent Extensions
// ---------------------------------------------------------------------------

function RecentExtensions() {
  const { data, isLoading } = useExtensions(1, 5)

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="space-y-2">
          <h2 className="text-lg font-semibold tracking-tight">Recent Extensions</h2>
          <p className="text-sm text-muted-foreground">Your most recent extension configurations</p>
        </div>
        <div className="grid gap-3">
          {Array.from({ length: 3 }).map((_, index) => (
            // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
            <SkeletonCard key={`ext-skeleton-${index}`} />
          ))}
        </div>
      </div>
    )
  }

  if (!data || data.items.length === 0) return null

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="space-y-1">
          <h2 className="text-lg font-semibold tracking-tight">Recent Extensions</h2>
          <p className="text-sm text-muted-foreground">Your most recent extension configurations</p>
        </div>
        <Button variant="ghost" size="sm" asChild>
          <Link to="/voice/extensions">
            View all <ArrowRight className="ml-1.5 h-3.5 w-3.5" />
          </Link>
        </Button>
      </div>
      <div className="grid gap-3">
        {data.items.map((ext) => (
          <ExtensionRow key={ext.id} extensionId={ext.id} displayName={ext.displayName} extensionNumber={ext.extensionNumber} isActive={ext.isActive} />
        ))}
      </div>
    </div>
  )
}

function ExtensionRow({
  extensionId,
  displayName,
  extensionNumber,
  isActive,
}: {
  extensionId: string
  displayName: string
  extensionNumber: string
  isActive: boolean
}) {
  const { data: dndData } = useDndSettings(extensionId)
  const { data: vmData } = useVoicemailMessages(extensionId, 1, 5)

  const unreadCount = vmData?.items.filter((m) => !m.isRead).length ?? 0
  const dndEnabled = dndData?.isEnabled ?? false

  return (
    <Card>
      <CardContent className="flex items-center justify-between py-4">
        <div className="flex items-center gap-4">
          <div className={`flex h-10 w-10 items-center justify-center rounded-lg ${isActive ? "bg-green-500/10" : "bg-muted"}`}>
            <PhoneForwarded className={`h-5 w-5 ${isActive ? "text-green-500" : "text-muted-foreground"}`} />
          </div>
          <div>
            <p className="font-medium">{displayName}</p>
            <p className="font-mono text-sm text-muted-foreground">Ext. {extensionNumber}</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {unreadCount > 0 && (
            <Badge variant="secondary" className="gap-1">
              <Mail className="h-3 w-3" />
              {unreadCount}
            </Badge>
          )}
          {dndEnabled && (
            <Badge variant="destructive" className="gap-1">
              <BellOff className="h-3 w-3" />
              DND
            </Badge>
          )}
          <Badge variant={isActive ? "default" : "outline"}>{isActive ? "Active" : "Inactive"}</Badge>
          <Button variant="outline" size="sm" asChild>
            <Link to="/voice/extensions/$extensionId" params={{ extensionId }}>
              Settings
            </Link>
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}
