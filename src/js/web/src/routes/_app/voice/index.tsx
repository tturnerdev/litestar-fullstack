import { createFileRoute, Link } from "@tanstack/react-router"
import { ArrowRight, BellOff, Mail, Phone, PhoneForwarded, Voicemail } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonCard } from "@/components/ui/skeleton"
import {
  useDndSettings,
  useExtensions,
  usePhoneNumbers,
  useVoicemailMessages,
  useVoicemailSettings,
} from "@/lib/api/hooks/voice"

export const Route = createFileRoute("/_app/voice/")({
  component: VoiceOverviewPage,
})

function VoiceOverviewPage() {
  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Voice"
        title="Voice Settings"
        description="Manage your phone numbers, extensions, voicemail, forwarding, and DND."
      />
      <PageSection>
        <SummaryCards />
      </PageSection>
      <PageSection delay={0.1}>
        <h2 className="text-lg font-semibold">Quick Access</h2>
        <QuickLinks />
      </PageSection>
      <PageSection delay={0.2}>
        <RecentExtensions />
      </PageSection>
    </PageContainer>
  )
}

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
          <p className="text-xs text-muted-foreground">{activePhones} active</p>
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
          <p className="text-xs text-muted-foreground">{activeExts} active</p>
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

function QuickLinks() {
  const links = [
    {
      label: "Phone Numbers",
      description: "View and manage your assigned phone numbers, labels, and caller ID settings.",
      to: "/voice/phone-numbers" as const,
      icon: Phone,
    },
    {
      label: "Extensions",
      description: "Configure extensions, voicemail, forwarding rules, and DND schedules.",
      to: "/voice/extensions" as const,
      icon: PhoneForwarded,
    },
  ]

  return (
    <div className="grid gap-4 md:grid-cols-2">
      {links.map((link) => (
        <Card key={link.to} hover>
          <CardHeader className="flex flex-row items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
              <link.icon className="h-5 w-5 text-primary" />
            </div>
            <div>
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

function RecentExtensions() {
  const { data, isLoading } = useExtensions(1, 5)

  if (isLoading) {
    return (
      <div className="space-y-4">
        <h2 className="text-lg font-semibold">Your Extensions</h2>
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
        <h2 className="text-lg font-semibold">Your Extensions</h2>
        <Button variant="ghost" size="sm" asChild>
          <Link to="/voice/extensions">View all</Link>
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
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-muted">
            <PhoneForwarded className="h-5 w-5 text-muted-foreground" />
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
