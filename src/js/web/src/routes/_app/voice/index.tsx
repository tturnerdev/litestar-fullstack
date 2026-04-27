import { createFileRoute, Link } from "@tanstack/react-router"
import { ArrowRight, Phone, PhoneForwarded, Voicemail } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonCard } from "@/components/ui/skeleton"
import { useExtensions, usePhoneNumbers } from "@/lib/api/hooks/voice"

export const Route = createFileRoute("/_app/voice/")({
  component: VoiceOverviewPage,
})

function VoiceOverviewPage() {
  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader eyebrow="Voice" title="Voice Settings" description="Manage your phone numbers, extensions, voicemail, forwarding, and DND." />
      <PageSection>
        <SummaryCards />
      </PageSection>
      <PageSection delay={0.1}>
        <QuickLinks />
      </PageSection>
    </PageContainer>
  )
}

function SummaryCards() {
  const { data: phoneData, isLoading: phonesLoading } = usePhoneNumbers(1, 1)
  const { data: extData, isLoading: extsLoading } = useExtensions(1, 1)

  if (phonesLoading || extsLoading) {
    return (
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {Array.from({ length: 3 }).map((_, index) => (
          // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
          <SkeletonCard key={`voice-skeleton-${index}`} />
        ))}
      </div>
    )
  }

  const items = [
    { label: "Phone Numbers", value: phoneData?.total ?? 0, icon: Phone },
    { label: "Extensions", value: extData?.total ?? 0, icon: PhoneForwarded },
    { label: "Voicemail Boxes", value: extData?.total ?? 0, icon: Voicemail },
  ]

  return (
    <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
      {items.map((item) => (
        <Card key={item.label}>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle className="text-sm text-muted-foreground">{item.label}</CardTitle>
            <item.icon className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-semibold">{item.value}</div>
          </CardContent>
        </Card>
      ))}
    </div>
  )
}

function QuickLinks() {
  const links = [
    { label: "Phone Numbers", description: "View and manage your assigned phone numbers", to: "/voice/phone-numbers" },
    { label: "Extensions", description: "Configure extensions, voicemail, forwarding and DND", to: "/voice/extensions" },
  ]

  return (
    <div className="grid gap-4 md:grid-cols-2">
      {links.map((link) => (
        <Card key={link.to} hover>
          <CardHeader>
            <CardTitle>{link.label}</CardTitle>
          </CardHeader>
          <CardContent className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">{link.description}</p>
            <Button asChild variant="ghost" size="sm">
              <Link to={link.to}>
                <ArrowRight className="h-4 w-4" />
              </Link>
            </Button>
          </CardContent>
        </Card>
      ))}
    </div>
  )
}
