import { createFileRoute, Link } from "@tanstack/react-router"
import { ArrowLeft, Voicemail } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { VoicemailMessageList } from "@/components/voice/voicemail-message-list"
import { VoicemailSettingsForm } from "@/components/voice/voicemail-settings-form"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { useExtension, useVoicemailMessages, useVoicemailSettings } from "@/lib/api/hooks/voice"

export const Route = createFileRoute("/_app/voice/extensions/$extensionId/voicemail")({
  component: VoicemailPage,
})

function VoicemailPage() {
  useDocumentTitle("Voicemail Settings")
  const { extensionId } = Route.useParams()
  const { data: extension, isLoading: extLoading } = useExtension(extensionId)
  const { data: vmMessages, isLoading: msgsLoading } = useVoicemailMessages(extensionId, 1, 100)
  const { data: vmSettings, isLoading: settingsLoading } = useVoicemailSettings(extensionId)

  const isLoading = extLoading || msgsLoading || settingsLoading
  const unreadCount = vmMessages?.items.filter((m) => !m.isRead).length ?? 0
  const totalCount = vmMessages?.total ?? 0
  const isEnabled = vmSettings?.isEnabled ?? false
  const extensionName = extension?.displayName ?? "Extension"

  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader eyebrow="Voice" title="Voicemail" />
        <PageSection>
          <SkeletonCard />
        </PageSection>
      </PageContainer>
    )
  }

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Voice"
        title="Voicemail"
        description={`Manage voicemail settings and messages for ${extensionName}.`}
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
                  <Link to="/voice/extensions">Extensions</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbLink asChild>
                  <Link to="/voice/extensions/$extensionId" params={{ extensionId }}>
                    {extensionName}
                  </Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbPage>Voicemail</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
        actions={
          <div className="flex items-center gap-2">
            {!isEnabled && (
              <Badge variant="outline" className="gap-1.5">
                <Voicemail className="h-3 w-3" />
                Disabled
              </Badge>
            )}
            {isEnabled && unreadCount > 0 && <Badge variant="secondary">{unreadCount} unread</Badge>}
            {isEnabled && unreadCount === 0 && totalCount > 0 && <Badge variant="outline">{totalCount} messages</Badge>}
            <Button variant="outline" size="sm" asChild>
              <Link to="/voice/extensions/$extensionId" params={{ extensionId }}>
                <ArrowLeft className="mr-2 h-4 w-4" /> Back to Extension
              </Link>
            </Button>
          </div>
        }
      />

      <PageSection>
        <SectionErrorBoundary name="Voicemail">
          <Tabs defaultValue="messages">
            <TabsList>
              <TabsTrigger value="messages" className="gap-2">
                Messages
                {totalCount > 0 && (
                  <Badge variant="secondary" className="ml-1 h-5 px-1.5 text-xs">
                    {totalCount}
                  </Badge>
                )}
              </TabsTrigger>
              <TabsTrigger value="settings">Settings</TabsTrigger>
            </TabsList>

            <TabsContent value="messages" className="mt-6">
              <VoicemailMessageList extensionId={extensionId} />
            </TabsContent>

            <TabsContent value="settings" className="mt-6">
              <VoicemailSettingsForm extensionId={extensionId} />
            </TabsContent>
          </Tabs>
        </SectionErrorBoundary>
      </PageSection>
    </PageContainer>
  )
}
