import { createFileRoute, Link } from "@tanstack/react-router"
import { ArrowLeft } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { VoicemailMessageList } from "@/components/voice/voicemail-message-list"
import { VoicemailSettingsForm } from "@/components/voice/voicemail-settings-form"
import { useVoicemailMessages, useVoicemailSettings } from "@/lib/api/hooks/voice"

export const Route = createFileRoute("/_app/voice/extensions/$extensionId/voicemail")({
  component: VoicemailPage,
})

function VoicemailPage() {
  const { extensionId } = Route.useParams()
  const { data: vmMessages } = useVoicemailMessages(extensionId, 1, 100)
  const { data: vmSettings } = useVoicemailSettings(extensionId)

  const unreadCount = vmMessages?.items.filter((m) => !m.isRead).length ?? 0
  const totalCount = vmMessages?.total ?? 0
  const isEnabled = vmSettings?.isEnabled ?? false

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Voice"
        title="Voicemail"
        description="Manage voicemail settings and listen to messages."
        actions={
          <div className="flex items-center gap-2">
            {!isEnabled && (
              <Badge variant="outline">Voicemail disabled</Badge>
            )}
            {unreadCount > 0 && (
              <Badge variant="secondary">{unreadCount} unread</Badge>
            )}
            <Button variant="outline" size="sm" asChild>
              <Link to="/voice/extensions/$extensionId" params={{ extensionId }}>
                <ArrowLeft className="mr-2 h-4 w-4" /> Back to Extension
              </Link>
            </Button>
          </div>
        }
      />
      <PageSection>
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
      </PageSection>
    </PageContainer>
  )
}
