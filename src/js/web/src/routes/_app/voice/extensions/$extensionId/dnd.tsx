import { createFileRoute, Link } from "@tanstack/react-router"
import { ArrowLeft } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { DndQuickToggle } from "@/components/voice/dnd-quick-toggle"
import { DndSettingsForm } from "@/components/voice/dnd-settings-form"
import { useDndSettings } from "@/lib/api/hooks/voice"

export const Route = createFileRoute("/_app/voice/extensions/$extensionId/dnd")({
  component: DndPage,
})

function DndPage() {
  const { extensionId } = Route.useParams()
  const { data } = useDndSettings(extensionId)

  const isEnabled = data?.isEnabled ?? false
  const mode = data?.mode ?? "off"

  const modeLabels: Record<string, string> = {
    off: "Off",
    always: "Always",
    scheduled: "Scheduled",
  }

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Voice"
        title="Do Not Disturb"
        description="Configure when calls should be silenced."
        actions={
          <div className="flex items-center gap-2">
            <Badge variant={isEnabled ? "destructive" : "secondary"}>
              {isEnabled ? "DND Active" : "DND Inactive"}
            </Badge>
            {mode !== "off" && (
              <Badge variant="outline">Mode: {modeLabels[mode]}</Badge>
            )}
            <DndQuickToggle extensionId={extensionId} showLabel />
            <Button variant="outline" size="sm" asChild>
              <Link to="/voice/extensions/$extensionId" params={{ extensionId }}>
                <ArrowLeft className="mr-2 h-4 w-4" /> Back to Extension
              </Link>
            </Button>
          </div>
        }
      />
      <PageSection>
        <DndSettingsForm extensionId={extensionId} />
      </PageSection>
    </PageContainer>
  )
}
