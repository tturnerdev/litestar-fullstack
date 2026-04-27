import { createFileRoute } from "@tanstack/react-router"
import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { DndSettingsForm } from "@/components/voice/dnd-settings-form"
import { ForwardingRuleEditor } from "@/components/voice/forwarding-rule-editor"
import { VoicemailSettingsForm } from "@/components/voice/voicemail-settings-form"
import { useExtension, useUpdateExtension } from "@/lib/api/hooks/voice"

export const Route = createFileRoute("/_app/voice/extensions/$extensionId/")({
  component: ExtensionSettingsPage,
})

function ExtensionSettingsPage() {
  const { extensionId } = Route.useParams()

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader eyebrow="Voice" title="Extension Settings" />
      <PageSection>
        <Tabs defaultValue="general">
          <TabsList>
            <TabsTrigger value="general">General</TabsTrigger>
            <TabsTrigger value="voicemail">Voicemail</TabsTrigger>
            <TabsTrigger value="forwarding">Forwarding</TabsTrigger>
            <TabsTrigger value="dnd">DND</TabsTrigger>
          </TabsList>

          <TabsContent value="general" className="mt-6">
            <GeneralTab extensionId={extensionId} />
          </TabsContent>

          <TabsContent value="voicemail" className="mt-6">
            <VoicemailSettingsForm extensionId={extensionId} />
          </TabsContent>

          <TabsContent value="forwarding" className="mt-6">
            <ForwardingRuleEditor extensionId={extensionId} />
          </TabsContent>

          <TabsContent value="dnd" className="mt-6">
            <DndSettingsForm extensionId={extensionId} />
          </TabsContent>
        </Tabs>
      </PageSection>
    </PageContainer>
  )
}

function GeneralTab({ extensionId }: { extensionId: string }) {
  const { data, isLoading, isError } = useExtension(extensionId)
  const updateMutation = useUpdateExtension(extensionId)
  const [displayName, setDisplayName] = useState("")
  const [dirty, setDirty] = useState(false)

  if (isLoading) return <SkeletonCard />

  if (isError || !data) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>General</CardTitle>
        </CardHeader>
        <CardContent className="text-muted-foreground">Unable to load extension details.</CardContent>
      </Card>
    )
  }

  const currentDisplayName = displayName || data.displayName

  function handleSave() {
    const payload: Record<string, unknown> = {}
    if (displayName) payload.displayName = displayName
    updateMutation.mutate(payload, {
      onSuccess: () => setDirty(false),
    })
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>General Settings</CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="space-y-2">
          <Label>Extension number</Label>
          <Input value={data.extensionNumber} disabled />
        </div>

        <div className="space-y-2">
          <Label htmlFor="ext-display-name">Display name</Label>
          <Input
            id="ext-display-name"
            value={currentDisplayName}
            onChange={(e) => {
              setDisplayName(e.target.value)
              setDirty(true)
            }}
          />
        </div>

        <div className="flex items-center justify-between">
          <Label>Status</Label>
          <span className={data.isActive ? "text-sm font-medium text-green-600" : "text-sm font-medium text-muted-foreground"}>{data.isActive ? "Active" : "Inactive"}</span>
        </div>

        <Button onClick={handleSave} disabled={!dirty || updateMutation.isPending}>
          {updateMutation.isPending ? "Saving..." : "Save changes"}
        </Button>
      </CardContent>
    </Card>
  )
}
