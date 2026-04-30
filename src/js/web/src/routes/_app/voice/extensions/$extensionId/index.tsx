import { createFileRoute, Link, useRouter } from "@tanstack/react-router"
import { AlertTriangle, ArrowLeft, ArrowRight, BellOff, Loader2, Mail, Pencil, PhoneForwarded, Trash2, Voicemail } from "lucide-react"
import { useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { DndQuickToggle } from "@/components/voice/dnd-quick-toggle"
import { DndSettingsForm } from "@/components/voice/dnd-settings-form"
import { ForwardingRuleEditor } from "@/components/voice/forwarding-rule-editor"
import { VoicemailSettingsForm } from "@/components/voice/voicemail-settings-form"
import {
  useDeleteExtension,
  useDndSettings,
  useExtension,
  useForwardingRules,
  useUpdateExtension,
  useVoicemailMessages,
  useVoicemailSettings,
} from "@/lib/api/hooks/voice"

export const Route = createFileRoute("/_app/voice/extensions/$extensionId/")({
  component: ExtensionSettingsPage,
})

function ExtensionSettingsPage() {
  const { extensionId } = Route.useParams()
  const router = useRouter()
  const { data } = useExtension(extensionId)
  const deleteExtension = useDeleteExtension()
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)

  const title = data ? `${data.displayName} (Ext. ${data.extensionNumber})` : "Extension Settings"

  const handleDelete = async () => {
    await deleteExtension.mutateAsync(extensionId)
    router.navigate({ to: "/voice/extensions" })
  }

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Voice"
        title={title}
        actions={
          <div className="flex items-center gap-2">
            <DndQuickToggle extensionId={extensionId} showLabel />
            <Button variant="outline" size="sm" asChild>
              <Link to="/voice/extensions/$extensionId/edit" params={{ extensionId }}>
                <Pencil className="mr-2 h-4 w-4" />
                Edit
              </Link>
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="text-destructive hover:bg-destructive hover:text-destructive-foreground"
              onClick={() => setShowDeleteDialog(true)}
            >
              <Trash2 className="mr-2 h-4 w-4" />
              Delete
            </Button>
            <Button variant="outline" size="sm" asChild>
              <Link to="/voice/extensions">
                <ArrowLeft className="mr-2 h-4 w-4" /> All Extensions
              </Link>
            </Button>
          </div>
        }
      />

      <PageSection>
        <SubPageLinks extensionId={extensionId} />
      </PageSection>

      <PageSection delay={0.1}>
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

      <Dialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-destructive" />
              Delete Extension
            </DialogTitle>
            <DialogDescription>
              Are you sure you want to delete{" "}
              <span className="font-medium">{data?.displayName}</span>
              {data?.extensionNumber && (
                <> (Ext. <span className="font-mono">{data.extensionNumber}</span>)</>
              )}
              ? This action cannot be undone. All associated forwarding rules, voicemail, and DND settings will be permanently removed.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowDeleteDialog(false)} disabled={deleteExtension.isPending}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleDelete}
              disabled={deleteExtension.isPending}
            >
              {deleteExtension.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </PageContainer>
  )
}

function SubPageLinks({ extensionId }: { extensionId: string }) {
  const { data: vmSettings } = useVoicemailSettings(extensionId)
  const { data: vmMessages } = useVoicemailMessages(extensionId, 1, 5)
  const { data: fwdRules } = useForwardingRules(extensionId)
  const { data: dndSettings } = useDndSettings(extensionId)

  const unreadCount = vmMessages?.items.filter((m) => !m.isRead).length ?? 0
  const totalMessages = vmMessages?.total ?? 0
  const ruleCount = fwdRules?.items?.length ?? 0
  const activeRules = fwdRules?.items?.filter((r) => r.isActive).length ?? 0
  const dndEnabled = dndSettings?.isEnabled ?? false
  const vmEnabled = vmSettings?.isEnabled ?? false

  const subPages = [
    {
      label: "Voicemail",
      description: vmEnabled
        ? unreadCount > 0
          ? `${unreadCount} unread of ${totalMessages} messages`
          : `${totalMessages} messages`
        : "Voicemail disabled",
      to: "/voice/extensions/$extensionId/voicemail" as const,
      icon: Voicemail,
      badge: unreadCount > 0 ? (
        <Badge variant="secondary" className="gap-1">
          <Mail className="h-3 w-3" />
          {unreadCount}
        </Badge>
      ) : null,
    },
    {
      label: "Call Forwarding",
      description: ruleCount > 0
        ? `${activeRules} of ${ruleCount} rules active`
        : "No forwarding rules configured",
      to: "/voice/extensions/$extensionId/forwarding" as const,
      icon: PhoneForwarded,
      badge: ruleCount > 0 ? (
        <Badge variant="secondary">{ruleCount} rules</Badge>
      ) : null,
    },
    {
      label: "Do Not Disturb",
      description: dndEnabled
        ? `DND is active (${dndSettings?.mode ?? "always"})`
        : "DND is off",
      to: "/voice/extensions/$extensionId/dnd" as const,
      icon: BellOff,
      badge: dndEnabled ? (
        <Badge variant="destructive" className="gap-1">
          <BellOff className="h-3 w-3" />
          Active
        </Badge>
      ) : null,
    },
  ]

  return (
    <div className="grid gap-3 md:grid-cols-3">
      {subPages.map((page) => (
        <Card key={page.to} hover>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <div className="flex items-center gap-3">
              <page.icon className="h-5 w-5 text-muted-foreground" />
              <CardTitle className="text-sm">{page.label}</CardTitle>
            </div>
            {page.badge}
          </CardHeader>
          <CardContent className="flex items-center justify-between">
            <CardDescription className="text-xs">{page.description}</CardDescription>
            <Button variant="ghost" size="sm" asChild>
              <Link to={page.to} params={{ extensionId }}>
                <ArrowRight className="h-4 w-4" />
              </Link>
            </Button>
          </CardContent>
        </Card>
      ))}
    </div>
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
        <CardDescription>Basic configuration for this extension.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="space-y-2">
          <Label>Extension number</Label>
          <Input value={data.extensionNumber} disabled />
        </div>

        <div className="space-y-2">
          <Label htmlFor="ext-display-name">Display name</Label>
          <p className="text-xs text-muted-foreground">This name appears in the directory and call logs.</p>
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
          <div>
            <Label>Status</Label>
            <p className="text-xs text-muted-foreground">Whether this extension can receive calls.</p>
          </div>
          <Badge variant={data.isActive ? "default" : "outline"}>
            {data.isActive ? "Active" : "Inactive"}
          </Badge>
        </div>

        {data.phoneNumberId && (
          <div className="flex items-center justify-between">
            <div>
              <Label>Linked phone number</Label>
              <p className="text-xs text-muted-foreground">A DID number routes directly to this extension.</p>
            </div>
            <Badge variant="secondary">Assigned</Badge>
          </div>
        )}

        <Button onClick={handleSave} disabled={!dirty || updateMutation.isPending}>
          {updateMutation.isPending ? "Saving..." : "Save changes"}
        </Button>
      </CardContent>
    </Card>
  )
}
