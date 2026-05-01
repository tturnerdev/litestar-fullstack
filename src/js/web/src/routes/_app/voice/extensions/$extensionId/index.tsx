import { createFileRoute, Link, useRouter } from "@tanstack/react-router"
import { useEffect, useState, useCallback } from "react"
import { z } from "zod"
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  BellOff,
  Check,
  ExternalLink,
  Fingerprint,
  Inbox,
  Loader2,
  Mail,
  Pencil,
  Phone,
  PhoneForwarded,
  Settings,
  Trash2,
  Voicemail,
} from "lucide-react"
import { ExternalDataTab } from "@/components/gateway/external-data-tab"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
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
import { Skeleton } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { CopyButton } from "@/components/ui/copy-button"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { EntityActivityPanel } from "@/components/shared/entity-activity-panel"
import { DeleteExtensionDialog } from "@/components/voice/delete-extension-dialog"
import { DndQuickToggle } from "@/components/voice/dnd-quick-toggle"
import { EditExtensionDialog } from "@/components/voice/edit-extension-dialog"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"
import {
  type Extension as ExtensionType,
  useDndSettings,
  useExtension,
  useForwardingRules,
  useUpdateExtension,
  useVoicemailMessages,
  useVoicemailSettings,
} from "@/lib/api/hooks/voice"
import { useGatewayLookupExtension } from "@/lib/api/hooks/gateway"
import { formatDuration } from "@/lib/format-utils"

const searchSchema = z.object({
  tab: z.string().optional(),
  edit: z.boolean().optional(),
})

export const Route = createFileRoute("/_app/voice/extensions/$extensionId/")({
  component: ExtensionDetailPage,
  validateSearch: searchSchema,
})


// -- Timestamp with tooltip ---------------------------------------------------

function TimestampField({
  label,
  value,
}: {
  label: string
  value: string | null | undefined
}) {
  if (!value) {
    return (
      <div>
        <p className="text-sm text-muted-foreground">{label}</p>
        <p className="text-sm">---</p>
      </div>
    )
  }

  return (
    <div>
      <p className="text-sm text-muted-foreground">{label}</p>
      <Tooltip>
        <TooltipTrigger asChild>
          <p className="cursor-default text-sm">{formatRelativeTimeShort(value)}</p>
        </TooltipTrigger>
        <TooltipContent>{formatDateTime(value)}</TooltipContent>
      </Tooltip>
    </div>
  )
}

// -- Main page ----------------------------------------------------------------

function ExtensionDetailPage() {
  const { extensionId } = Route.useParams()
  const { tab = "details", edit } = Route.useSearch()
  const router = useRouter()
  const navigate = Route.useNavigate()
  const { data, isLoading, isError } = useExtension(extensionId)
  useDocumentTitle(data ? `${data.displayName} (Ext. ${data.extensionNumber})` : "Extension")
  const updateExtension = useUpdateExtension(extensionId)
  const gatewayQuery = useGatewayLookupExtension(data?.extensionNumber ?? "", tab === "external")
  const [showEditDialog, setShowEditDialog] = useState(false)
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)

  // Open edit dialog when ?edit=true is in the URL
  useEffect(() => {
    if (edit && data) {
      setShowEditDialog(true)
      // Clear the search param so refreshing doesn't re-open the dialog
      navigate({ search: {}, replace: true })
    }
  }, [edit, data, navigate])

  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        {/* Header skeleton */}
        <div className="space-y-2">
          <Skeleton className="h-4 w-20" />
          <Skeleton className="h-8 w-64" />
        </div>
        {/* Extension Info card */}
        <PageSection>
          <div className="rounded-xl border border-border/60 bg-card/80 p-6 space-y-4">
            <div className="flex items-center gap-2">
              <Skeleton className="h-5 w-5 rounded" />
              <Skeleton className="h-6 w-28" />
            </div>
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
              {Array.from({ length: 4 }).map((_, i) => (
                <div key={i} className="space-y-1.5">
                  <Skeleton className="h-3.5 w-24" />
                  <Skeleton className="h-5 w-28" />
                </div>
              ))}
            </div>
          </div>
        </PageSection>
        {/* Call Settings card */}
        <PageSection delay={0.1}>
          <div className="rounded-xl border border-border/60 bg-card/80 p-6 space-y-4">
            <div className="flex items-center gap-2">
              <Skeleton className="h-5 w-5 rounded" />
              <Skeleton className="h-6 w-28" />
            </div>
            <div className="grid gap-4 md:grid-cols-3">
              {Array.from({ length: 3 }).map((_, i) => (
                <div key={i} className="flex items-start gap-3">
                  <Skeleton className="mt-0.5 h-4 w-4 rounded" />
                  <div className="space-y-1.5">
                    <Skeleton className="h-3.5 w-24" />
                    <Skeleton className="h-5 w-16" />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </PageSection>
        {/* Sub-page link cards */}
        <PageSection delay={0.15}>
          <div className="grid gap-3 md:grid-cols-3">
            {Array.from({ length: 3 }).map((_, i) => (
              <div key={i} className="rounded-xl border border-border/60 bg-card/80 p-6 space-y-3">
                <div className="flex items-center gap-3">
                  <Skeleton className="h-5 w-5 rounded" />
                  <Skeleton className="h-5 w-24" />
                </div>
                <Skeleton className="h-3 w-36" />
              </div>
            ))}
          </div>
        </PageSection>
        {/* Metadata card */}
        <PageSection delay={0.2}>
          <div className="rounded-xl border border-border/60 bg-card/80 p-6 space-y-4">
            <div className="flex items-center gap-2">
              <Skeleton className="h-5 w-5 rounded" />
              <Skeleton className="h-6 w-24" />
            </div>
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
              {Array.from({ length: 4 }).map((_, i) => (
                <div key={i} className="space-y-1.5">
                  <Skeleton className="h-3.5 w-24" />
                  <Skeleton className="h-5 w-36" />
                </div>
              ))}
            </div>
          </div>
        </PageSection>
      </PageContainer>
    )
  }

  if (isError || !data) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader
          eyebrow="Voice"
          title="Extension Details"
          actions={
            <Button variant="outline" size="sm" asChild>
              <Link to="/voice/extensions">Back to extensions</Link>
            </Button>
          }
        />
        <PageSection>
          <Card>
            <CardHeader>
              <CardTitle>Extension detail</CardTitle>
            </CardHeader>
            <CardContent className="text-muted-foreground">
              We could not load this extension.
            </CardContent>
          </Card>
        </PageSection>
      </PageContainer>
    )
  }

  const title = `${data.displayName} (Ext. ${data.extensionNumber})`

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Voice"
        title={title}
        description={data.isActive ? undefined : "This extension is currently disabled"}
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
                <BreadcrumbPage>{data.displayName}</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
        actions={
          <div className="flex items-center gap-3">
            <Button variant="outline" size="sm" asChild>
              <Link to="/voice/extensions">
                <ArrowLeft className="mr-2 h-4 w-4" />
                Back to Extensions
              </Link>
            </Button>
            <DndQuickToggle extensionId={extensionId} showLabel />
            {!data.isActive && (
              <Badge
                variant="outline"
                className="border-muted-foreground/30 text-muted-foreground"
              >
                Disabled
              </Badge>
            )}
            <Button variant="outline" size="sm" onClick={() => setShowEditDialog(true)}>
              <Pencil className="mr-2 h-4 w-4" /> Edit
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
          </div>
        }
      />

      <PageSection>
        <Tabs value={tab} onValueChange={(value) => navigate({ search: { tab: value }, replace: true })}>
          <TabsList>
            <TabsTrigger value="details">Details</TabsTrigger>
            <TabsTrigger value="voicemail">Voicemail</TabsTrigger>
            <TabsTrigger value="external">External Data</TabsTrigger>
            <TabsTrigger value="activity">Activity</TabsTrigger>
          </TabsList>

          <TabsContent value="details" className="mt-6 space-y-6">
            {/* Extension Info */}
            <Card>
              <CardHeader>
                <div className="flex items-center gap-2">
                  <Phone className="h-5 w-5 text-muted-foreground" />
                  <CardTitle>Extension Info</CardTitle>
                </div>
              </CardHeader>
              <CardContent>
                <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-4">
                  <div>
                    <p className="text-muted-foreground">Extension Number</p>
                    <p className="font-mono font-medium">{data.extensionNumber}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Display Name</p>
                    <p className="font-medium">{data.displayName}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Phone Number</p>
                    <p>{data.phoneNumberId ? "Assigned" : "Not assigned"}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Active</p>
                    <div className="mt-0.5 flex items-center gap-2">
                      <p>{data.isActive ? "Yes" : "No"}</p>
                      <Switch
                        checked={data.isActive}
                        onCheckedChange={(checked) =>
                          updateExtension.mutate({ isActive: checked })
                        }
                        disabled={updateExtension.isPending}
                      />
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Call Settings */}
            <Card>
              <CardHeader>
                <div className="flex items-center gap-2">
                  <Settings className="h-5 w-5 text-muted-foreground" />
                  <CardTitle>Call Settings</CardTitle>
                </div>
              </CardHeader>
              <CardContent>
                <CallSettingsSummary extensionId={extensionId} />
              </CardContent>
            </Card>

            {/* Call Forwarding */}
            <CallForwardingCard extensionId={extensionId} extension={data} />

            {/* Sub-page links (voicemail, forwarding, dnd) */}
            <SubPageLinks extensionId={extensionId} />

            {/* Metadata */}
            <Card>
              <CardHeader>
                <div className="flex items-center gap-2">
                  <Fingerprint className="h-5 w-5 text-muted-foreground" />
                  <CardTitle>Metadata</CardTitle>
                </div>
              </CardHeader>
              <CardContent>
                <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-4">
                  <div>
                    <p className="text-sm text-muted-foreground">Extension ID</p>
                    <div className="flex items-center gap-1">
                      <p className="font-mono text-xs">{extensionId}</p>
                      <CopyButton value={extensionId} label="extension ID" />
                    </div>
                  </div>
                  <TimestampField label="Created" value={data.createdAt} />
                  <TimestampField label="Last Updated" value={data.updatedAt} />
                  {data.phoneNumberId && (
                    <div>
                      <p className="text-sm text-muted-foreground">Phone Number ID</p>
                      <div className="flex items-center gap-1">
                        <p className="font-mono text-xs">{data.phoneNumberId}</p>
                        <CopyButton value={data.phoneNumberId} label="phone number ID" />
                      </div>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="voicemail" className="mt-6 space-y-6">
            <ExtensionVoicemailTab extensionId={extensionId} />
          </TabsContent>

          <TabsContent value="external" className="mt-6">
            <ExternalDataTab
              hasIdentifier={!!data.extensionNumber}
              noIdentifierMessage="This extension has no extension number. Cannot look up external PBX data."
              sources={gatewayQuery.data?.sources}
              isLoading={gatewayQuery.isLoading}
              isRefetching={gatewayQuery.isRefetching}
              isError={gatewayQuery.isError}
              onRefresh={() => gatewayQuery.refetch()}
            />
          </TabsContent>

          <TabsContent value="activity" className="mt-6">
            <Card>
              <CardHeader>
                <CardTitle>Activity Log</CardTitle>
              </CardHeader>
              <CardContent>
                <EntityActivityPanel
                  targetType="extension"
                  targetId={extensionId}
                  enabled={tab === "activity"}
                />
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </PageSection>

      {/* Danger Zone */}
      <PageSection delay={0.25}>
        <Card className="border-destructive/30">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-destructive">
              <AlertTriangle className="h-4 w-4" />
              Danger Zone
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium text-sm">Delete this extension</p>
                <p className="text-sm text-muted-foreground">
                  This action cannot be undone. All forwarding rules, voicemail settings, and DND
                  configuration will be permanently removed.
                </p>
              </div>
              <Button
                variant="destructive"
                size="sm"
                onClick={() => setShowDeleteDialog(true)}
              >
                <Trash2 className="mr-2 h-4 w-4" /> Delete
              </Button>
            </div>
          </CardContent>
        </Card>
      </PageSection>

      {/* Edit extension dialog */}
      <EditExtensionDialog
        extension={data}
        open={showEditDialog}
        onOpenChange={setShowEditDialog}
      />

      {/* Delete confirmation dialog */}
      <DeleteExtensionDialog
        extensionId={extensionId}
        extensionName={data.displayName}
        extensionNumber={data.extensionNumber}
        open={showDeleteDialog}
        onOpenChange={setShowDeleteDialog}
        onDeleted={() => router.navigate({ to: "/voice/extensions" })}
      />
    </PageContainer>
  )
}

// -- Call forwarding card -----------------------------------------------------

interface ForwardingState {
  forwardAlwaysEnabled: boolean
  forwardAlwaysDestination: string
  forwardBusyEnabled: boolean
  forwardBusyDestination: string
  forwardNoAnswerEnabled: boolean
  forwardNoAnswerDestination: string
  forwardNoAnswerRingCount: number
  forwardUnreachableEnabled: boolean
  forwardUnreachableDestination: string
  dndEnabled: boolean
}

function stateFromExtension(ext: ExtensionType): ForwardingState {
  return {
    forwardAlwaysEnabled: ext.forwardAlwaysEnabled,
    forwardAlwaysDestination: ext.forwardAlwaysDestination ?? "",
    forwardBusyEnabled: ext.forwardBusyEnabled,
    forwardBusyDestination: ext.forwardBusyDestination ?? "",
    forwardNoAnswerEnabled: ext.forwardNoAnswerEnabled,
    forwardNoAnswerDestination: ext.forwardNoAnswerDestination ?? "",
    forwardNoAnswerRingCount: ext.forwardNoAnswerRingCount,
    forwardUnreachableEnabled: ext.forwardUnreachableEnabled,
    forwardUnreachableDestination: ext.forwardUnreachableDestination ?? "",
    dndEnabled: ext.dndEnabled,
  }
}

function hasChanges(current: ForwardingState, original: ForwardingState): boolean {
  return (
    current.dndEnabled !== original.dndEnabled ||
    current.forwardAlwaysEnabled !== original.forwardAlwaysEnabled ||
    current.forwardAlwaysDestination !== original.forwardAlwaysDestination ||
    current.forwardBusyEnabled !== original.forwardBusyEnabled ||
    current.forwardBusyDestination !== original.forwardBusyDestination ||
    current.forwardNoAnswerEnabled !== original.forwardNoAnswerEnabled ||
    current.forwardNoAnswerDestination !== original.forwardNoAnswerDestination ||
    current.forwardNoAnswerRingCount !== original.forwardNoAnswerRingCount ||
    current.forwardUnreachableEnabled !== original.forwardUnreachableEnabled ||
    current.forwardUnreachableDestination !== original.forwardUnreachableDestination
  )
}

function buildPatch(current: ForwardingState, original: ForwardingState): Record<string, unknown> {
  const patch: Record<string, unknown> = {}
  if (current.dndEnabled !== original.dndEnabled)
    patch.dndEnabled = current.dndEnabled
  if (current.forwardAlwaysEnabled !== original.forwardAlwaysEnabled)
    patch.forwardAlwaysEnabled = current.forwardAlwaysEnabled
  if (current.forwardAlwaysDestination !== original.forwardAlwaysDestination)
    patch.forwardAlwaysDestination = current.forwardAlwaysDestination || null
  if (current.forwardBusyEnabled !== original.forwardBusyEnabled)
    patch.forwardBusyEnabled = current.forwardBusyEnabled
  if (current.forwardBusyDestination !== original.forwardBusyDestination)
    patch.forwardBusyDestination = current.forwardBusyDestination || null
  if (current.forwardNoAnswerEnabled !== original.forwardNoAnswerEnabled)
    patch.forwardNoAnswerEnabled = current.forwardNoAnswerEnabled
  if (current.forwardNoAnswerDestination !== original.forwardNoAnswerDestination)
    patch.forwardNoAnswerDestination = current.forwardNoAnswerDestination || null
  if (current.forwardNoAnswerRingCount !== original.forwardNoAnswerRingCount)
    patch.forwardNoAnswerRingCount = current.forwardNoAnswerRingCount
  if (current.forwardUnreachableEnabled !== original.forwardUnreachableEnabled)
    patch.forwardUnreachableEnabled = current.forwardUnreachableEnabled
  if (current.forwardUnreachableDestination !== original.forwardUnreachableDestination)
    patch.forwardUnreachableDestination = current.forwardUnreachableDestination || null
  return patch
}

function CallForwardingCard({
  extensionId,
  extension,
}: {
  extensionId: string
  extension: ExtensionType
}) {
  const updateExtension = useUpdateExtension(extensionId)
  const [isEditing, setIsEditing] = useState(false)
  const [state, setState] = useState<ForwardingState>(() => stateFromExtension(extension))
  const original = stateFromExtension(extension)

  // Sync state when extension data refreshes (e.g. after save)
  useEffect(() => {
    if (!isEditing) {
      setState(stateFromExtension(extension))
    }
  }, [extension, isEditing])

  const update = useCallback(
    <K extends keyof ForwardingState>(key: K, value: ForwardingState[K]) => {
      setState((prev) => ({ ...prev, [key]: value }))
    },
    [],
  )

  function handleSave() {
    const patch = buildPatch(state, original)
    if (Object.keys(patch).length === 0) {
      setIsEditing(false)
      return
    }
    updateExtension.mutate(patch, {
      onSuccess: () => setIsEditing(false),
    })
  }

  function handleCancel() {
    setState(stateFromExtension(extension))
    setIsEditing(false)
  }

  const dirty = hasChanges(state, original)
  const anyForwardingEnabled =
    extension.forwardAlwaysEnabled ||
    extension.forwardBusyEnabled ||
    extension.forwardNoAnswerEnabled ||
    extension.forwardUnreachableEnabled

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <PhoneForwarded className="h-5 w-5 text-muted-foreground" />
            <CardTitle>Call Forwarding</CardTitle>
            {!isEditing && extension.dndEnabled && (
              <Badge variant="destructive" className="ml-2 gap-1 text-xs">
                <BellOff className="h-3 w-3" /> DND
              </Badge>
            )}
            {!isEditing && anyForwardingEnabled && (
              <Badge variant="secondary" className="ml-1 text-xs">Active</Badge>
            )}
          </div>
          {!isEditing ? (
            <Button variant="outline" size="sm" onClick={() => setIsEditing(true)}>
              <Pencil className="mr-2 h-4 w-4" /> Edit
            </Button>
          ) : (
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={handleCancel}
                disabled={updateExtension.isPending}
              >
                Cancel
              </Button>
              <Button
                size="sm"
                onClick={handleSave}
                disabled={!dirty || updateExtension.isPending}
              >
                {updateExtension.isPending ? (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                ) : (
                  <Check className="mr-2 h-4 w-4" />
                )}
                Save
              </Button>
            </div>
          )}
        </div>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* DND Toggle */}
        <div className="flex items-center justify-between rounded-lg border border-border/60 bg-muted/30 p-4">
          <div className="flex items-center gap-3">
            <BellOff className={`h-5 w-5 ${isEditing ? (state.dndEnabled ? "text-destructive" : "text-muted-foreground") : (extension.dndEnabled ? "text-destructive" : "text-muted-foreground")}`} />
            <div>
              <p className="text-sm font-medium">Do Not Disturb</p>
              <p className="text-xs text-muted-foreground">
                Silence all incoming calls to this extension
              </p>
            </div>
          </div>
          <Switch
            checked={isEditing ? state.dndEnabled : extension.dndEnabled}
            onCheckedChange={(checked) => {
              if (isEditing) {
                update("dndEnabled", checked)
              } else {
                updateExtension.mutate({ dndEnabled: checked })
              }
            }}
            disabled={updateExtension.isPending}
          />
        </div>

        {/* Forwarding Rules */}
        <div className="space-y-4">
          <ForwardingRuleRow
            label="Always Forward"
            description="Forward all incoming calls"
            enabled={isEditing ? state.forwardAlwaysEnabled : extension.forwardAlwaysEnabled}
            destination={isEditing ? state.forwardAlwaysDestination : (extension.forwardAlwaysDestination ?? "")}
            onEnabledChange={(v) => update("forwardAlwaysEnabled", v)}
            onDestinationChange={(v) => update("forwardAlwaysDestination", v)}
            isEditing={isEditing}
            disabled={updateExtension.isPending}
          />

          <ForwardingRuleRow
            label="Forward on Busy"
            description="Forward when the line is busy"
            enabled={isEditing ? state.forwardBusyEnabled : extension.forwardBusyEnabled}
            destination={isEditing ? state.forwardBusyDestination : (extension.forwardBusyDestination ?? "")}
            onEnabledChange={(v) => update("forwardBusyEnabled", v)}
            onDestinationChange={(v) => update("forwardBusyDestination", v)}
            isEditing={isEditing}
            disabled={updateExtension.isPending}
          />

          <ForwardingRuleRow
            label="Forward on No Answer"
            description="Forward after the ring timeout"
            enabled={isEditing ? state.forwardNoAnswerEnabled : extension.forwardNoAnswerEnabled}
            destination={isEditing ? state.forwardNoAnswerDestination : (extension.forwardNoAnswerDestination ?? "")}
            ringCount={isEditing ? state.forwardNoAnswerRingCount : extension.forwardNoAnswerRingCount}
            onEnabledChange={(v) => update("forwardNoAnswerEnabled", v)}
            onDestinationChange={(v) => update("forwardNoAnswerDestination", v)}
            onRingCountChange={(v) => update("forwardNoAnswerRingCount", v)}
            showRingCount
            isEditing={isEditing}
            disabled={updateExtension.isPending}
          />

          <ForwardingRuleRow
            label="Forward on Unreachable"
            description="Forward when the extension is offline"
            enabled={isEditing ? state.forwardUnreachableEnabled : extension.forwardUnreachableEnabled}
            destination={isEditing ? state.forwardUnreachableDestination : (extension.forwardUnreachableDestination ?? "")}
            onEnabledChange={(v) => update("forwardUnreachableEnabled", v)}
            onDestinationChange={(v) => update("forwardUnreachableDestination", v)}
            isEditing={isEditing}
            disabled={updateExtension.isPending}
          />
        </div>
      </CardContent>
    </Card>
  )
}

// -- Forwarding rule row ------------------------------------------------------

function ForwardingRuleRow({
  label,
  description,
  enabled,
  destination,
  ringCount,
  onEnabledChange,
  onDestinationChange,
  onRingCountChange,
  showRingCount = false,
  isEditing,
  disabled,
}: {
  label: string
  description: string
  enabled: boolean
  destination: string
  ringCount?: number
  onEnabledChange: (v: boolean) => void
  onDestinationChange: (v: string) => void
  onRingCountChange?: (v: number) => void
  showRingCount?: boolean
  isEditing: boolean
  disabled: boolean
}) {
  if (!isEditing) {
    // Read-only view
    return (
      <div className="flex items-center justify-between rounded-lg border border-border/40 p-4">
        <div className="flex items-center gap-3">
          <PhoneForwarded className={`h-4 w-4 ${enabled ? "text-primary" : "text-muted-foreground"}`} />
          <div>
            <div className="flex items-center gap-2">
              <p className="text-sm font-medium">{label}</p>
              {enabled ? (
                <Badge variant="default" className="text-xs">On</Badge>
              ) : (
                <Badge variant="outline" className="text-xs">Off</Badge>
              )}
            </div>
            <p className="text-xs text-muted-foreground">{description}</p>
            {enabled && destination && (
              <p className="mt-1 font-mono text-xs text-muted-foreground">
                Destination: {destination}
                {showRingCount && ringCount != null && ` (${ringCount} rings)`}
              </p>
            )}
          </div>
        </div>
      </div>
    )
  }

  // Editing view
  return (
    <div className="rounded-lg border border-border/40 p-4 space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium">{label}</p>
          <p className="text-xs text-muted-foreground">{description}</p>
        </div>
        <Switch
          checked={enabled}
          onCheckedChange={onEnabledChange}
          disabled={disabled}
        />
      </div>
      {enabled && (
        <div className="grid gap-3 pt-1 md:grid-cols-2">
          <div className="space-y-1.5">
            <Label className="text-xs">Destination</Label>
            <Input
              value={destination}
              onChange={(e) => onDestinationChange(e.target.value)}
              placeholder="Phone number or extension"
              disabled={disabled}
              className="h-9 text-sm"
            />
          </div>
          {showRingCount && onRingCountChange && (
            <div className="space-y-1.5">
              <Label className="text-xs">Ring count</Label>
              <Input
                type="number"
                value={ringCount ?? 4}
                onChange={(e) => {
                  const v = parseInt(e.target.value, 10)
                  if (!isNaN(v) && v >= 1 && v <= 10) onRingCountChange(v)
                }}
                min={1}
                max={10}
                disabled={disabled}
                className="h-9 text-sm"
              />
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// -- Call settings summary ----------------------------------------------------

function CallSettingsSummary({ extensionId }: { extensionId: string }) {
  const { data: dndSettings } = useDndSettings(extensionId)
  const { data: fwdRules } = useForwardingRules(extensionId)
  const { data: vmSettings } = useVoicemailSettings(extensionId)

  const dndEnabled = dndSettings?.isEnabled ?? false
  const ruleCount = fwdRules?.items?.length ?? 0
  const activeRules = fwdRules?.items?.filter((r) => r.isActive).length ?? 0
  const vmEnabled = vmSettings?.isEnabled ?? false

  return (
    <div className="grid gap-4 text-sm md:grid-cols-3">
      <div className="flex items-start gap-3">
        <BellOff className="mt-0.5 h-4 w-4 text-muted-foreground" />
        <div>
          <p className="text-muted-foreground">Do Not Disturb</p>
          <div className="mt-0.5 flex items-center gap-2">
            {dndEnabled ? (
              <Badge variant="destructive" className="gap-1 text-xs">
                <BellOff className="h-3 w-3" />
                Active
                {dndSettings?.mode && dndSettings.mode !== "always"
                  ? ` (${dndSettings.mode})`
                  : ""}
              </Badge>
            ) : (
              <span>Off</span>
            )}
          </div>
        </div>
      </div>
      <div className="flex items-start gap-3">
        <PhoneForwarded className="mt-0.5 h-4 w-4 text-muted-foreground" />
        <div>
          <p className="text-muted-foreground">Forwarding Rules</p>
          <p className="mt-0.5">
            {ruleCount > 0
              ? `${activeRules} of ${ruleCount} rules active`
              : "No rules configured"}
          </p>
        </div>
      </div>
      <div className="flex items-start gap-3">
        <Voicemail className="mt-0.5 h-4 w-4 text-muted-foreground" />
        <div>
          <p className="text-muted-foreground">Voicemail</p>
          <p className="mt-0.5">{vmEnabled ? "Enabled" : "Disabled"}</p>
        </div>
      </div>
    </div>
  )
}

// -- Sub-page links -----------------------------------------------------------

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
      description:
        ruleCount > 0
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

// -- Extension Voicemail Tab --------------------------------------------------

function ExtensionVoicemailTab({ extensionId }: { extensionId: string }) {
  const { data: vmSettings, isLoading: settingsLoading } = useVoicemailSettings(extensionId)
  const { data: vmMessages, isLoading: msgsLoading } = useVoicemailMessages(extensionId, 1, 5)

  const isLoading = settingsLoading || msgsLoading
  const vmEnabled = vmSettings?.isEnabled ?? false
  const unreadCount = vmMessages?.items.filter((m) => !m.isRead).length ?? 0
  const totalCount = vmMessages?.total ?? 0
  const recentMessages = vmMessages?.items ?? []

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Voicemail className="h-5 w-5 text-muted-foreground" />
              <CardTitle>Voicemail Settings</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 md:grid-cols-3">
              {Array.from({ length: 3 }).map((_, i) => (
                <div key={i} className="space-y-1.5">
                  <div className="h-3.5 w-24 animate-pulse rounded bg-muted" />
                  <div className="h-5 w-16 animate-pulse rounded bg-muted" />
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    )
  }

  if (!vmSettings) {
    return (
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Voicemail className="h-5 w-5 text-muted-foreground" />
            <CardTitle>Voicemail</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col items-center gap-4 py-8 text-center">
            <Voicemail className="h-10 w-10 text-muted-foreground/50" />
            <div>
              <p className="font-medium">No voicemail box configured</p>
              <p className="text-sm text-muted-foreground">
                Set up voicemail for this extension to allow callers to leave messages.
              </p>
            </div>
            <Button variant="outline" size="sm" asChild>
              <Link
                to="/voice/extensions/$extensionId/voicemail"
                params={{ extensionId }}
              >
                Set Up Voicemail
              </Link>
            </Button>
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="space-y-6">
      {/* Voicemail settings card */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div className="flex items-center gap-2">
            <Voicemail className="h-5 w-5 text-muted-foreground" />
            <CardTitle>Voicemail Settings</CardTitle>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant={vmEnabled ? "default" : "outline"}>
              {vmEnabled ? "Enabled" : "Disabled"}
            </Badge>
            <Button variant="ghost" size="sm" asChild>
              <Link
                to="/voice/extensions/$extensionId/voicemail"
                params={{ extensionId }}
              >
                <ExternalLink className="mr-1.5 h-3.5 w-3.5" />
                Full settings
              </Link>
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-4">
            <div>
              <p className="text-muted-foreground">Greeting</p>
              <p className="capitalize">{vmSettings.greetingType.replace("_", " ")}</p>
            </div>
            <div>
              <p className="text-muted-foreground">Transcription</p>
              <p>{vmSettings.transcriptionEnabled ? "Enabled" : "Disabled"}</p>
            </div>
            <div>
              <p className="text-muted-foreground">Email Notification</p>
              <p>{vmSettings.emailNotification ? "Enabled" : "Disabled"}</p>
            </div>
            <div>
              <p className="text-muted-foreground">Max Length</p>
              <p>{vmSettings.maxMessageLengthSeconds}s</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Recent messages */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div className="flex items-center gap-3">
            <CardTitle>Recent Messages</CardTitle>
            {unreadCount > 0 && (
              <Badge variant="secondary" className="gap-1">
                <Mail className="h-3 w-3" />
                {unreadCount} unread
              </Badge>
            )}
          </div>
          {totalCount > 0 && (
            <Button variant="ghost" size="sm" asChild>
              <Link
                to="/voice/extensions/$extensionId/voicemail"
                params={{ extensionId }}
              >
                View all ({totalCount})
                <ArrowRight className="ml-1.5 h-3.5 w-3.5" />
              </Link>
            </Button>
          )}
        </CardHeader>
        <CardContent>
          {recentMessages.length === 0 ? (
            <div className="flex flex-col items-center gap-2 py-6 text-center">
              <Inbox className="h-8 w-8 text-muted-foreground/50" />
              <p className="text-sm text-muted-foreground">No voicemail messages yet.</p>
            </div>
          ) : (
            <div className="space-y-2">
              {recentMessages.map((msg) => (
                <Link
                  key={msg.id}
                  to="/voice/extensions/$extensionId/voicemail"
                  params={{ extensionId }}
                  className="group flex items-center gap-3 rounded-lg border border-border/40 p-3 transition-all hover:bg-muted/30 hover:shadow-sm"
                >
                  <div className="flex items-center gap-2">
                    {!msg.isRead && (
                      <div className="h-2 w-2 rounded-full bg-primary" />
                    )}
                    {msg.isUrgent && (
                      <Badge variant="destructive" className="text-[10px] px-1 py-0">
                        Urgent
                      </Badge>
                    )}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className={`text-sm ${!msg.isRead ? "font-semibold" : ""}`}>
                      {msg.callerName ?? msg.callerNumber}
                    </p>
                    <p className="text-xs text-muted-foreground truncate">
                      {formatDuration(msg.durationSeconds)} &middot;{" "}
                      {formatDateTime(msg.receivedAt)}
                      {msg.transcription
                        ? ` — ${msg.transcription.slice(0, 50)}${msg.transcription.length > 50 ? "..." : ""}`
                        : ""}
                    </p>
                  </div>
                  <ArrowRight className="h-4 w-4 text-muted-foreground/50 transition-transform group-hover:translate-x-0.5 group-hover:text-foreground" />
                </Link>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
