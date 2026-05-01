import { createFileRoute, Link, useRouter } from "@tanstack/react-router"
import { useEffect, useState } from "react"
import { z } from "zod"
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  BellOff,
  Fingerprint,
  Mail,
  Pencil,
  Phone,
  PhoneForwarded,
  Settings,
  Trash2,
  Voicemail,
} from "lucide-react"
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
import { Skeleton } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { CopyButton } from "@/components/ui/copy-button"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { DeleteExtensionDialog } from "@/components/voice/delete-extension-dialog"
import { DndQuickToggle } from "@/components/voice/dnd-quick-toggle"
import { EditExtensionDialog } from "@/components/voice/edit-extension-dialog"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"
import {
  useDndSettings,
  useExtension,
  useForwardingRules,
  useUpdateExtension,
  useVoicemailMessages,
  useVoicemailSettings,
} from "@/lib/api/hooks/voice"

const searchSchema = z.object({
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
  const { edit } = Route.useSearch()
  const router = useRouter()
  const navigate = Route.useNavigate()
  const { data, isLoading, isError } = useExtension(extensionId)
  const updateExtension = useUpdateExtension(extensionId)
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

      {/* Extension Info */}
      <PageSection>
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
      </PageSection>

      {/* Call Settings */}
      <PageSection delay={0.1}>
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
      </PageSection>

      {/* Sub-page links (voicemail, forwarding, dnd) */}
      <PageSection delay={0.15}>
        <SubPageLinks extensionId={extensionId} />
      </PageSection>

      {/* Metadata */}
      <PageSection delay={0.2}>
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
