import { createFileRoute, Link, useRouter } from "@tanstack/react-router"
import { useState } from "react"
import {
  AlertTriangle,
  ArrowRight,
  BellOff,
  Fingerprint,
  Loader2,
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
import { Button, buttonVariants } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { CopyButton } from "@/components/ui/copy-button"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { DndQuickToggle } from "@/components/voice/dnd-quick-toggle"
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
  component: ExtensionDetailPage,
})

// -- Formatting helpers -------------------------------------------------------

function formatDateTime(value: string | null | undefined): string {
  if (!value) return "---"
  return new Date(value).toLocaleString()
}

function formatRelativeTime(value: string | null | undefined): string {
  if (!value) return "Never"
  const date = new Date(value)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffMins = Math.floor(diffMs / 60_000)
  if (diffMins < 1) return "Just now"
  if (diffMins < 60) return `${diffMins}m ago`
  const diffHours = Math.floor(diffMins / 60)
  if (diffHours < 24) return `${diffHours}h ago`
  const diffDays = Math.floor(diffHours / 24)
  return `${diffDays}d ago`
}

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
          <p className="cursor-default text-sm">{formatRelativeTime(value)}</p>
        </TooltipTrigger>
        <TooltipContent>{formatDateTime(value)}</TooltipContent>
      </Tooltip>
    </div>
  )
}

// -- Main page ----------------------------------------------------------------

function ExtensionDetailPage() {
  const { extensionId } = Route.useParams()
  const router = useRouter()
  const { data, isLoading, isError } = useExtension(extensionId)
  const updateExtension = useUpdateExtension(extensionId)
  const deleteExtension = useDeleteExtension()
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)

  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader eyebrow="Voice" title="Extension Details" />
        <PageSection>
          <SkeletonCard />
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

  const handleDelete = async () => {
    await deleteExtension.mutateAsync(extensionId)
    router.navigate({ to: "/voice/extensions" })
  }

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
            <DndQuickToggle extensionId={extensionId} showLabel />
            {!data.isActive && (
              <Badge
                variant="outline"
                className="border-muted-foreground/30 text-muted-foreground"
              >
                Disabled
              </Badge>
            )}
            <Button variant="outline" size="sm" asChild>
              <Link to="/voice/extensions/$extensionId/edit" params={{ extensionId }}>
                <Pencil className="mr-2 h-4 w-4" /> Edit
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

      {/* Delete confirmation dialog */}
      <AlertDialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-destructive" />
              Delete Extension
            </AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete{" "}
              <span className="font-medium text-foreground">{data.displayName}</span>
              {data.extensionNumber && (
                <> (Ext. <span className="font-mono text-foreground">{data.extensionNumber}</span>)</>
              )}
              ? This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="rounded-md border border-destructive/20 bg-destructive/5 px-4 py-3">
            <p className="mb-2 text-sm font-medium text-destructive">The following will be permanently removed:</p>
            <ul className="list-inside list-disc space-y-1 text-sm text-muted-foreground">
              <li>All call forwarding rules</li>
              <li>Voicemail settings and messages</li>
              <li>Do Not Disturb configuration</li>
            </ul>
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel
              onClick={() => setShowDeleteDialog(false)}
              disabled={deleteExtension.isPending}
            >
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              className={buttonVariants({ variant: "destructive" })}
              onClick={handleDelete}
              disabled={deleteExtension.isPending}
            >
              {deleteExtension.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Trash2 className="mr-2 h-4 w-4" />
              )}
              Delete Extension
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
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
