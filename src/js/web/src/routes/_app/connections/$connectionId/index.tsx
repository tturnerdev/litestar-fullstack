import { createFileRoute, Link, useRouter } from "@tanstack/react-router"
import { useState } from "react"
import {
  AlertCircle,
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  Circle,
  Globe,
  Key,
  Loader2,
  Lock,
  Pencil,
  Plug,
  Server,
  Settings,
  ShieldCheck,
  Trash2,
  XCircle,
} from "lucide-react"
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
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
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
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Separator } from "@/components/ui/separator"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Textarea } from "@/components/ui/textarea"
import { CopyButton } from "@/components/ui/copy-button"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"
import {
  useConnection,
  useDeleteConnection,
  useTestConnection,
  useUpdateConnection,
} from "@/lib/api/hooks/connections"

export const Route = createFileRoute("/_app/connections/$connectionId/")({
  component: ConnectionDetailPage,
})

// ── Label maps ──────────────────────────────────────────────────────────

const typeLabels: Record<string, string> = {
  pbx: "PBX",
  helpdesk: "Helpdesk",
  carrier: "Carrier",
  other: "Other",
}

const authTypeLabels: Record<string, string> = {
  api_key: "API Key",
  basic: "Basic Auth",
  oauth2: "OAuth 2.0",
  token: "Token",
  none: "None",
}

// ── Status badge ────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  switch (status) {
    case "connected":
      return (
        <Badge className="gap-1 bg-emerald-100 text-emerald-700 hover:bg-emerald-100 dark:bg-emerald-900/30 dark:text-emerald-400">
          <CheckCircle2 className="h-3 w-3" />
          Connected
        </Badge>
      )
    case "disconnected":
      return (
        <Badge variant="outline" className="gap-1">
          <XCircle className="h-3 w-3" />
          Disconnected
        </Badge>
      )
    case "error":
      return (
        <Badge variant="destructive" className="gap-1">
          <AlertCircle className="h-3 w-3" />
          Error
        </Badge>
      )
    default:
      return (
        <Badge variant="outline" className="gap-1 text-muted-foreground">
          <Circle className="h-3 w-3" />
          Unknown
        </Badge>
      )
  }
}

// ── Timestamp with tooltip ──────────────────────────────────────────────

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
        <p className="text-muted-foreground text-sm">{label}</p>
        <p className="text-sm">---</p>
      </div>
    )
  }

  return (
    <div>
      <p className="text-muted-foreground text-sm">{label}</p>
      <Tooltip>
        <TooltipTrigger asChild>
          <p className="cursor-default text-sm">{formatRelativeTimeShort(value)}</p>
        </TooltipTrigger>
        <TooltipContent>{formatDateTime(value)}</TooltipContent>
      </Tooltip>
    </div>
  )
}

// ── Main page ───────────────────────────────────────────────────────────

function ConnectionDetailPage() {
  const { connectionId } = Route.useParams()
  const router = useRouter()
  const { data, isLoading, isError } = useConnection(connectionId)
  const deleteConnection = useDeleteConnection()
  const testConnection = useTestConnection(connectionId)
  const updateConnection = useUpdateConnection(connectionId)

  const [deleteOpen, setDeleteOpen] = useState(false)
  const [settingsText, setSettingsText] = useState<string | null>(null)
  const [settingsError, setSettingsError] = useState<string | null>(null)
  const [settingsDirty, setSettingsDirty] = useState(false)

  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader eyebrow="Connections" title="Connection Details" />
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
          eyebrow="Connections"
          title="Connection Details"
          actions={
            <Button variant="outline" size="sm" asChild>
              <Link to="/connections">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back to connections
              </Link>
            </Button>
          }
        />
        <PageSection>
          <Card>
            <CardHeader>
              <CardTitle>Connection detail</CardTitle>
            </CardHeader>
            <CardContent className="text-muted-foreground">
              We could not load this connection.
            </CardContent>
          </Card>
        </PageSection>
      </PageContainer>
    )
  }

  const handleDelete = async () => {
    await deleteConnection.mutateAsync(connectionId)
    router.navigate({ to: "/connections" })
  }

  const currentSettingsText =
    settingsText ?? (data.settings ? JSON.stringify(data.settings, null, 2) : "")

  const handleSaveSettings = () => {
    const text = currentSettingsText.trim()
    if (text) {
      try {
        const parsed = JSON.parse(text)
        setSettingsError(null)
        updateConnection.mutate(
          { settings: parsed },
          { onSuccess: () => setSettingsDirty(false) },
        )
      } catch {
        setSettingsError("Invalid JSON")
        return
      }
    } else {
      updateConnection.mutate(
        { settings: null },
        { onSuccess: () => setSettingsDirty(false) },
      )
    }
  }

  const settingsEntries = data.settings ? Object.entries(data.settings) : []

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Connections"
        title={data.name}
        description={`${typeLabels[data.connectionType] ?? data.connectionType} · ${data.provider}`}
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
                  <Link to="/connections">Connections</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbPage>{data.name}</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
        actions={
          <div className="flex items-center gap-3">
            <StatusBadge status={data.status} />
            {!data.isEnabled && (
              <Badge
                variant="outline"
                className="border-muted-foreground/30 text-muted-foreground"
              >
                Disabled
              </Badge>
            )}
            <Button
              size="sm"
              variant="outline"
              onClick={() => testConnection.mutate()}
              disabled={testConnection.isPending}
            >
              {testConnection.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Plug className="mr-2 h-4 w-4" />
              )}
              Test
            </Button>
            <Button variant="outline" size="sm" asChild>
              <Link to="/connections/$connectionId/edit" params={{ connectionId }}>
                <Pencil className="mr-2 h-4 w-4" /> Edit
              </Link>
            </Button>
            <Button variant="outline" size="sm" asChild>
              <Link to="/connections">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back
              </Link>
            </Button>
          </div>
        }
      />

      {/* Test result inline feedback */}
      {testConnection.isSuccess && (
        <Alert variant="success">
          <CheckCircle2 className="h-4 w-4" />
          <AlertTitle>Connection test passed</AlertTitle>
          <AlertDescription>{testConnection.data.message}</AlertDescription>
        </Alert>
      )}
      {testConnection.isError && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Connection test failed</AlertTitle>
          <AlertDescription>
            {testConnection.error instanceof Error
              ? testConnection.error.message
              : "An unexpected error occurred"}
          </AlertDescription>
        </Alert>
      )}

      {/* Connection Info */}
      <PageSection>
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Globe className="h-5 w-5 text-muted-foreground" />
              <CardTitle>Connection Info</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-3">
              <div>
                <p className="text-muted-foreground">Name</p>
                <p className="font-medium">{data.name}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Type</p>
                <p>{typeLabels[data.connectionType] ?? data.connectionType}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Provider</p>
                <p>{data.provider}</p>
              </div>
              <div className="md:col-span-2 lg:col-span-3">
                <p className="text-muted-foreground">Description</p>
                <p>{data.description || "---"}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Status</p>
                <div className="mt-0.5">
                  <StatusBadge status={data.status} />
                </div>
              </div>
              <div>
                <p className="text-muted-foreground">Enabled</p>
                <p>{data.isEnabled ? "Yes" : "No"}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Connection ID</p>
                <div className="flex items-center gap-1">
                  <p className="font-mono text-xs">{connectionId}</p>
                  <CopyButton value={connectionId} label="connection ID" />
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </PageSection>

      {/* Server Configuration */}
      <PageSection delay={0.1}>
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Server className="h-5 w-5 text-muted-foreground" />
              <CardTitle>Server Configuration</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-3">
              <div>
                <p className="text-muted-foreground">Host</p>
                <div className="flex items-center gap-1">
                  <p className="font-mono text-xs">{data.host || "---"}</p>
                  {data.host && <CopyButton value={data.host} label="host" />}
                </div>
              </div>
              <div>
                <p className="text-muted-foreground">Port</p>
                <p className="font-mono text-xs">{data.port != null ? String(data.port) : "---"}</p>
              </div>
              <div>
                <p className="text-muted-foreground">SSL / TLS</p>
                <div className="flex items-center gap-1.5">
                  {data.port === 443 ? (
                    <>
                      <ShieldCheck className="h-3.5 w-3.5 text-emerald-500" />
                      <span>Likely (port 443)</span>
                    </>
                  ) : (
                    <span className="text-muted-foreground">Not determined</span>
                  )}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </PageSection>

      {/* Authentication */}
      <PageSection delay={0.15}>
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Key className="h-5 w-5 text-muted-foreground" />
              <CardTitle>Authentication</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-3">
              <div>
                <p className="text-muted-foreground">Auth Type</p>
                <p>{authTypeLabels[data.authType] ?? data.authType}</p>
              </div>
              {data.credentialFields.length > 0 && (
                <div className="md:col-span-2 lg:col-span-3">
                  <p className="text-muted-foreground">Credentials</p>
                  <div className="mt-1.5 flex flex-wrap gap-2">
                    {data.credentialFields.map((field) => (
                      <Badge
                        key={field}
                        variant="outline"
                        className="gap-1.5 font-mono text-xs"
                      >
                        <Lock className="h-3 w-3 text-muted-foreground" />
                        {field}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </PageSection>

      {/* Settings */}
      <PageSection delay={0.2}>
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Settings className="h-5 w-5 text-muted-foreground" />
              <CardTitle>Settings</CardTitle>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Key-value display */}
            {settingsEntries.length > 0 && (
              <div className="rounded-md border">
                <div className="grid grid-cols-[minmax(120px,1fr)_2fr] text-sm">
                  {settingsEntries.map(([key, value], idx) => (
                    <div key={key} className="contents">
                      <div
                        className={`px-3 py-2 font-mono text-xs text-muted-foreground ${idx !== settingsEntries.length - 1 ? "border-b" : ""}`}
                      >
                        {key}
                      </div>
                      <div
                        className={`border-l px-3 py-2 font-mono text-xs ${idx !== settingsEntries.length - 1 ? "border-b" : ""}`}
                      >
                        {typeof value === "object" ? JSON.stringify(value) : String(value ?? "---")}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {settingsEntries.length === 0 && !settingsDirty && (
              <p className="text-sm text-muted-foreground">No settings configured.</p>
            )}

            <Separator />

            {/* Raw JSON editor */}
            <div className="space-y-2">
              <Label htmlFor="settings-json">Configuration JSON</Label>
              <Textarea
                id="settings-json"
                value={currentSettingsText}
                onChange={(e) => {
                  setSettingsText(e.target.value)
                  setSettingsError(null)
                  setSettingsDirty(true)
                }}
                rows={8}
                className="font-mono text-xs"
                placeholder='{"key": "value"}'
              />
              {settingsError && (
                <p className="text-destructive text-sm">{settingsError}</p>
              )}
            </div>
            <div className="flex items-center justify-end gap-2">
              <Button
                variant="ghost"
                onClick={() => {
                  setSettingsText(null)
                  setSettingsError(null)
                  setSettingsDirty(false)
                }}
                disabled={!settingsDirty || updateConnection.isPending}
              >
                Reset
              </Button>
              <Button
                onClick={handleSaveSettings}
                disabled={!settingsDirty || updateConnection.isPending}
              >
                {updateConnection.isPending && (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                )}
                Save Settings
              </Button>
            </div>
          </CardContent>
        </Card>
      </PageSection>

      {/* Metadata */}
      <PageSection delay={0.25}>
        <Card>
          <CardHeader>
            <CardTitle>Metadata</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-4">
              <TimestampField label="Created" value={data.createdAt} />
              <TimestampField label="Updated" value={data.updatedAt} />
              <TimestampField label="Last Health Check" value={data.lastHealthCheck} />
              <div>
                <p className="text-muted-foreground text-sm">Team ID</p>
                <div className="flex items-center gap-1">
                  <p className="font-mono text-xs">{data.teamId}</p>
                  <CopyButton value={data.teamId} label="team ID" />
                </div>
              </div>
            </div>
            {data.lastError && (
              <div className="mt-4">
                <Alert variant="destructive">
                  <AlertCircle className="h-4 w-4" />
                  <AlertTitle>Last Error</AlertTitle>
                  <AlertDescription className="font-mono text-xs">
                    {data.lastError}
                  </AlertDescription>
                </Alert>
              </div>
            )}
          </CardContent>
        </Card>
      </PageSection>

      {/* Danger Zone */}
      <PageSection delay={0.3}>
        <Card className="border-destructive/30">
          <CardHeader>
            <CardTitle className="text-destructive">Danger Zone</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium text-sm">Delete this connection</p>
                <p className="text-sm text-muted-foreground">
                  This action cannot be undone. All configuration and credentials will be
                  permanently removed.
                </p>
              </div>
              <Button
                variant="destructive"
                size="sm"
                onClick={() => setDeleteOpen(true)}
              >
                <Trash2 className="mr-2 h-4 w-4" /> Delete
              </Button>
            </div>
          </CardContent>
        </Card>
      </PageSection>

      {/* Delete confirmation dialog */}
      <AlertDialog open={deleteOpen} onOpenChange={setDeleteOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-destructive" />
              Delete connection?
            </AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete <strong>{data.name}</strong> and all associated
              configuration. This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel
              onClick={() => setDeleteOpen(false)}
              disabled={deleteConnection.isPending}
            >
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              className={buttonVariants({ variant: "destructive" })}
              onClick={() => {
                handleDelete()
                setDeleteOpen(false)
              }}
              disabled={deleteConnection.isPending}
            >
              {deleteConnection.isPending && (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              )}
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </PageContainer>
  )
}
