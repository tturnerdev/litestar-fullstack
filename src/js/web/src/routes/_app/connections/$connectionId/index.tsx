import { createFileRoute, Link, useRouter } from "@tanstack/react-router"
import { useState } from "react"
import {
  AlertCircle,
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  Circle,
  Loader2,
  Pencil,
  Plug,
  Trash2,
  XCircle,
} from "lucide-react"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Badge } from "@/components/ui/badge"
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Textarea } from "@/components/ui/textarea"
import {
  useConnection,
  useDeleteConnection,
  useTestConnection,
  useUpdateConnection,
} from "@/lib/api/hooks/connections"

export const Route = createFileRoute("/_app/connections/$connectionId/")({
  component: ConnectionDetailPage,
})

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

function formatDateTime(value: string | null | undefined): string {
  if (!value) return "---"
  return new Date(value).toLocaleString()
}

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
            <CardContent className="text-muted-foreground">We could not load this connection.</CardContent>
          </Card>
        </PageSection>
      </PageContainer>
    )
  }

  const handleDelete = async () => {
    await deleteConnection.mutateAsync(connectionId)
    router.navigate({ to: "/connections" })
  }

  const currentSettingsText = settingsText ?? (data.settings ? JSON.stringify(data.settings, null, 2) : "")

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

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Connections"
        title={data.name}
        description={`${typeLabels[data.connectionType] ?? data.connectionType} · ${data.provider}`}
        breadcrumbs={
          <Breadcrumb>
            <BreadcrumbList>
              <BreadcrumbItem><BreadcrumbLink asChild><Link to="/home">Home</Link></BreadcrumbLink></BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem><BreadcrumbLink asChild><Link to="/connections">Connections</Link></BreadcrumbLink></BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem><BreadcrumbPage>{data.name}</BreadcrumbPage></BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
        actions={
          <div className="flex items-center gap-3">
            <StatusBadge status={data.status} />
            {!data.isEnabled && (
              <Badge variant="outline" className="border-muted-foreground/30 text-muted-foreground">
                Disabled
              </Badge>
            )}
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

      {/* Connection Info */}
      <PageSection>
        <Card>
          <CardHeader>
            <CardTitle>Connection Information</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-3">
              <InfoField label="Name" value={data.name} />
              <InfoField label="Type" value={typeLabels[data.connectionType] ?? data.connectionType} />
              <InfoField label="Provider" value={data.provider} />
              <InfoField label="Description" value={data.description} />
              <InfoField label="Enabled" value={data.isEnabled ? "Yes" : "No"} />
              <InfoField label="Created" value={formatDateTime(data.createdAt)} />
            </div>
          </CardContent>
        </Card>
      </PageSection>

      {/* Configuration */}
      <PageSection delay={0.1}>
        <Card>
          <CardHeader>
            <CardTitle>Configuration</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-3">
              <InfoField label="Host" value={data.host} mono />
              <InfoField label="Port" value={data.port != null ? String(data.port) : null} mono />
              <InfoField label="Auth Type" value={authTypeLabels[data.authType] ?? data.authType} />
              {data.credentialFields.length > 0 && (
                <div className="md:col-span-2 lg:col-span-3">
                  <p className="text-muted-foreground">Credentials</p>
                  <div className="mt-1 flex flex-wrap gap-2">
                    {data.credentialFields.map((field) => (
                      <Badge key={field} variant="outline" className="font-mono text-xs">
                        {field}: ••••••••
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </PageSection>

      {/* Status */}
      <PageSection delay={0.2}>
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle>Status</CardTitle>
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
                Test Connection
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-3">
              <InfoField label="Status">
                <StatusBadge status={data.status} />
              </InfoField>
              <InfoField label="Last Health Check" value={formatDateTime(data.lastHealthCheck)} />
              <InfoField label="Last Error" value={data.lastError} />
            </div>
          </CardContent>
        </Card>
      </PageSection>

      {/* Settings JSON */}
      <PageSection delay={0.3}>
        <Card>
          <CardHeader>
            <CardTitle>Settings</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
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
              {settingsError && <p className="text-destructive text-sm">{settingsError}</p>}
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
                {updateConnection.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Save Settings
              </Button>
            </div>
          </CardContent>
        </Card>
      </PageSection>

      {/* Danger Zone */}
      <PageSection delay={0.4}>
        <Card className="border-destructive/30">
          <CardHeader>
            <CardTitle className="text-destructive">Danger Zone</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium text-sm">Delete this connection</p>
                <p className="text-sm text-muted-foreground">
                  This action cannot be undone. All configuration and credentials will be permanently removed.
                </p>
              </div>
              <Button variant="destructive" size="sm" onClick={() => setDeleteOpen(true)}>
                <Trash2 className="mr-2 h-4 w-4" /> Delete
              </Button>
              <Dialog open={deleteOpen} onOpenChange={setDeleteOpen}>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle className="flex items-center gap-2">
                      <AlertTriangle className="h-5 w-5 text-destructive" />
                      Delete connection?
                    </DialogTitle>
                    <DialogDescription>
                      This will permanently delete <strong>{data.name}</strong> and all associated configuration. This
                      action cannot be undone.
                    </DialogDescription>
                  </DialogHeader>
                  <DialogFooter>
                    <Button variant="outline" onClick={() => setDeleteOpen(false)} disabled={deleteConnection.isPending}>
                      Cancel
                    </Button>
                    <Button
                      variant="destructive"
                      onClick={() => {
                        handleDelete()
                        setDeleteOpen(false)
                      }}
                      disabled={deleteConnection.isPending}
                    >
                      {deleteConnection.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                      Delete
                    </Button>
                  </DialogFooter>
                </DialogContent>
              </Dialog>
            </div>
          </CardContent>
        </Card>
      </PageSection>
    </PageContainer>
  )
}

// ── Info Field helper ─────────────────────────────────────────────────

function InfoField({
  label,
  value,
  mono,
  children,
}: {
  label: string
  value?: string | null
  mono?: boolean
  children?: React.ReactNode
}) {
  return (
    <div>
      <p className="text-muted-foreground">{label}</p>
      {children ?? <p className={mono ? "font-mono text-xs" : ""}>{value ?? "---"}</p>}
    </div>
  )
}
