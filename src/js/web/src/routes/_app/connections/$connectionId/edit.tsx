import { createFileRoute, Link, useRouter } from "@tanstack/react-router"
import { useEffect, useState } from "react"
import { Loader2, ShieldCheck } from "lucide-react"
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { Textarea } from "@/components/ui/textarea"
import { useConnection, useUpdateConnection, type ConnectionUpdate } from "@/lib/api/hooks/connections"

export const Route = createFileRoute("/_app/connections/$connectionId/edit")({
  component: EditConnectionPage,
})

const connectionTypes = [
  { value: "pbx", label: "PBX / Phone Server" },
  { value: "helpdesk", label: "Helpdesk / Ticketing" },
  { value: "carrier", label: "Telephone Carrier" },
  { value: "other", label: "Other" },
]

const authTypes = [
  { value: "none", label: "None" },
  { value: "api_key", label: "API Key" },
  { value: "basic", label: "Basic Auth (Username/Password)" },
  { value: "oauth2", label: "OAuth 2.0" },
  { value: "token", label: "Bearer Token" },
]

/** Returns credential input fields based on the selected auth type. */
function getCredentialFields(authType: string): { key: string; label: string; type: string; placeholder?: string }[] {
  switch (authType) {
    case "api_key":
      return [{ key: "api_key", label: "API Key", type: "password" }]
    case "basic":
      return [
        { key: "username", label: "Username", type: "text" },
        { key: "password", label: "Password", type: "password" },
      ]
    case "oauth2":
      return [
        { key: "client_id", label: "Client ID", type: "text" },
        { key: "client_secret", label: "Client Secret", type: "password" },
        { key: "scopes", label: "Scopes (comma-separated)", type: "text", placeholder: "e.g. gql:core, gql:ringgroup, gql:findmefollow" },
      ]
    case "token":
      return [{ key: "token", label: "Token", type: "password" }]
    default:
      return []
  }
}

function EditConnectionPage() {
  const { connectionId } = Route.useParams()
  const router = useRouter()
  const { data, isLoading, isError } = useConnection(connectionId)
  const updateConnection = useUpdateConnection(connectionId)

  const [name, setName] = useState("")
  const [connectionType, setConnectionType] = useState("pbx")
  const [provider, setProvider] = useState("")
  const [host, setHost] = useState("")
  const [port, setPort] = useState("")
  const [authType, setAuthType] = useState("none")
  const [credentials, setCredentials] = useState<Record<string, string>>({})
  const [description, setDescription] = useState("")
  const [verifySsl, setVerifySsl] = useState(true)
  const [settingsText, setSettingsText] = useState("")
  const [initialized, setInitialized] = useState(false)

  // Pre-populate form fields when connection data loads
  useEffect(() => {
    if (data && !initialized) {
      setName(data.name)
      setConnectionType(data.connectionType)
      setProvider(data.provider)
      setHost(data.host ?? "")
      setPort(data.port != null ? String(data.port) : "")
      setAuthType(data.authType ?? "none")
      setDescription(data.description ?? "")
      setVerifySsl(data.settings?.verify_ssl !== false)
      setSettingsText(data.settings ? JSON.stringify(data.settings, null, 2) : "")
      setInitialized(true)
    }
  }, [data, initialized])

  const credentialFields = getCredentialFields(authType)

  const handleCredentialChange = (key: string, value: string) => {
    setCredentials((prev) => ({ ...prev, [key]: value }))
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    if (!data) return

    const payload: ConnectionUpdate = {}

    // Only include fields that changed
    if (name !== data.name) payload.name = name
    if (connectionType !== data.connectionType) payload.connectionType = connectionType
    if (provider !== data.provider) payload.provider = provider
    if ((host || null) !== (data.host || null)) payload.host = host || null
    if (description !== (data.description ?? "")) payload.description = description || null

    const currentPort = port ? parseInt(port, 10) : null
    if (currentPort !== (data.port ?? null)) payload.port = currentPort

    if (authType !== (data.authType ?? "none")) payload.authType = authType

    // Parse settings JSON
    const trimmedSettings = settingsText.trim()
    let parsedSettings: Record<string, unknown> | null = null
    if (trimmedSettings) {
      try {
        parsedSettings = JSON.parse(trimmedSettings)
      } catch {
        // Keep existing settings if JSON is invalid
        parsedSettings = data.settings ?? null
      }
    }

    // Check if verify_ssl changed — merge into settings
    const originalVerifySsl = data.settings?.verify_ssl !== false
    if (verifySsl !== originalVerifySsl || parsedSettings !== null) {
      const base = parsedSettings ?? data.settings ?? {}
      payload.settings = { ...base, verify_ssl: verifySsl }
    }

    // Only include credentials if the user actually entered new values
    if (authType !== "none" && Object.keys(credentials).length > 0) {
      const creds: Record<string, unknown> = {}
      for (const field of credentialFields) {
        if (credentials[field.key]) {
          if (field.key === "scopes") {
            creds[field.key] = credentials[field.key].split(",").map((s) => s.trim()).filter(Boolean)
          } else {
            creds[field.key] = credentials[field.key]
          }
        }
      }
      if (Object.keys(creds).length > 0) {
        payload.credentials = creds
      }
    }

    // If auth type changed to "none", clear credentials
    if (authType === "none" && data.authType !== "none") {
      payload.credentials = null
    }

    updateConnection.mutate(payload, {
      onSuccess: () => {
        router.navigate({
          to: "/connections/$connectionId",
          params: { connectionId },
        })
      },
    })
  }

  const isValid = name.trim() !== "" && provider.trim() !== ""

  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader eyebrow="Connections" title="Edit Connection" />
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
          title="Edit Connection"
          actions={
            <Button variant="outline" size="sm" asChild>
              <Link to="/connections">Back to connections</Link>
            </Button>
          }
        />
        <PageSection>
          <Card>
            <CardHeader>
              <CardTitle>Error</CardTitle>
            </CardHeader>
            <CardContent className="text-muted-foreground">We could not load this connection.</CardContent>
          </Card>
        </PageSection>
      </PageContainer>
    )
  }

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Connections"
        title="Edit Connection"
        description={`Editing ${data.name}`}
        breadcrumbs={
          <Breadcrumb>
            <BreadcrumbList>
              <BreadcrumbItem><BreadcrumbLink asChild><Link to="/home">Home</Link></BreadcrumbLink></BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem><BreadcrumbLink asChild><Link to="/connections">Connections</Link></BreadcrumbLink></BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbLink asChild>
                  <Link to="/connections/$connectionId" params={{ connectionId }}>{data.name}</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem><BreadcrumbPage>Edit</BreadcrumbPage></BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Connection Details</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Basic Info */}
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="conn-name">Name *</Label>
                <Input
                  id="conn-name"
                  placeholder="e.g., Production PBX"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="conn-type">Type *</Label>
                <Select value={connectionType} onValueChange={setConnectionType}>
                  <SelectTrigger id="conn-type">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {connectionTypes.map((t) => (
                      <SelectItem key={t.value} value={t.value}>
                        {t.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="conn-provider">Provider *</Label>
              <Input
                id="conn-provider"
                placeholder="e.g., FreePBX, Zendesk, Twilio"
                value={provider}
                onChange={(e) => setProvider(e.target.value)}
                required
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="conn-description">Description</Label>
              <Textarea
                id="conn-description"
                placeholder="Optional description of this connection"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={2}
              />
            </div>

            {/* Host / Port */}
            <div className="grid gap-4 md:grid-cols-3">
              <div className="space-y-2 md:col-span-2">
                <Label htmlFor="conn-host">Host / URL</Label>
                <Input
                  id="conn-host"
                  placeholder="e.g., pbx.example.com or https://api.example.com"
                  value={host}
                  onChange={(e) => setHost(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="conn-port">Port</Label>
                <Input
                  id="conn-port"
                  type="number"
                  placeholder="e.g., 443"
                  value={port}
                  onChange={(e) => setPort(e.target.value)}
                  min={1}
                  max={65535}
                />
              </div>
            </div>

            {/* Auth Type */}
            <div className="space-y-2">
              <Label htmlFor="conn-auth">Authentication Type</Label>
              <Select
                value={authType}
                onValueChange={(v) => {
                  setAuthType(v)
                  setCredentials({})
                }}
              >
                <SelectTrigger id="conn-auth">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {authTypes.map((t) => (
                    <SelectItem key={t.value} value={t.value}>
                      {t.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {/* Credential Fields */}
            {credentialFields.length > 0 && (
              <div className="space-y-4 rounded-lg border border-border/60 bg-muted/20 p-4">
                <div>
                  <p className="font-medium text-sm">Credentials</p>
                  <p className="text-xs text-muted-foreground">Leave fields blank to keep existing credentials unchanged.</p>
                </div>
                <div className="grid gap-4 md:grid-cols-2">
                  {credentialFields.map((field) => (
                    <div key={field.key} className={`space-y-2 ${field.key === "scopes" ? "md:col-span-2" : ""}`}>
                      <Label htmlFor={`cred-${field.key}`}>{field.label}</Label>
                      <Input
                        id={`cred-${field.key}`}
                        type={field.type}
                        value={credentials[field.key] ?? ""}
                        onChange={(e) => handleCredentialChange(field.key, e.target.value)}
                        placeholder={
                          data.credentialFields.includes(field.key)
                            ? "••••••••"
                            : field.placeholder ?? `Enter ${field.label.toLowerCase()}`
                        }
                      />
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* SSL Verification */}
            <div className="flex items-center justify-between rounded-lg border border-border/60 bg-muted/20 p-4">
              <div className="flex items-center gap-3">
                <ShieldCheck className="h-4 w-4 text-muted-foreground" />
                <div>
                  <p className="font-medium text-sm">Verify SSL Certificate</p>
                  <p className="text-xs text-muted-foreground">Disable for self-signed certificates</p>
                </div>
              </div>
              <Switch checked={verifySsl} onCheckedChange={setVerifySsl} />
            </div>

            {/* Settings JSON */}
            <div className="space-y-2">
              <Label htmlFor="conn-settings">Settings JSON</Label>
              <Textarea
                id="conn-settings"
                value={settingsText}
                onChange={(e) => setSettingsText(e.target.value)}
                rows={6}
                className="font-mono text-xs"
                placeholder='{"key": "value"}'
              />
            </div>

            {/* Submit */}
            <div className="flex items-center justify-end gap-2 pt-2">
              <Button
                type="button"
                variant="ghost"
                onClick={() =>
                  router.navigate({
                    to: "/connections/$connectionId",
                    params: { connectionId },
                  })
                }
              >
                Cancel
              </Button>
              <Button type="submit" disabled={!isValid || updateConnection.isPending}>
                {updateConnection.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Save Changes
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </PageContainer>
  )
}
