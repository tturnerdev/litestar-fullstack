import { createFileRoute, useRouter } from "@tanstack/react-router"
import { useState } from "react"
import { ChevronRight, Globe, Headphones, Loader2, Phone, Plug } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader } from "@/components/ui/page-layout"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"
import { useCreateConnection, type ConnectionCreate } from "@/lib/api/hooks/connections"

export const Route = createFileRoute("/_app/connections/new")({
  component: NewConnectionPage,
})

const tips = [
  {
    icon: Phone,
    title: "PBX / Phone Server",
    description: "Connect to FreePBX, Asterisk, 3CX, etc.",
  },
  {
    icon: Headphones,
    title: "Helpdesk",
    description: "Connect to Zendesk, Freshdesk, etc.",
  },
  {
    icon: Globe,
    title: "Carrier / DID Provider",
    description: "Connect to Twilio, Telnyx, etc.",
  },
  {
    icon: Plug,
    title: "Other Sources",
    description: "Any external API or data source",
  },
]

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
function getCredentialFields(authType: string): { key: string; label: string; type: string }[] {
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
      ]
    case "token":
      return [{ key: "token", label: "Token", type: "password" }]
    default:
      return []
  }
}

function NewConnectionPage() {
  const router = useRouter()
  const createConnection = useCreateConnection()

  const [name, setName] = useState("")
  const [connectionType, setConnectionType] = useState("pbx")
  const [provider, setProvider] = useState("")
  const [host, setHost] = useState("")
  const [port, setPort] = useState("")
  const [authType, setAuthType] = useState("none")
  const [credentials, setCredentials] = useState<Record<string, string>>({})
  const [description, setDescription] = useState("")

  const credentialFields = getCredentialFields(authType)

  const handleCredentialChange = (key: string, value: string) => {
    setCredentials((prev) => ({ ...prev, [key]: value }))
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    const payload: ConnectionCreate = {
      name,
      connectionType,
      provider,
      authType,
    }

    if (host) payload.host = host
    if (port) payload.port = parseInt(port, 10)
    if (description) payload.description = description

    // Only include credentials if auth type requires them and values are provided
    if (authType !== "none" && Object.keys(credentials).length > 0) {
      const creds: Record<string, unknown> = {}
      for (const field of credentialFields) {
        if (credentials[field.key]) {
          creds[field.key] = credentials[field.key]
        }
      }
      if (Object.keys(creds).length > 0) {
        payload.credentials = creds
      }
    }

    createConnection.mutate(payload, {
      onSuccess: () => {
        router.navigate({ to: "/connections" })
      },
    })
  }

  const isValid = name.trim() !== "" && provider.trim() !== ""

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Connections"
        title="New Connection"
        description="Add a new external data source integration."
      />

      <div className="flex gap-6">
        {/* Main form */}
        <Card className="min-w-0 flex-1">
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
                  <p className="font-medium text-sm">Credentials</p>
                  <div className="grid gap-4 md:grid-cols-2">
                    {credentialFields.map((field) => (
                      <div key={field.key} className="space-y-2">
                        <Label htmlFor={`cred-${field.key}`}>{field.label}</Label>
                        <Input
                          id={`cred-${field.key}`}
                          type={field.type}
                          value={credentials[field.key] ?? ""}
                          onChange={(e) => handleCredentialChange(field.key, e.target.value)}
                          placeholder={`Enter ${field.label.toLowerCase()}`}
                        />
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Submit */}
              <div className="flex items-center justify-end gap-2 pt-2">
                <Button
                  type="button"
                  variant="ghost"
                  onClick={() => router.navigate({ to: "/connections" })}
                >
                  Cancel
                </Button>
                <Button type="submit" disabled={!isValid || createConnection.isPending}>
                  {createConnection.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  Create Connection
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>

        {/* Sidebar tips */}
        <Card className="h-fit w-72 shrink-0 border-border/40 bg-linear-to-br from-muted/30 to-muted/10">
          <CardHeader className="space-y-1 pb-3">
            <CardTitle className="text-lg">Connection Types</CardTitle>
            <CardDescription>Supported integrations</CardDescription>
          </CardHeader>
          <CardContent className="space-y-1.5">
            {tips.map((tip) => (
              <div key={tip.title} className="group flex items-center gap-3 rounded-lg bg-background/60 p-3">
                <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
                  <tip.icon className="h-4 w-4" />
                </div>
                <div className="min-w-0 flex-1">
                  <p className="font-medium text-sm">{tip.title}</p>
                  <p className="text-xs text-muted-foreground">{tip.description}</p>
                </div>
                <ChevronRight className="h-4 w-4 text-muted-foreground/30" />
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </PageContainer>
  )
}
