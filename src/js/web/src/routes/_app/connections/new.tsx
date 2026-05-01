import { createFileRoute, Link, useBlocker, useRouter } from "@tanstack/react-router"
import { useCallback, useMemo, useRef, useState } from "react"
import {
  AlertTriangle,
  ChevronRight,
  Globe,
  Headphones,
  Info,
  KeyRound,
  Loader2,
  Lock,
  Phone,
  Plug,
  ShieldCheck,
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
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader } from "@/components/ui/page-layout"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { Textarea } from "@/components/ui/textarea"
import { useAuth } from "@/hooks/use-auth"
import { useCreateConnection, type ConnectionCreate } from "@/lib/api/hooks/connections"
import { cn } from "@/lib/utils"

export const Route = createFileRoute("/_app/connections/new")({
  component: NewConnectionPage,
})

// ── Field limits ────────────────────────────────────────────────────────

const NAME_MAX = 100
const PROVIDER_MAX = 100
const DESC_MAX = 500

// ── Static data ──────────────────────────────────────────────────────────

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
  { value: "pbx", label: "PBX / Phone Server", icon: Phone },
  { value: "helpdesk", label: "Helpdesk / Ticketing", icon: Headphones },
  { value: "carrier", label: "Telephone Carrier", icon: Globe },
  { value: "other", label: "Other", icon: Plug },
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

// ── Validation helpers ───────────────────────────────────────────────────

interface FieldErrors {
  name?: string
  provider?: string
  host?: string
  port?: string
}

function validateHost(value: string): string | undefined {
  if (!value) return undefined
  // Allow hostname, IP, or URL with optional protocol
  const hostPattern = /^(https?:\/\/)?[\w.-]+(:\d+)?(\/.*)?$/i
  if (!hostPattern.test(value)) {
    return "Enter a valid hostname or URL (e.g., pbx.example.com or https://api.example.com)"
  }
  return undefined
}

function validatePort(value: string): string | undefined {
  if (!value) return undefined
  const num = Number(value)
  if (!Number.isInteger(num) || num < 1 || num > 65535) {
    return "Port must be between 1 and 65535"
  }
  return undefined
}

/** Required-field asterisk. */
function RequiredMark() {
  return <span className="text-destructive">*</span>
}

/** Small helper-text below a field. */
function FieldHint({ children }: { children: React.ReactNode }) {
  return <p className="text-xs text-muted-foreground">{children}</p>
}

/** Inline field error message. */
function FieldError({ message }: { message?: string }) {
  if (!message) return null
  return <p className="text-sm text-destructive">{message}</p>
}

// ── Page component ───────────────────────────────────────────────────────

function NewConnectionPage() {
  const router = useRouter()
  const { currentTeam } = useAuth()
  const createConnection = useCreateConnection()

  // Form state
  const [name, setName] = useState("")
  const [connectionType, setConnectionType] = useState("pbx")
  const [provider, setProvider] = useState("")
  const [host, setHost] = useState("")
  const [port, setPort] = useState("")
  const [authType, setAuthType] = useState("none")
  const [credentials, setCredentials] = useState<Record<string, string>>({})
  const [description, setDescription] = useState("")
  const [verifySsl, setVerifySsl] = useState(true)
  const [gatewayTimeout, setGatewayTimeout] = useState("")
  const [gatewayCacheTtl, setGatewayCacheTtl] = useState("")

  // Validation state
  const [errors, setErrors] = useState<FieldErrors>({})
  const [touched, setTouched] = useState<Record<string, boolean>>({})

  // Auth-type change confirmation
  const [pendingAuthType, setPendingAuthType] = useState<string | null>(null)
  const hasCredentials = Object.values(credentials).some((v) => v.trim() !== "")

  const credentialFields = getCredentialFields(authType)

  // Track whether the form has been modified (for unsaved-changes blocker)
  const formDirty = useMemo(
    () =>
      name !== "" ||
      provider !== "" ||
      host !== "" ||
      port !== "" ||
      description !== "" ||
      authType !== "none" ||
      connectionType !== "pbx" ||
      gatewayTimeout !== "" ||
      gatewayCacheTtl !== "" ||
      Object.values(credentials).some((v) => v !== ""),
    [name, provider, host, port, description, authType, connectionType, gatewayTimeout, gatewayCacheTtl, credentials],
  )

  // Ref to skip blocking after a successful submit
  const justSubmittedRef = useRef(false)

  // Block navigation when form is dirty
  const blocker = useBlocker({
    shouldBlockFn: () => formDirty && !justSubmittedRef.current,
    withResolver: true,
  })

  // ── Field handlers ───────────────────────────────────────────────────

  const markTouched = useCallback((field: string) => {
    setTouched((prev) => ({ ...prev, [field]: true }))
  }, [])

  const validateField = useCallback((field: keyof FieldErrors, value: string) => {
    let error: string | undefined
    switch (field) {
      case "name":
        error = value.trim() === "" ? "Name is required" : undefined
        break
      case "provider":
        error = value.trim() === "" ? "Provider is required" : undefined
        break
      case "host":
        error = validateHost(value)
        break
      case "port":
        error = validatePort(value)
        break
    }
    setErrors((prev) => ({ ...prev, [field]: error }))
    return error
  }, [])

  const handleFieldChange = useCallback(
    (field: keyof FieldErrors, value: string, setter: (v: string) => void) => {
      setter(value)
      if (touched[field]) {
        validateField(field, value)
      }
    },
    [touched, validateField],
  )

  const handleFieldBlur = useCallback(
    (field: keyof FieldErrors, value: string) => {
      markTouched(field)
      validateField(field, value)
    },
    [markTouched, validateField],
  )

  const handleCredentialChange = (key: string, value: string) => {
    setCredentials((prev) => ({ ...prev, [key]: value }))
  }

  // ── Auth type change with confirmation ───────────────────────────────

  const handleAuthTypeChange = (newType: string) => {
    if (hasCredentials && newType !== authType) {
      setPendingAuthType(newType)
    } else {
      setAuthType(newType)
      setCredentials({})
    }
  }

  const confirmAuthTypeChange = () => {
    if (pendingAuthType) {
      setAuthType(pendingAuthType)
      setCredentials({})
      setPendingAuthType(null)
    }
  }

  const cancelAuthTypeChange = () => {
    setPendingAuthType(null)
  }

  // ── Submit ───────────────────────────────────────────────────────────

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    if (!currentTeam) return

    // Validate all fields before submit
    const nameError = validateField("name", name)
    const providerError = validateField("provider", provider)
    const hostError = validateField("host", host)
    const portError = validateField("port", port)
    setTouched({ name: true, provider: true, host: true, port: true })

    if (nameError || providerError || hostError || portError) return

    const payload: ConnectionCreate = {
      name,
      connectionType,
      provider: provider.toLowerCase(),
      authType,
      teamId: currentTeam.id,
    }

    if (host) payload.host = host
    if (port) payload.port = Number.parseInt(port, 10)
    if (description) payload.description = description

    const settings: Record<string, unknown> = { verify_ssl: verifySsl }
    if (gatewayTimeout.trim()) settings.timeout = parseInt(gatewayTimeout, 10)
    if (gatewayCacheTtl.trim()) settings.cache_ttl = parseInt(gatewayCacheTtl, 10)
    payload.settings = settings

    // Only include credentials if auth type requires them and values are provided
    if (authType !== "none" && Object.keys(credentials).length > 0) {
      const creds: Record<string, unknown> = {}
      for (const field of credentialFields) {
        if (credentials[field.key]) {
          if (field.key === "scopes") {
            creds[field.key] = credentials[field.key]
              .split(",")
              .map((s) => s.trim())
              .filter(Boolean)
          } else {
            creds[field.key] = credentials[field.key]
          }
        }
      }
      if (Object.keys(creds).length > 0) {
        payload.credentials = creds
      }
    }

    justSubmittedRef.current = true
    createConnection.mutate(payload, {
      onSuccess: () => {
        router.navigate({ to: "/connections" })
      },
      onError: () => {
        justSubmittedRef.current = false
      },
    })
  }

  const isValid =
    name.trim() !== "" &&
    provider.trim() !== "" &&
    !errors.host &&
    !errors.port &&
    !!currentTeam

  // Get the icon for the currently selected connection type
  const selectedTypeIcon = connectionTypes.find((t) => t.value === connectionType)?.icon

  return (
    <>
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Connections"
        title="New Connection"
        description="Add a new external data source integration."
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
                <BreadcrumbPage>New Connection</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
      />

      <div className="flex gap-6">
        {/* Main form */}
        <Card className="min-w-0 flex-1">
          <CardHeader>
            <CardTitle className="text-lg">Connection Details</CardTitle>
            <CardDescription>
              Fields marked with <span className="text-destructive">*</span> are required.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-6">
              {/* Basic Info */}
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="conn-name">
                    Name <RequiredMark />
                  </Label>
                  <Input
                    id="conn-name"
                    placeholder="e.g., Production PBX"
                    value={name}
                    onChange={(e) => {
                      if (e.target.value.length <= NAME_MAX) handleFieldChange("name", e.target.value, setName)
                    }}
                    onBlur={() => handleFieldBlur("name", name)}
                    aria-invalid={!!errors.name}
                    maxLength={NAME_MAX}
                    required
                  />
                  <div className="flex items-center justify-between">
                    {errors.name ? (
                      <FieldError message={errors.name} />
                    ) : (
                      <FieldHint>A descriptive name to identify this connection.</FieldHint>
                    )}
                    <p className={cn("shrink-0 text-xs", name.length >= NAME_MAX ? "text-red-500" : "text-muted-foreground")}>
                      {name.length}/{NAME_MAX}
                    </p>
                  </div>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="conn-type">
                    Type <RequiredMark />
                  </Label>
                  <Select value={connectionType} onValueChange={setConnectionType}>
                    <SelectTrigger id="conn-type">
                      <span className="flex items-center gap-2">
                        {selectedTypeIcon &&
                          (() => {
                            const Icon = selectedTypeIcon
                            return <Icon className="h-4 w-4 text-muted-foreground" />
                          })()}
                        <SelectValue />
                      </span>
                    </SelectTrigger>
                    <SelectContent>
                      {connectionTypes.map((t) => (
                        <SelectItem key={t.value} value={t.value}>
                          <span className="flex items-center gap-2">
                            <t.icon className="h-4 w-4 text-muted-foreground" />
                            {t.label}
                          </span>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <FieldHint>The category of system you are connecting to.</FieldHint>
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="conn-provider">
                  Provider <RequiredMark />
                </Label>
                <Input
                  id="conn-provider"
                  placeholder="e.g., FreePBX, Zendesk, Twilio"
                  value={provider}
                  onChange={(e) => {
                    if (e.target.value.length <= PROVIDER_MAX) handleFieldChange("provider", e.target.value, setProvider)
                  }}
                  onBlur={() => handleFieldBlur("provider", provider)}
                  aria-invalid={!!errors.provider}
                  maxLength={PROVIDER_MAX}
                  required
                />
                <div className="flex items-center justify-between">
                  {errors.provider ? (
                    <FieldError message={errors.provider} />
                  ) : (
                    <FieldHint>The specific software or service provider (e.g., FreePBX, Zendesk).</FieldHint>
                  )}
                  <p className={cn("shrink-0 text-xs", provider.length >= PROVIDER_MAX ? "text-red-500" : "text-muted-foreground")}>
                    {provider.length}/{PROVIDER_MAX}
                  </p>
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="conn-description">Description</Label>
                <Textarea
                  id="conn-description"
                  placeholder="Optional description of this connection"
                  value={description}
                  onChange={(e) => {
                    if (e.target.value.length <= DESC_MAX) setDescription(e.target.value)
                  }}
                  maxLength={DESC_MAX}
                  rows={2}
                />
                <div className="flex items-center justify-between">
                  <FieldHint>Optional notes about the purpose or configuration of this connection.</FieldHint>
                  <p className={cn("shrink-0 text-xs", description.length >= DESC_MAX ? "text-red-500" : "text-muted-foreground")}>
                    {description.length}/{DESC_MAX}
                  </p>
                </div>
              </div>

              {/* Host / Port */}
              <div className="grid gap-4 md:grid-cols-3">
                <div className="space-y-2 md:col-span-2">
                  <Label htmlFor="conn-host">Host / URL</Label>
                  <Input
                    id="conn-host"
                    placeholder="e.g., pbx.example.com or https://api.example.com"
                    value={host}
                    onChange={(e) => handleFieldChange("host", e.target.value, setHost)}
                    onBlur={() => handleFieldBlur("host", host)}
                    aria-invalid={!!errors.host}
                  />
                  {errors.host ? (
                    <FieldError message={errors.host} />
                  ) : (
                    <FieldHint>The hostname, IP address, or full URL of the remote service.</FieldHint>
                  )}
                </div>
                <div className="space-y-2">
                  <Label htmlFor="conn-port">Port</Label>
                  <Input
                    id="conn-port"
                    type="number"
                    placeholder="e.g., 443"
                    value={port}
                    onChange={(e) => handleFieldChange("port", e.target.value, setPort)}
                    onBlur={() => handleFieldBlur("port", port)}
                    aria-invalid={!!errors.port}
                    min={1}
                    max={65535}
                  />
                  {errors.port ? (
                    <FieldError message={errors.port} />
                  ) : (
                    <FieldHint>1 - 65535. Leave blank to use the default.</FieldHint>
                  )}
                </div>
              </div>

              {/* Auth Type */}
              <div className="space-y-2">
                <Label htmlFor="conn-auth">Authentication Type</Label>
                <Select value={authType} onValueChange={handleAuthTypeChange}>
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
                <FieldHint>How the connection authenticates with the remote service.</FieldHint>
              </div>

              {/* Credential Fields */}
              {credentialFields.length > 0 && (
                <div className="space-y-4 rounded-lg border border-border/60 bg-muted/20 p-4">
                  <div className="flex items-center gap-2">
                    <Lock className="h-4 w-4 text-muted-foreground" />
                    <p className="font-medium text-sm">Credentials</p>
                  </div>
                  <div className="flex items-start gap-2 rounded-md bg-muted/40 px-3 py-2">
                    <Info className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                    <p className="text-xs text-muted-foreground">
                      Credentials are encrypted at rest and never displayed after saving. Only authorized team members
                      can update them.
                    </p>
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
                          placeholder={field.placeholder ?? `Enter ${field.label.toLowerCase()}`}
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

              {/* Gateway Overrides */}
              <div className="space-y-4 rounded-lg border border-border/60 bg-muted/20 p-4">
                <div className="flex items-center gap-2">
                  <Info className="h-4 w-4 text-muted-foreground" />
                  <p className="font-medium text-sm">Gateway Overrides</p>
                </div>
                <p className="text-xs text-muted-foreground">
                  Override global gateway defaults for this connection. Leave empty to use the global defaults.
                </p>
                <div className="grid gap-4 md:grid-cols-2">
                  <div className="space-y-2">
                    <Label htmlFor="conn-gateway-timeout">Timeout</Label>
                    <div className="flex items-center gap-2">
                      <Input
                        id="conn-gateway-timeout"
                        type="number"
                        min={1}
                        max={300}
                        value={gatewayTimeout}
                        onChange={(e) => setGatewayTimeout(e.target.value)}
                        placeholder="Uses global default"
                      />
                      <span className="shrink-0 text-xs text-muted-foreground">sec</span>
                    </div>
                    <FieldHint>Request timeout for this provider (1-300s).</FieldHint>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="conn-gateway-cache-ttl">Cache TTL</Label>
                    <div className="flex items-center gap-2">
                      <Input
                        id="conn-gateway-cache-ttl"
                        type="number"
                        min={0}
                        max={86400}
                        value={gatewayCacheTtl}
                        onChange={(e) => setGatewayCacheTtl(e.target.value)}
                        placeholder="Uses global default"
                      />
                      <span className="shrink-0 text-xs text-muted-foreground">sec</span>
                    </div>
                    <FieldHint>Cache duration for responses (0-86400s).</FieldHint>
                  </div>
                </div>
              </div>

              {/* Submit */}
              <div className="flex items-center justify-end gap-2 pt-2">
                <Button type="button" variant="ghost" onClick={() => router.navigate({ to: "/connections" })}>
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

        {/* Sidebar */}
        <div className="flex h-fit w-72 shrink-0 flex-col gap-4">
          {/* Connection Types tip card */}
          <Card className="border-border/40 bg-linear-to-br from-muted/30 to-muted/10">
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

          {/* Security Note */}
          <Card className="border-border/40">
            <CardHeader className="space-y-1 pb-3">
              <div className="flex items-center gap-2">
                <KeyRound className="h-4 w-4 text-muted-foreground" />
                <CardTitle className="text-sm">Security Note</CardTitle>
              </div>
            </CardHeader>
            <CardContent className="space-y-3">
              <p className="text-xs leading-relaxed text-muted-foreground">
                All credentials are encrypted using AES-256 before being stored. They are never exposed in API
                responses or logs.
              </p>
              <p className="text-xs leading-relaxed text-muted-foreground">
                After creation, credential values can only be replaced -- not viewed. Use the
                <span className="font-medium text-foreground"> Test Connection </span>
                feature to verify credentials without revealing them.
              </p>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Auth type change confirmation dialog */}
      <AlertDialog open={pendingAuthType !== null} onOpenChange={(open) => !open && cancelAuthTypeChange()}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-warning" />
              Change Authentication Type?
            </AlertDialogTitle>
            <AlertDialogDescription>
              Switching the authentication type will clear all credential fields you have filled in. This cannot be
              undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={cancelAuthTypeChange}>Keep Current</AlertDialogCancel>
            <AlertDialogAction onClick={confirmAuthTypeChange}>Clear &amp; Switch</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

    </PageContainer>

    {/* -- Unsaved changes dialog ---------------------------------------- */}
    <AlertDialog open={blocker.status === "blocked"} onOpenChange={() => blocker.reset?.()}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Unsaved changes</AlertDialogTitle>
          <AlertDialogDescription>
            You have unsaved changes to this connection. Are you sure you want to leave? Your changes will be lost.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel onClick={() => blocker.reset?.()}>Stay on page</AlertDialogCancel>
          <AlertDialogAction onClick={() => blocker.proceed?.()}>Discard changes</AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
    </>
  )
}
