import { createFileRoute, Link, useBlocker, useRouter } from "@tanstack/react-router"
import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import {
  AlertCircle,
  AlertTriangle,
  ChevronRight,
  Globe,
  Headphones,
  Info,
  KeyRound,
  Loader2,
  Lock,
  Network,
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
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { Textarea } from "@/components/ui/textarea"
import { useConnection, useUpdateConnection, type ConnectionUpdate } from "@/lib/api/hooks/connections"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { cn } from "@/lib/utils"

export const Route = createFileRoute("/_app/connections/$connectionId/edit")({
  component: EditConnectionPage,
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
    icon: Network,
    title: "Network Gateway",
    description: "Connect to UniFi, Meraki, etc.",
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
  { value: "network", label: "Network Gateway", icon: Network },
  { value: "other", label: "Other", icon: Plug },
]

const authTypes = [
  { value: "none", label: "None" },
  { value: "api_key", label: "API Key" },
  { value: "basic", label: "Basic Auth (Username/Password)" },
  { value: "oauth2", label: "OAuth 2.0" },
  { value: "token", label: "Bearer Token" },
]

// ── Provider presets ────────────────────────────────────────────────────

interface ProviderPreset {
  value: string
  label: string
  connectionType: string
  authType: string
  hint: string
  hostPlaceholder: string
  hostHint: string
  portPlaceholder: string
  credentialsHint: string
  defaultSettings: { verify_ssl: boolean; timeout: number }
}

const providerPresets: ProviderPreset[] = [
  {
    value: "freepbx",
    label: "FreePBX",
    connectionType: "pbx",
    authType: "oauth2",
    hint: "Requires OAuth2 client credentials from FreePBX Admin -> Connectivity -> API -> Applications.",
    hostPlaceholder: "e.g., admin.example.com",
    hostHint: "Enter the FreePBX admin URL. Authentication requires OAuth2 client ID and secret.",
    portPlaceholder: "e.g., 443",
    credentialsHint: "Find credentials in FreePBX Admin -> Connectivity -> API -> Applications.",
    defaultSettings: { verify_ssl: true, timeout: 10 },
  },
  {
    value: "telnyx",
    label: "Telnyx",
    connectionType: "carrier",
    authType: "api_key",
    hint: "Requires an API key from the Telnyx Mission Control Portal.",
    hostPlaceholder: "e.g., api.telnyx.com",
    hostHint: "Uses API key authentication from your Telnyx portal.",
    portPlaceholder: "e.g., 443",
    credentialsHint: "Generate an API key at portal.telnyx.com under Auth -> API Keys.",
    defaultSettings: { verify_ssl: true, timeout: 10 },
  },
  {
    value: "unifi",
    label: "Unifi Network",
    connectionType: "network",
    authType: "api_key",
    hint: "Requires an API key from UniFi Console -> Settings -> API.",
    hostPlaceholder: "e.g., unifi.example.com",
    hostHint: "Enter the UniFi controller address. Uses API token authentication.",
    portPlaceholder: "e.g., 443",
    credentialsHint: "Create an API key in UniFi Console -> Settings -> API.",
    defaultSettings: { verify_ssl: false, timeout: 10 },
  },
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

function EditConnectionPage() {
  useDocumentTitle("Edit Connection")
  const { connectionId } = Route.useParams()
  const router = useRouter()
  const { data, isLoading, isError, refetch } = useConnection(connectionId)
  const updateConnection = useUpdateConnection(connectionId)

  // Form state
  const [name, setName] = useState("")
  const [connectionType, setConnectionType] = useState("pbx")
  const [provider, setProvider] = useState("")
  const [selectedPreset, setSelectedPreset] = useState<string | null>(null)
  const [host, setHost] = useState("")
  const [port, setPort] = useState("")
  const [authType, setAuthType] = useState("none")
  const [credentials, setCredentials] = useState<Record<string, string>>({})
  const [description, setDescription] = useState("")
  const [verifySsl, setVerifySsl] = useState(true)
  const [gatewayTimeout, setGatewayTimeout] = useState("")
  const [gatewayCacheTtl, setGatewayCacheTtl] = useState("")
  const [settingsText, setSettingsText] = useState("")
  const [initialized, setInitialized] = useState(false)

  // Validation state
  const [errors, setErrors] = useState<FieldErrors>({})
  const [touched, setTouched] = useState<Record<string, boolean>>({})

  // Auth-type change confirmation
  const [pendingAuthType, setPendingAuthType] = useState<string | null>(null)
  const hasCredentials = Object.values(credentials).some((v) => v.trim() !== "")
  // On the edit page, existing saved credentials also count
  const hasExistingCredentials = (data?.credentialFields?.length ?? 0) > 0

  const credentialFields = getCredentialFields(authType)

  // Reset form state when navigating to a different connection
  useEffect(() => {
    setInitialized(false)
    setSelectedPreset(null)
    setErrors({})
    setTouched({})
    setCredentials({})
    setPendingAuthType(null)
  }, [connectionId])

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
      setGatewayTimeout(data.settings?.timeout != null ? String(data.settings.timeout) : "")
      setGatewayCacheTtl(data.settings?.cache_ttl != null ? String(data.settings.cache_ttl) : "")
      setSettingsText(data.settings ? JSON.stringify(data.settings, null, 2) : "")
      // Detect if the existing provider matches a known preset (by value or label)
      const normalizedProvider = data.provider.toLowerCase()
      const matchedPreset = providerPresets.find(
        (p) => p.value === normalizedProvider || p.label.toLowerCase() === normalizedProvider,
      )
      setSelectedPreset(matchedPreset ? matchedPreset.value : "_custom")
      setInitialized(true)
    }
  }, [data, initialized])

  // Track whether the form has been modified relative to original data
  const formDirty = useMemo(() => {
    if (!data || !initialized) return false
    return (
      name !== data.name ||
      connectionType !== data.connectionType ||
      provider !== data.provider ||
      host !== (data.host ?? "") ||
      port !== (data.port != null ? String(data.port) : "") ||
      authType !== (data.authType ?? "none") ||
      description !== (data.description ?? "") ||
      verifySsl !== (data.settings?.verify_ssl !== false) ||
      gatewayTimeout !== (data.settings?.timeout != null ? String(data.settings.timeout) : "") ||
      gatewayCacheTtl !== (data.settings?.cache_ttl != null ? String(data.settings.cache_ttl) : "") ||
      settingsText !== (data.settings ? JSON.stringify(data.settings, null, 2) : "") ||
      Object.values(credentials).some((v) => v !== "")
    )
  }, [name, connectionType, provider, host, port, authType, description, verifySsl, gatewayTimeout, gatewayCacheTtl, settingsText, credentials, data, initialized])

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

  // ── Provider preset selection ───────────────────────────────────────

  const handlePresetChange = useCallback(
    (value: string) => {
      if (value === "_custom") {
        setSelectedPreset("_custom")
        setProvider("")
        setErrors((prev) => ({ ...prev, provider: undefined }))
        return
      }
      const preset = providerPresets.find((p) => p.value === value)
      if (preset) {
        setSelectedPreset(value)
        setProvider(preset.label)
        setConnectionType(preset.connectionType)
        setVerifySsl(preset.defaultSettings.verify_ssl)
        setGatewayTimeout(String(preset.defaultSettings.timeout))
        // Only change auth type if no credentials have been entered
        if ((hasCredentials || hasExistingCredentials) && preset.authType !== authType) {
          setPendingAuthType(preset.authType)
        } else {
          setAuthType(preset.authType)
          setCredentials({})
        }
        setErrors((prev) => ({ ...prev, provider: undefined }))
      }
    },
    [authType, hasCredentials, hasExistingCredentials],
  )

  const activePreset = selectedPreset && selectedPreset !== "_custom"
    ? providerPresets.find((p) => p.value === selectedPreset)
    : null

  // ── Auth type change with confirmation ───────────────────────────────

  const handleAuthTypeChange = (newType: string) => {
    if ((hasCredentials || hasExistingCredentials) && newType !== authType) {
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

    if (!data) return

    // Validate all fields before submit
    const nameError = validateField("name", name)
    const providerError = validateField("provider", provider)
    const hostError = validateField("host", host)
    const portError = validateField("port", port)
    setTouched({ name: true, provider: true, host: true, port: true })

    if (nameError || providerError || hostError || portError) return

    const payload: ConnectionUpdate = {}

    // Only include fields that changed
    const resolvedProvider = selectedPreset && selectedPreset !== "_custom"
      ? selectedPreset
      : provider.toLowerCase()
    if (name !== data.name) payload.name = name
    if (connectionType !== data.connectionType) payload.connectionType = connectionType
    if (resolvedProvider !== data.provider) payload.provider = resolvedProvider
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

    // Check if verify_ssl or gateway overrides changed -- merge into settings
    const originalVerifySsl = data.settings?.verify_ssl !== false
    const originalTimeout = data.settings?.timeout != null ? String(data.settings.timeout) : ""
    const originalCacheTtl = data.settings?.cache_ttl != null ? String(data.settings.cache_ttl) : ""
    const gatewayFieldsChanged = gatewayTimeout !== originalTimeout || gatewayCacheTtl !== originalCacheTtl
    if (verifySsl !== originalVerifySsl || gatewayFieldsChanged || parsedSettings !== null) {
      const base = parsedSettings ?? data.settings ?? {}
      const merged: Record<string, unknown> = { ...base, verify_ssl: verifySsl }
      // Gateway overrides: set if provided, remove if cleared
      if (gatewayTimeout.trim()) {
        merged.timeout = parseInt(gatewayTimeout, 10)
      } else {
        delete merged.timeout
      }
      if (gatewayCacheTtl.trim()) {
        merged.cache_ttl = parseInt(gatewayCacheTtl, 10)
      } else {
        delete merged.cache_ttl
      }
      payload.settings = merged
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

    justSubmittedRef.current = true
    updateConnection.mutate(payload, {
      onSuccess: () => {
        router.navigate({
          to: "/connections/$connectionId",
          params: { connectionId },
        })
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
    !errors.port

  // Get the icon for the currently selected connection type
  const selectedTypeIcon = connectionTypes.find((t) => t.value === connectionType)?.icon

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
          <EmptyState
            icon={AlertCircle}
            title="Unable to load connection"
            description="Something went wrong. Please try again."
            action={<Button variant="outline" size="sm" onClick={() => refetch()}>Try again</Button>}
          />
        </PageSection>
      </PageContainer>
    )
  }

  return (
    <>
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Connections"
        title="Edit Connection"
        description={`Editing ${data.name}`}
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
                <BreadcrumbLink asChild>
                  <Link to="/connections/$connectionId" params={{ connectionId }}>{data.name}</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbPage>Edit</BreadcrumbPage>
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
                    <p className={cn("shrink-0 text-xs", name.length >= NAME_MAX ? "text-destructive" : "text-muted-foreground")}>
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
                <Select value={selectedPreset ?? ""} onValueChange={handlePresetChange}>
                  <SelectTrigger id="conn-provider-preset">
                    <SelectValue placeholder="Select a provider..." />
                  </SelectTrigger>
                  <SelectContent>
                    {providerPresets.map((p) => (
                      <SelectItem key={p.value} value={p.value}>
                        {p.label}
                      </SelectItem>
                    ))}
                    <SelectItem value="_custom">Custom</SelectItem>
                  </SelectContent>
                </Select>
                {selectedPreset === "_custom" && (
                  <div className="pt-1">
                    <Input
                      id="conn-provider"
                      placeholder="e.g., Zendesk, Twilio, 3CX"
                      value={provider}
                      onChange={(e) => {
                        if (e.target.value.length <= PROVIDER_MAX) handleFieldChange("provider", e.target.value, setProvider)
                      }}
                      onBlur={() => handleFieldBlur("provider", provider)}
                      aria-invalid={!!errors.provider}
                      maxLength={PROVIDER_MAX}
                      required
                    />
                    <div className="flex items-center justify-between pt-1">
                      <p className={cn("shrink-0 text-xs", provider.length >= PROVIDER_MAX ? "text-destructive" : "text-muted-foreground")}>
                        {provider.length}/{PROVIDER_MAX}
                      </p>
                    </div>
                  </div>
                )}
                {errors.provider ? (
                  <FieldError message={errors.provider} />
                ) : activePreset ? (
                  <FieldHint>{activePreset.hint}</FieldHint>
                ) : selectedPreset === "_custom" ? (
                  <FieldHint>Enter the name of your provider.</FieldHint>
                ) : (
                  <FieldHint>Choose a known provider or select Custom to enter one manually.</FieldHint>
                )}
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
                  <p className={cn("shrink-0 text-xs", description.length >= DESC_MAX ? "text-destructive" : "text-muted-foreground")}>
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
                    placeholder={activePreset ? activePreset.hostPlaceholder : connectionType === "network" ? "e.g., 192.168.1.1 or unifi.local" : "e.g., pbx.example.com or https://api.example.com"}
                    value={host}
                    onChange={(e) => handleFieldChange("host", e.target.value, setHost)}
                    onBlur={() => handleFieldBlur("host", host)}
                    aria-invalid={!!errors.host}
                  />
                  {errors.host ? (
                    <FieldError message={errors.host} />
                  ) : activePreset ? (
                    <FieldHint>{activePreset.hostHint}</FieldHint>
                  ) : (
                    <FieldHint>The hostname, IP address, or full URL of the remote service.</FieldHint>
                  )}
                </div>
                <div className="space-y-2">
                  <Label htmlFor="conn-port">Port</Label>
                  <Input
                    id="conn-port"
                    type="number"
                    placeholder={activePreset ? activePreset.portPlaceholder : "e.g., 443"}
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
                      Credentials are encrypted at rest and never displayed after saving. Leave fields blank to keep
                      existing credentials unchanged.
                    </p>
                  </div>
                  {activePreset && (
                    <p className="text-xs text-muted-foreground mt-1">{activePreset.credentialsHint}</p>
                  )}
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
                <FieldHint>Advanced settings as raw JSON. The verify_ssl toggle and gateway overrides above are merged automatically.</FieldHint>
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
                Existing credential values can only be replaced -- not viewed. Use the
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
              Switching the authentication type will discard all saved credentials for this connection. Any new
              credential values you have entered will also be cleared. This cannot be undone.
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
