import { createFileRoute, Link, useBlocker, useRouter } from "@tanstack/react-router"
import { Globe, Info, Key, Loader2, Minus, Plus, Send, Shield, Webhook } from "lucide-react"
import { useCallback, useRef, useState } from "react"
import { toast } from "sonner"
import { EventTypeSelector } from "@/components/shared/event-type-selector"
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
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader } from "@/components/ui/page-layout"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { Switch } from "@/components/ui/switch"
import { Textarea } from "@/components/ui/textarea"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { useCreateWebhook } from "@/lib/api/hooks/webhooks"
import type { WebhookCreate } from "@/lib/generated/api"
import { cn } from "@/lib/utils"

export const Route = createFileRoute("/_app/webhooks/new")({
  component: NewWebhookPage,
})

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const NAME_MAX = 100
const URL_MAX = 500
const DESC_MAX = 500
const SECRET_MAX = 200

const tips = [
  {
    icon: Globe,
    title: "HTTPS required",
    description: "Your endpoint must accept POST requests over HTTPS with a JSON body.",
  },
  {
    icon: Shield,
    title: "Signing secret",
    description: "Add a secret to verify that payloads are authentic. We sign each delivery with HMAC-SHA256.",
  },
  {
    icon: Send,
    title: "Event filtering",
    description: "Subscribe to specific events or leave empty to receive all events.",
  },
  {
    icon: Key,
    title: "Custom headers",
    description: "Add authorization tokens or custom headers sent with every delivery.",
  },
]

// ---------------------------------------------------------------------------
// Header pair type
// ---------------------------------------------------------------------------

interface HeaderPair {
  key: string
  value: string
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

interface WebhookFieldErrors {
  name?: string
  url?: string
  description?: string
}

function validateWebhookField(field: keyof WebhookFieldErrors, value: string): string | undefined {
  switch (field) {
    case "name":
      if (value.trim() === "") return "Name is required"
      if (value.trim().length < 2) return "Name must be at least 2 characters"
      if (value.length > 200) return "Name must be 200 characters or less"
      return undefined
    case "url": {
      if (value.trim() === "") return "URL is required"
      try {
        const parsed = new URL(value)
        if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
          return "URL must start with https:// or http://"
        }
      } catch {
        return "Enter a valid URL (e.g., https://example.com/webhook)"
      }
      return undefined
    }
    case "description":
      if (value.length > 500) return "Description must be 500 characters or less"
      return undefined
  }
}

function FieldError({ message }: { message?: string }) {
  if (!message) return null
  return <p className="text-sm text-destructive">{message}</p>
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

function NewWebhookPage() {
  useDocumentTitle("New Webhook")
  const router = useRouter()
  const createWebhook = useCreateWebhook()
  const justSubmittedRef = useRef(false)

  // Form state
  const [name, setName] = useState("")
  const [url, setUrl] = useState("")
  const [description, setDescription] = useState("")
  const [secret, setSecret] = useState("")
  const [events, setEvents] = useState<string[]>([])
  const [isActive, setIsActive] = useState(true)
  const [headers, setHeaders] = useState<HeaderPair[]>([])

  // Validation state
  const [fieldErrors, setFieldErrors] = useState<WebhookFieldErrors>({})
  const touchedRef = useRef<Record<string, boolean>>({})

  const validateField = useCallback((field: keyof WebhookFieldErrors, value: string) => {
    const error = validateWebhookField(field, value)
    setFieldErrors((prev) => ({ ...prev, [field]: error }))
    return error
  }, [])

  const handleFieldBlur = useCallback(
    (field: keyof WebhookFieldErrors, value: string) => {
      touchedRef.current[field] = true
      validateField(field, value)
    },
    [validateField],
  )

  // Dirty check
  const formDirty =
    name.trim() !== "" ||
    url.trim() !== "" ||
    description.trim() !== "" ||
    secret.trim() !== "" ||
    events.length > 0 ||
    !isActive ||
    headers.some((h) => h.key.trim() !== "" || h.value.trim() !== "")

  const blocker = useBlocker({
    shouldBlockFn: () => formDirty && !justSubmittedRef.current,
    withResolver: true,
  })

  // Header management
  const addHeader = useCallback(() => {
    setHeaders((prev) => [...prev, { key: "", value: "" }])
  }, [])

  const removeHeader = useCallback((index: number) => {
    setHeaders((prev) => prev.filter((_, i) => i !== index))
  }, [])

  const updateHeader = useCallback((index: number, field: "key" | "value", val: string) => {
    setHeaders((prev) => prev.map((h, i) => (i === index ? { ...h, [field]: val } : h)))
  }, [])

  const hasValidationErrors = Object.values(fieldErrors).some((e) => !!e)
  const isValid = name.trim().length >= 2 && url.trim() !== "" && !hasValidationErrors

  // Submit
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    // Pre-submit validation
    const nameErr = validateField("name", name)
    const urlErr = validateField("url", url)
    const descErr = validateField("description", description)
    for (const f of ["name", "url", "description"] as const) {
      touchedRef.current[f] = true
    }
    if (nameErr || urlErr || descErr) return

    justSubmittedRef.current = true

    // Build headers record from pairs
    const headersRecord: Record<string, string> = {}
    for (const h of headers) {
      const k = h.key.trim()
      const v = h.value.trim()
      if (k) headersRecord[k] = v
    }

    const payload: WebhookCreate = {
      name: name.trim(),
      url: url.trim(),
      description: description.trim() || undefined,
      secret: secret.trim() || undefined,
      events,
      isActive,
      headers: Object.keys(headersRecord).length > 0 ? headersRecord : undefined,
    }

    createWebhook.mutate(payload, {
      onSuccess: (data) => {
        toast.success("Webhook created successfully")
        if (data.validationStatus === "unreachable") {
          toast.warning("Webhook created but URL appears unreachable", {
            description: "The endpoint could not be reached during validation. Please verify the URL is correct and accessible.",
          })
        } else if (data.validationStatus === "invalid_url") {
          toast.warning("Webhook created but URL appears invalid", {
            description: "The URL failed validation. Please check the URL format.",
          })
        }
        router.navigate({
          to: "/webhooks/$webhookId",
          params: { webhookId: data.id },
        })
      },
      onSettled: () => {
        justSubmittedRef.current = false
      },
    })
  }

  return (
    <>
      <PageContainer className="flex-1 space-y-8">
        <PageHeader
          eyebrow="Integrations"
          title="New Webhook"
          description="Create a webhook to receive event notifications via HTTP POST."
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
                    <Link to="/webhooks">Webhooks</Link>
                  </BreadcrumbLink>
                </BreadcrumbItem>
                <BreadcrumbSeparator />
                <BreadcrumbItem>
                  <BreadcrumbPage>New Webhook</BreadcrumbPage>
                </BreadcrumbItem>
              </BreadcrumbList>
            </Breadcrumb>
          }
        />

        <div className="flex gap-6">
          {/* Main form */}
          <SectionErrorBoundary name="Create Webhook Form">
            <Card className="min-w-0 flex-1">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-lg">
                  <Webhook className="h-5 w-5" />
                  Webhook Details
                </CardTitle>
              </CardHeader>
              <CardContent>
                <form onSubmit={handleSubmit} className="space-y-6">
                  {/* Name */}
                  <div className="space-y-2">
                    <Label htmlFor="webhook-name">
                      Name <span className="text-red-500">*</span>
                    </Label>
                    <Input
                      id="webhook-name"
                      placeholder="e.g., Slack Notifications"
                      value={name}
                      onChange={(e) => {
                        setName(e.target.value)
                        if (touchedRef.current.name) validateField("name", e.target.value)
                      }}
                      onBlur={() => handleFieldBlur("name", name)}
                      maxLength={NAME_MAX}
                      required
                      autoFocus
                      aria-invalid={!!fieldErrors.name}
                    />
                    <FieldError message={fieldErrors.name} />
                    <div className="flex items-center justify-between">
                      <p className="text-xs text-muted-foreground">A friendly name to identify this webhook.</p>
                      <p className={cn("text-xs", name.length >= NAME_MAX ? "text-destructive" : "text-muted-foreground")}>
                        {name.length}/{NAME_MAX}
                      </p>
                    </div>
                  </div>

                  {/* URL */}
                  <div className="space-y-2">
                    <Label htmlFor="webhook-url">
                      URL <span className="text-red-500">*</span>
                    </Label>
                    <Input
                      id="webhook-url"
                      type="url"
                      placeholder="https://example.com/webhook"
                      value={url}
                      onChange={(e) => {
                        setUrl(e.target.value)
                        if (touchedRef.current.url) validateField("url", e.target.value)
                      }}
                      onBlur={() => handleFieldBlur("url", url)}
                      maxLength={URL_MAX}
                      required
                      aria-invalid={!!fieldErrors.url}
                    />
                    <FieldError message={fieldErrors.url} />
                    <div className="flex items-center justify-between">
                      <p className="text-xs text-muted-foreground">Must be an HTTPS URL that accepts POST requests with a JSON body.</p>
                      <p className={cn("shrink-0 text-xs", url.length >= URL_MAX ? "text-destructive" : "text-muted-foreground")}>
                        {url.length}/{URL_MAX}
                      </p>
                    </div>
                  </div>

                  {/* Description */}
                  <div className="space-y-2">
                    <Label htmlFor="webhook-description">Description</Label>
                    <Textarea
                      id="webhook-description"
                      placeholder="What is this webhook used for?"
                      value={description}
                      onChange={(e) => {
                        setDescription(e.target.value)
                        if (touchedRef.current.description) validateField("description", e.target.value)
                      }}
                      onBlur={() => handleFieldBlur("description", description)}
                      maxLength={DESC_MAX}
                      rows={2}
                      className="resize-none"
                      aria-invalid={!!fieldErrors.description}
                    />
                    <FieldError message={fieldErrors.description} />
                    <div className="flex items-center justify-between">
                      <p className="text-xs text-muted-foreground">Optional notes about this webhook's purpose.</p>
                      <p className={cn("shrink-0 text-xs", description.length >= DESC_MAX ? "text-destructive" : "text-muted-foreground")}>
                        {description.length}/{DESC_MAX}
                      </p>
                    </div>
                  </div>

                  {/* Events */}
                  <div className="space-y-2">
                    <Label>Events</Label>
                    <EventTypeSelector selected={events} onChange={setEvents} />
                  </div>

                  {/* Secret */}
                  <div className="space-y-2">
                    <Label htmlFor="webhook-secret">Secret</Label>
                    <Input
                      id="webhook-secret"
                      type="password"
                      placeholder="Optional signing secret"
                      value={secret}
                      onChange={(e) => setSecret(e.target.value)}
                      maxLength={SECRET_MAX}
                    />
                    <div className="flex items-center justify-between">
                      <p className="text-xs text-muted-foreground">Used to sign payloads so you can verify they came from us. Keep this value secret.</p>
                      <p className={cn("shrink-0 text-xs", secret.length >= SECRET_MAX ? "text-destructive" : "text-muted-foreground")}>
                        {secret.length}/{SECRET_MAX}
                      </p>
                    </div>
                  </div>

                  {/* Custom Headers */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <Label>Custom Headers</Label>
                      <Button type="button" variant="outline" size="sm" className="h-7 gap-1 px-2 text-xs" onClick={addHeader}>
                        <Plus className="h-3 w-3" />
                        Add Header
                      </Button>
                    </div>
                    <p className="text-xs text-muted-foreground">Additional HTTP headers sent with each delivery.</p>
                    {headers.length > 0 && (
                      <div className="space-y-2">
                        {headers.map((header, index) => (
                          // biome-ignore lint/suspicious/noArrayIndexKey: Header pairs have no stable ID
                          <div key={index} className="flex items-center gap-2">
                            <Input placeholder="Header name" value={header.key} onChange={(e) => updateHeader(index, "key", e.target.value)} className="flex-1 font-mono text-xs" />
                            <Input placeholder="Value" value={header.value} onChange={(e) => updateHeader(index, "value", e.target.value)} className="flex-1 font-mono text-xs" />
                            <Button type="button" variant="ghost" size="icon" className="h-8 w-8 shrink-0" onClick={() => removeHeader(index)} aria-label="Remove header">
                              <Minus className="h-4 w-4" />
                            </Button>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Active toggle */}
                  <div className="flex items-center gap-3 rounded-md border p-3">
                    <Switch id="webhook-active" checked={isActive} onCheckedChange={setIsActive} />
                    <div className="space-y-0.5">
                      <Label htmlFor="webhook-active" className="cursor-pointer">
                        Active
                      </Label>
                      <p className="text-xs text-muted-foreground">When disabled, deliveries are paused but the configuration is preserved.</p>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center justify-end gap-2 border-t pt-4">
                    <Button type="button" variant="ghost" onClick={() => router.navigate({ to: "/webhooks" })}>
                      Cancel
                    </Button>
                    <Button type="submit" disabled={!isValid || createWebhook.isPending}>
                      {createWebhook.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                      Create Webhook
                    </Button>
                  </div>
                </form>
              </CardContent>
            </Card>
          </SectionErrorBoundary>

          {/* Sidebar tips */}
          <Card className="hidden h-fit w-72 shrink-0 border-border/40 bg-linear-to-br from-muted/30 to-muted/10 lg:block">
            <CardHeader className="space-y-1 pb-3">
              <CardTitle className="flex items-center gap-2 text-lg">
                <Info className="h-4 w-4" />
                Tips
              </CardTitle>
              <CardDescription>Setting up webhooks</CardDescription>
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
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </PageContainer>

      {/* Unsaved changes dialog */}
      <AlertDialog open={blocker.status === "blocked"} onOpenChange={() => blocker.reset?.()}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Unsaved changes</AlertDialogTitle>
            <AlertDialogDescription>You have unsaved changes to this webhook. Are you sure you want to leave? Your changes will be lost.</AlertDialogDescription>
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
