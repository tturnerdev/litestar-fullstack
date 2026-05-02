import { createFileRoute, Link, useBlocker, useRouter } from "@tanstack/react-router"
import { Globe, Info, Key, Loader2, Minus, Plus, Send, Shield, Webhook } from "lucide-react"
import { useCallback, useRef, useState } from "react"
import { toast } from "sonner"
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

const AVAILABLE_EVENTS = [
  "extension.created",
  "extension.updated",
  "extension.deleted",
  "device.created",
  "device.updated",
  "device.deleted",
  "phone_number.created",
  "phone_number.updated",
  "ticket.created",
  "ticket.updated",
  "ticket.closed",
  "user.created",
  "user.updated",
  "voicemail.received",
] as const

const EVENT_CATEGORIES: { label: string; events: string[] }[] = [
  {
    label: "Extensions",
    events: ["extension.created", "extension.updated", "extension.deleted"],
  },
  {
    label: "Devices",
    events: ["device.created", "device.updated", "device.deleted"],
  },
  {
    label: "Phone Numbers",
    events: ["phone_number.created", "phone_number.updated"],
  },
  {
    label: "Tickets",
    events: ["ticket.created", "ticket.updated", "ticket.closed"],
  },
  {
    label: "Users",
    events: ["user.created", "user.updated"],
  },
  {
    label: "Voicemail",
    events: ["voicemail.received"],
  },
]

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

  // Event toggles
  const toggleEvent = useCallback((event: string) => {
    setEvents((prev) => (prev.includes(event) ? prev.filter((e) => e !== event) : [...prev, event]))
  }, [])

  const selectAllEvents = useCallback(() => {
    setEvents([...AVAILABLE_EVENTS])
  }, [])

  const clearAllEvents = useCallback(() => {
    setEvents([])
  }, [])

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

  // Validation
  const isValid = name.trim() !== "" && url.trim() !== ""

  // Submit
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!isValid) return

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
                      onChange={(e) => setName(e.target.value)}
                      maxLength={NAME_MAX}
                      required
                      autoFocus
                    />
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
                      onChange={(e) => setUrl(e.target.value)}
                      maxLength={URL_MAX}
                      required
                    />
                    <p className="text-xs text-muted-foreground">Must be an HTTPS URL that accepts POST requests with a JSON body.</p>
                  </div>

                  {/* Description */}
                  <div className="space-y-2">
                    <Label htmlFor="webhook-description">Description</Label>
                    <Textarea
                      id="webhook-description"
                      placeholder="What is this webhook used for?"
                      value={description}
                      onChange={(e) => setDescription(e.target.value)}
                      maxLength={DESC_MAX}
                      rows={2}
                      className="resize-none"
                    />
                    <div className="flex items-center justify-between">
                      <p className="text-xs text-muted-foreground">Optional notes about this webhook's purpose.</p>
                      <p className={cn("shrink-0 text-xs", description.length >= DESC_MAX ? "text-destructive" : "text-muted-foreground")}>
                        {description.length}/{DESC_MAX}
                      </p>
                    </div>
                  </div>

                  {/* Events */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <Label>Events</Label>
                      <div className="flex items-center gap-2">
                        <Button type="button" variant="ghost" size="sm" className="h-6 px-2 text-xs" onClick={selectAllEvents}>
                          Select all
                        </Button>
                        <Button type="button" variant="ghost" size="sm" className="h-6 px-2 text-xs" onClick={clearAllEvents} disabled={events.length === 0}>
                          Clear
                        </Button>
                      </div>
                    </div>
                    <p className="text-xs text-muted-foreground">Select which events should trigger this webhook. If none are selected, all events will be sent.</p>
                    <div className="space-y-3 rounded-md border p-4">
                      {EVENT_CATEGORIES.map((category) => (
                        <div key={category.label}>
                          <p className="mb-1.5 text-xs font-medium text-muted-foreground uppercase tracking-wider">{category.label}</p>
                          <div className="grid grid-cols-2 gap-1.5">
                            {category.events.map((event) => (
                              <label key={event} className="flex items-center gap-2 cursor-pointer text-sm hover:bg-muted/50 rounded px-2 py-1">
                                <input type="checkbox" checked={events.includes(event)} onChange={() => toggleEvent(event)} className="rounded border-input" />
                                <span className="text-xs font-mono">{event}</span>
                              </label>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                    {events.length > 0 && (
                      <p className="text-xs text-muted-foreground">
                        {events.length} event{events.length === 1 ? "" : "s"} selected
                      </p>
                    )}
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
                    <p className="text-xs text-muted-foreground">Used to sign payloads so you can verify they came from us. Keep this value secret.</p>
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
