import { createFileRoute, Link, useNavigate } from "@tanstack/react-router"
import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { toast } from "sonner"
import {
  Activity,
  AlertCircle,
  Check,
  ChevronDown,
  Clock,
  Download,
  Eye,
  Home,
  Loader2,
  MoreVertical,
  Pencil,
  Play,
  Plus,
  Search,
  Trash2,
  Webhook,
  X,
  XCircle,
} from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { BulkActionBar, createBulkDeleteAction, createExportAction } from "@/components/ui/bulk-action-bar"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Skeleton, SkeletonTable } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { nextSortDirection, SortableHeader, type SortDirection } from "@/components/ui/sortable-header"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Textarea } from "@/components/ui/textarea"
import {
  useWebhooks,
  useCreateWebhook,
  useUpdateWebhook,
  useDeleteWebhook,
  useTestWebhook,
  useWebhookDeliveries,
} from "@/lib/api/hooks/webhooks"
import type { WebhookDelivery } from "@/lib/api/hooks/webhooks"
import { exportToCsv, type CsvHeader } from "@/lib/csv-export"
import { formatDateTime } from "@/lib/date-utils"
import { useDebouncedValue } from "@/hooks/use-debounced-value"
import { useDocumentTitle } from "@/hooks/use-document-title"
import type { WebhookCreate, WebhookList, WebhookUpdate } from "@/lib/generated/api"

export const Route = createFileRoute("/_app/webhooks/")({
  component: WebhooksPage,
})

// -- Constants ----------------------------------------------------------------

const PAGE_SIZES = [10, 25, 50, 100] as const
const DEFAULT_PAGE_SIZE = 25
const PAGE_SIZE_STORAGE_KEY = "webhooks-page-size"

function getStoredPageSize(): number {
  try {
    const stored = localStorage.getItem(PAGE_SIZE_STORAGE_KEY)
    if (stored) {
      const parsed = Number(stored)
      if ((PAGE_SIZES as readonly number[]).includes(parsed)) return parsed
    }
  } catch {
    // localStorage unavailable
  }
  return DEFAULT_PAGE_SIZE
}

const csvHeaders: CsvHeader<WebhookList>[] = [
  { label: "Name", accessor: (w) => w.name },
  { label: "URL", accessor: (w) => w.url },
  { label: "Active", accessor: (w) => w.isActive ? "Yes" : "No" },
  { label: "Events", accessor: (w) => w.events.join(", ") },
  { label: "Failure Count", accessor: (w) => String(w.failureCount ?? 0) },
  { label: "Last Triggered", accessor: (w) => w.lastTriggeredAt ?? "" },
  { label: "Created At", accessor: (w) => w.createdAt ?? "" },
]

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

// -- Helpers ------------------------------------------------------------------

function truncateUrl(url: string, maxLen = 40): string {
  if (url.length <= maxLen) return url
  return url.slice(0, maxLen) + "..."
}

function statusCodeBadge(code: number | null): React.ReactNode {
  if (code === null) {
    return (
      <Badge variant="outline" className="text-muted-foreground">
        --
      </Badge>
    )
  }
  if (code >= 200 && code < 300) {
    return (
      <Badge className="bg-emerald-100 text-emerald-700 hover:bg-emerald-100 dark:bg-emerald-900/30 dark:text-emerald-400">
        {code}
      </Badge>
    )
  }
  if (code >= 300 && code < 400) {
    return (
      <Badge className="bg-amber-100 text-amber-700 hover:bg-amber-100 dark:bg-amber-900/30 dark:text-amber-400">
        {code}
      </Badge>
    )
  }
  return (
    <Badge className="bg-red-100 text-red-700 hover:bg-red-100 dark:bg-red-900/30 dark:text-red-400">
      {code}
    </Badge>
  )
}

// -- Delivery History Panel ---------------------------------------------------

function DeliveryHistoryPanel({ webhookId }: { webhookId: string }) {
  const { data: deliveries, isLoading, isError, refetch } = useWebhookDeliveries(webhookId)

  if (isLoading) {
    return (
      <div className="px-2 pb-3">
        <Table aria-label="Delivery history loading">
          <TableHeader>
            <TableRow>
              <TableHead className="text-xs">Timestamp</TableHead>
              <TableHead className="text-xs">Event</TableHead>
              <TableHead className="text-xs">Status</TableHead>
              <TableHead className="text-xs">Response Time</TableHead>
              <TableHead className="text-xs">Result</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {Array.from({ length: 5 }).map((_, i) => (
              <TableRow key={i}>
                <TableCell>
                  <div className="flex items-center gap-1.5">
                    <Skeleton className="h-3 w-3 rounded-full" />
                    <Skeleton className="h-3 w-28" />
                  </div>
                </TableCell>
                <TableCell>
                  <Skeleton className="h-3 w-24" />
                </TableCell>
                <TableCell>
                  <Skeleton className="h-5 w-12 rounded-full" />
                </TableCell>
                <TableCell>
                  <Skeleton className="h-3 w-14" />
                </TableCell>
                <TableCell>
                  <Skeleton className="h-5 w-16 rounded-full" />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    )
  }

  if (isError) {
    return (
      <EmptyState
        icon={AlertCircle}
        title="Failed to load delivery history"
        description="Something went wrong. Please try again."
        action={<Button variant="outline" size="sm" onClick={() => refetch()}>Try again</Button>}
      />
    )
  }

  if (!deliveries || deliveries.length === 0) {
    return (
      <div className="flex items-center gap-2 py-4 px-6 text-sm text-muted-foreground">
        <Activity className="h-4 w-4" />
        No delivery attempts yet. Use the Test action to send a test payload.
      </div>
    )
  }

  return (
    <div className="px-2 pb-3">
      <Table aria-label="Delivery history">
        <TableHeader>
          <TableRow>
            <TableHead className="text-xs">Timestamp</TableHead>
            <TableHead className="text-xs">Event</TableHead>
            <TableHead className="text-xs">Status</TableHead>
            <TableHead className="text-xs">Response Time</TableHead>
            <TableHead className="text-xs">Result</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {deliveries.map((delivery: WebhookDelivery) => (
            <TableRow key={delivery.id}>
              <TableCell className="text-xs text-muted-foreground">
                <div className="flex items-center gap-1.5">
                  <Clock className="h-3 w-3" />
                  {formatDateTime(delivery.createdAt, "--")}
                </div>
              </TableCell>
              <TableCell>
                <span className="text-xs font-mono">{delivery.event}</span>
              </TableCell>
              <TableCell>{statusCodeBadge(delivery.statusCode)}</TableCell>
              <TableCell className="text-xs text-muted-foreground">{delivery.responseTimeMs}ms</TableCell>
              <TableCell>
                {delivery.success ? (
                  <Badge className="gap-1 bg-emerald-100 text-emerald-700 hover:bg-emerald-100 dark:bg-emerald-900/30 dark:text-emerald-400">
                    <Check className="h-3 w-3" />
                    Success
                  </Badge>
                ) : (
                  <Badge
                    variant="destructive"
                    className="gap-1"
                    title={delivery.error ?? undefined}
                  >
                    <XCircle className="h-3 w-3" />
                    Failed
                  </Badge>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}

// -- Create/Edit Webhook Dialog -----------------------------------------------

function WebhookFormDialog({
  open,
  onOpenChange,
  editWebhook,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  editWebhook?: WebhookList | null
}) {
  const createWebhook = useCreateWebhook()
  const updateWebhook = useUpdateWebhook(editWebhook?.id ?? "")

  const [name, setName] = useState("")
  const [url, setUrl] = useState("")
  const [secret, setSecret] = useState("")
  const [events, setEvents] = useState<string[]>([])
  const [description, setDescription] = useState("")
  const [isActive, setIsActive] = useState(true)
  const [headersText, setHeadersText] = useState("")

  // Populate form for editing
  const resetForm = useCallback(() => {
    if (editWebhook) {
      setName(editWebhook.name)
      setUrl(editWebhook.url)
      setSecret("")
      setEvents([...editWebhook.events])
      setDescription("")
      setIsActive(editWebhook.isActive)
      setHeadersText("")
    } else {
      setName("")
      setUrl("")
      setSecret("")
      setEvents([])
      setDescription("")
      setIsActive(true)
      setHeadersText("")
    }
  }, [editWebhook])

  // Reset on open
  const handleOpenChange = useCallback(
    (isOpen: boolean) => {
      if (isOpen) resetForm()
      onOpenChange(isOpen)
    },
    [onOpenChange, resetForm],
  )

  const toggleEvent = useCallback((event: string) => {
    setEvents((prev) => (prev.includes(event) ? prev.filter((e) => e !== event) : [...prev, event]))
  }, [])

  const parseHeaders = useCallback((text: string): Record<string, string> => {
    const headers: Record<string, string> = {}
    if (!text.trim()) return headers
    for (const line of text.split("\n")) {
      const colonIdx = line.indexOf(":")
      if (colonIdx > 0) {
        const key = line.slice(0, colonIdx).trim()
        const value = line.slice(colonIdx + 1).trim()
        if (key) headers[key] = value
      }
    }
    return headers
  }, [])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!name.trim() || !url.trim()) return

    const headers = parseHeaders(headersText)

    if (editWebhook) {
      const payload: WebhookUpdate = {
        name: name.trim(),
        url: url.trim(),
        events,
        isActive,
        headers,
        description: description.trim(),
      }
      if (secret) {
        payload.secret = secret
      }
      updateWebhook.mutate(payload, {
        onSuccess: () => {
          toast.success("Webhook updated")
          handleOpenChange(false)
        },
        onError: (err) => {
          toast.error("Failed to update webhook", {
            description: err instanceof Error ? err.message : undefined,
          })
        },
      })
    } else {
      const payload: WebhookCreate = {
        name: name.trim(),
        url: url.trim(),
        secret: secret || undefined,
        events,
        isActive,
        headers,
        description: description.trim(),
      }
      createWebhook.mutate(payload, {
        onSuccess: () => {
          toast.success("Webhook created")
          handleOpenChange(false)
          // Restore focus to the search input after dialog closes
          setTimeout(() => {
            const searchInput = document.querySelector<HTMLInputElement>('input[placeholder*="Search"]')
            if (searchInput) {
              searchInput.focus()
            }
          }, 0)
        },
        onError: (err) => {
          toast.error("Failed to create webhook", {
            description: err instanceof Error ? err.message : undefined,
          })
        },
      })
    }
  }

  const isPending = createWebhook.isPending || updateWebhook.isPending
  const isEditing = !!editWebhook

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{isEditing ? "Edit Webhook" : "New Webhook"}</DialogTitle>
          <DialogDescription>
            {isEditing
              ? "Update your webhook configuration."
              : "Create a webhook to receive event notifications via HTTP POST."}
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="webhook-name">Name</Label>
            <Input
              id="webhook-name"
              placeholder="e.g., Slack Notifications"
              value={name}
              onChange={(e) => setName(e.target.value)}
              maxLength={100}
              required
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="webhook-url">URL</Label>
            <Input
              id="webhook-url"
              type="url"
              placeholder="https://example.com/webhook"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              maxLength={500}
              required
            />
            <p className="text-xs text-muted-foreground mt-1">
              Must be an HTTPS URL that accepts POST requests with a JSON body.
            </p>
          </div>

          <div className="space-y-2">
            <Label htmlFor="webhook-secret">
              Secret {isEditing && <span className="text-muted-foreground">(leave blank to keep current)</span>}
            </Label>
            <Input
              id="webhook-secret"
              type="password"
              placeholder={isEditing ? "Enter new secret to change" : "Optional signing secret"}
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              maxLength={200}
            />
            <p className="text-xs text-muted-foreground mt-1">
              Used to sign payloads so you can verify they came from us. Keep this value secret.
            </p>
          </div>

          <div className="space-y-2">
            <Label>Events</Label>
            <p className="text-xs text-muted-foreground">
              Select which events should trigger this webhook. If none are selected, all events will be sent.
            </p>
            <div className="grid grid-cols-2 gap-2 rounded-md border p-3 max-h-48 overflow-y-auto">
              {AVAILABLE_EVENTS.map((event) => (
                <label
                  key={event}
                  className="flex items-center gap-2 cursor-pointer text-sm hover:bg-muted/50 rounded px-1 py-0.5"
                >
                  <input
                    type="checkbox"
                    checked={events.includes(event)}
                    onChange={() => toggleEvent(event)}
                    className="rounded border-input"
                  />
                  <span className="text-xs font-mono">{event}</span>
                </label>
              ))}
            </div>
            {events.length > 0 && (
              <p className="text-xs text-muted-foreground">
                {events.length} event{events.length === 1 ? "" : "s"} selected
              </p>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="webhook-description">Description</Label>
            <Textarea
              id="webhook-description"
              placeholder="What is this webhook used for?"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              maxLength={500}
              rows={2}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="webhook-headers">
              Custom Headers <span className="text-muted-foreground">(one per line, Key: Value)</span>
            </Label>
            <Textarea
              id="webhook-headers"
              placeholder={"X-Custom-Header: my-value\nAuthorization: Bearer token123"}
              value={headersText}
              onChange={(e) => setHeadersText(e.target.value)}
              rows={3}
              className="font-mono text-xs"
            />
            <p className="text-xs text-muted-foreground mt-1">
              Additional HTTP headers sent with each delivery. One header per line.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <Switch id="webhook-active" checked={isActive} onCheckedChange={setIsActive} />
            <Label htmlFor="webhook-active">Active</Label>
          </div>

          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => handleOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={!name.trim() || !url.trim() || isPending}>
              {isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {isEditing ? "Save Changes" : "Create Webhook"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

// -- Delete Confirmation Dialog ------------------------------------------------

function DeleteWebhookDialog({
  open,
  onOpenChange,
  webhook,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  webhook: WebhookList | null
}) {
  const deleteWebhook = useDeleteWebhook()

  const handleDelete = () => {
    if (!webhook) return
    deleteWebhook.mutate(webhook.id, {
      onSuccess: () => {
        toast.success("Webhook deleted")
        onOpenChange(false)
        // The deleted row is gone, so restore focus to the search input
        setTimeout(() => {
          const searchInput = document.querySelector<HTMLInputElement>('input[placeholder*="Search"]')
          if (searchInput) {
            searchInput.focus()
          }
        }, 0)
      },
      onError: (err) => {
        toast.error("Failed to delete webhook", {
          description: err instanceof Error ? err.message : undefined,
        })
      },
    })
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Delete Webhook</DialogTitle>
          <DialogDescription>
            Are you sure you want to delete <strong>{webhook?.name}</strong>? This action cannot be undone.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="destructive" onClick={handleDelete} disabled={deleteWebhook.isPending}>
            {deleteWebhook.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            Delete
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// -- Main page ----------------------------------------------------------------

function WebhooksPage() {
  useDocumentTitle("Webhooks")
  const searchInputRef = useRef<HTMLInputElement>(null)

  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(getStoredPageSize)
  const [search, setSearch] = useState("")
  const debouncedSearch = useDebouncedValue(search)
  const [createOpen, setCreateOpen] = useState(false)
  const [editWebhook, setEditWebhook] = useState<WebhookList | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<WebhookList | null>(null)
  const [selected, setSelected] = useState<Set<string>>(new Set())

  // Sort state
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<SortDirection>(null)

  const handleSort = useCallback(
    (key: string) => {
      const next = nextSortDirection(sortKey, sortDir, key)
      setSortKey(next.sort)
      setSortDir(next.direction)
    },
    [sortKey, sortDir],
  )

  // Keyboard shortcuts: "/" to focus search, "N" opens the create dialog
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement
      if (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable) return
      if (e.key === "/" && !e.ctrlKey && !e.metaKey) {
        e.preventDefault()
        searchInputRef.current?.focus()
      }
      if (e.key === "n" && !e.ctrlKey && !e.metaKey && !e.altKey) {
        e.preventDefault()
        setCreateOpen(true)
      }
    }
    document.addEventListener("keydown", handleKeyDown)
    return () => document.removeEventListener("keydown", handleKeyDown)
  }, [])

  // Persist page size preference
  const handlePageSizeChange = useCallback((value: string) => {
    const size = Number(value)
    setPageSize(size)
    setPage(1)
    try {
      localStorage.setItem(PAGE_SIZE_STORAGE_KEY, value)
    } catch {
      // localStorage unavailable
    }
  }, [])

  // Reset page when debounced search changes
  useEffect(() => {
    setPage(1)
  }, [debouncedSearch])

  const { data, isLoading, isError, refetch } = useWebhooks(page, pageSize, debouncedSearch || undefined)
  const deleteWebhook = useDeleteWebhook()

  const rawWebhooks = data?.items ?? []

  // Client-side sorting
  const webhooks = useMemo(() => {
    if (!sortKey || !sortDir) return rawWebhooks
    const sorted = [...rawWebhooks]
    sorted.sort((a, b) => {
      let aVal: string | number
      let bVal: string | number
      switch (sortKey) {
        case "name":
          aVal = a.name.toLowerCase()
          bVal = b.name.toLowerCase()
          break
        case "url":
          aVal = a.url.toLowerCase()
          bVal = b.url.toLowerCase()
          break
        case "status":
          aVal = a.isActive ? 1 : 0
          bVal = b.isActive ? 1 : 0
          break
        case "created":
          aVal = a.createdAt ?? ""
          bVal = b.createdAt ?? ""
          break
        default:
          return 0
      }
      if (aVal < bVal) return sortDir === "asc" ? -1 : 1
      if (aVal > bVal) return sortDir === "asc" ? 1 : -1
      return 0
    })
    return sorted
  }, [rawWebhooks, sortKey, sortDir])

  const handleExport = useCallback(() => {
    exportToCsv("webhooks", csvHeaders, webhooks)
  }, [webhooks])
  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / pageSize))

  const hasActiveFilters = search !== ""

  const allSelected = webhooks.length > 0 && selected.size === webhooks.length
  const someSelected = selected.size > 0 && selected.size < webhooks.length

  const toggleAll = () => {
    if (allSelected) {
      setSelected(new Set())
    } else {
      setSelected(new Set(webhooks.map((w) => w.id)))
    }
  }

  const toggleOne = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const bulkActions = useMemo(
    () => [
      createBulkDeleteAction(
        (id) => deleteWebhook.mutateAsync(id),
        () => refetch(),
        { label: "Delete Selected" },
      ),
      createExportAction<WebhookList>(
        "webhooks",
        csvHeaders,
        (ids) => webhooks.filter((w) => ids.includes(w.id)),
      ),
    ],
    [deleteWebhook, refetch, webhooks],
  )

  const breadcrumbs = (
    <Breadcrumb>
      <BreadcrumbList>
        <BreadcrumbItem>
          <BreadcrumbLink asChild>
            <Link to="/">
              <Home className="h-3.5 w-3.5" />
            </Link>
          </BreadcrumbLink>
        </BreadcrumbItem>
        <BreadcrumbSeparator />
        <BreadcrumbItem>
          <BreadcrumbPage>Webhooks</BreadcrumbPage>
        </BreadcrumbItem>
      </BreadcrumbList>
    </Breadcrumb>
  )

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Integrations"
        title="Webhooks"
        description="Manage webhook subscriptions for receiving event notifications."
        breadcrumbs={breadcrumbs}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={handleExport} disabled={webhooks.length === 0}>
              <Download className="mr-2 h-4 w-4" /> Export
            </Button>
            <Button size="sm" onClick={() => setCreateOpen(true)}>
              <Plus className="mr-2 h-4 w-4" /> New webhook
              <kbd className="ml-1.5 hidden rounded border border-border bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground sm:inline">N</kbd>
            </Button>
          </div>
        }
      />

      {/* Search */}
      <PageSection>
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative max-w-sm flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              ref={searchInputRef}
              placeholder="Search webhooks..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9 pr-8"
            />
            {search ? (
              <button
                type="button"
                onClick={() => setSearch("")}
                className="absolute right-2 top-1/2 -translate-y-1/2 rounded-sm p-0.5 text-muted-foreground hover:text-foreground"
              >
                <X className="h-3.5 w-3.5" />
                <span className="sr-only">Clear search</span>
              </button>
            ) : (
              <kbd className="pointer-events-none absolute right-8 top-1/2 -translate-y-1/2 hidden rounded border border-border bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground sm:inline">/</kbd>
            )}
          </div>
        </div>
      </PageSection>

      {/* Content */}
      <PageSection delay={0.1}>
        {isLoading ? (
          <SkeletonTable rows={6} />
        ) : isError ? (
          <EmptyState
            icon={AlertCircle}
            title="Unable to load webhooks"
            description="Something went wrong while fetching your webhooks. Please try again."
            action={
              <Button variant="outline" size="sm" onClick={() => refetch()}>
                Try again
              </Button>
            }
          />
        ) : webhooks.length === 0 && !hasActiveFilters ? (
          <EmptyState
            icon={Webhook}
            title="No webhooks yet"
            description="Create your first webhook to receive event notifications via HTTP POST."
            action={
              <Button size="sm" onClick={() => setCreateOpen(true)}>
                <Plus className="mr-2 h-4 w-4" /> New webhook
              </Button>
            }
          />
        ) : webhooks.length === 0 ? (
          <EmptyState
            icon={Webhook}
            variant="no-results"
            title="No results found"
            description="No webhooks match your current search. Try adjusting your search terms."
            action={
              <Button variant="outline" size="sm" onClick={() => setSearch("")}>
                Clear search
              </Button>
            }
          />
        ) : (
          <div className="space-y-3">
            {/* Result count */}
            <div className="flex items-center justify-between">
              <p className="text-xs text-muted-foreground">
                {total} webhook{total === 1 ? "" : "s"}
                {hasActiveFilters && " (filtered)"}
              </p>
              {totalPages > 1 && (
                <p className="text-xs text-muted-foreground">
                  Page {page} of {totalPages}
                </p>
              )}
            </div>

            {/* Table */}
            <div className="overflow-x-auto rounded-md border border-border/60 bg-card/80">
              <Table aria-label="Webhooks">
                <TableHeader className="sticky top-0 z-10 bg-background">
                  <TableRow>
                    <TableHead className="w-[40px]">
                      <Checkbox
                        checked={allSelected}
                        indeterminate={someSelected}
                        onChange={toggleAll}
                        aria-label="Select all webhooks"
                      />
                    </TableHead>
                    <SortableHeader
                      label="Name"
                      sortKey="name"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <SortableHeader
                      label="URL"
                      sortKey="url"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                      className="hidden sm:table-cell"
                    />
                    <TableHead className="hidden md:table-cell">Events</TableHead>
                    <SortableHeader
                      label="Status"
                      sortKey="status"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <TableHead className="hidden lg:table-cell">Last Triggered</TableHead>
                    <TableHead className="hidden md:table-cell">Failures</TableHead>
                    <TableHead className="w-24 text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {webhooks.map((webhook, index) => (
                    <WebhookRow
                      key={webhook.id}
                      webhook={webhook}
                      index={index}
                      selected={selected.has(webhook.id)}
                      onToggle={() => toggleOne(webhook.id)}
                      onEdit={() => setEditWebhook(webhook)}
                      onDelete={() => setDeleteTarget(webhook)}
                    />
                  ))}
                </TableBody>
              </Table>
            </div>

            {/* Pagination */}
            <div className="flex items-center justify-end gap-4">
              <div className="flex items-center gap-2">
                <span className="text-sm text-muted-foreground">Rows per page</span>
                <Select value={String(pageSize)} onValueChange={handlePageSizeChange}>
                  <SelectTrigger className="h-8 w-[70px]">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {PAGE_SIZES.map((size) => (
                      <SelectItem key={size} value={String(size)}>
                        {size}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              {totalPages > 1 && (
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                    disabled={page <= 1}
                  >
                    Previous
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                    disabled={page >= totalPages}
                  >
                    Next
                  </Button>
                </div>
              )}
            </div>
          </div>
        )}
      </PageSection>

      {/* Create dialog */}
      <WebhookFormDialog open={createOpen} onOpenChange={setCreateOpen} />

      {/* Edit dialog */}
      <WebhookFormDialog
        open={!!editWebhook}
        onOpenChange={(isOpen) => {
          if (!isOpen) setEditWebhook(null)
        }}
        editWebhook={editWebhook}
      />

      {/* Delete confirmation dialog */}
      <DeleteWebhookDialog
        open={!!deleteTarget}
        onOpenChange={(isOpen) => {
          if (!isOpen) setDeleteTarget(null)
        }}
        webhook={deleteTarget}
      />

      <BulkActionBar
        selectedCount={selected.size}
        selectedIds={Array.from(selected)}
        onClearSelection={() => setSelected(new Set())}
        actions={bulkActions}
      />
    </PageContainer>
  )
}

// -- Table row ----------------------------------------------------------------

function WebhookRow({
  webhook,
  index,
  selected,
  onToggle,
  onEdit,
  onDelete,
}: {
  webhook: WebhookList
  index: number
  selected: boolean
  onToggle: () => void
  onEdit: () => void
  onDelete: () => void
}) {
  const testWebhookMutation = useTestWebhook()
  const [deliveriesOpen, setDeliveriesOpen] = useState(false)
  const navigate = useNavigate()

  return (
    <Collapsible open={deliveriesOpen} onOpenChange={setDeliveriesOpen} asChild>
      <>
        <TableRow
          data-state={selected ? "selected" : undefined}
          className={`cursor-pointer hover:bg-muted/50 transition-colors ${index % 2 === 1 ? "bg-muted/20" : ""}`}
          onClick={(e) => {
            const target = e.target as HTMLElement
            if (target.closest("[role=checkbox]") || target.closest("[data-slot=dropdown]") || target.closest("button") || target.closest("a")) {
              return
            }
            navigate({ to: "/webhooks/$webhookId", params: { webhookId: webhook.id } })
          }}
        >
          <TableCell>
            <Checkbox
              checked={selected}
              onChange={(e) => {
                e.stopPropagation()
                onToggle()
              }}
              aria-label={`Select ${webhook.name}`}
            />
          </TableCell>
          <TableCell>
            <div className="flex items-center gap-2">
              <Webhook className="h-4 w-4 text-muted-foreground shrink-0" />
              <div className="min-w-0">
                <Link
                  to="/webhooks/$webhookId"
                  params={{ webhookId: webhook.id }}
                  className="font-medium hover:underline"
                  onClick={(e) => e.stopPropagation()}
                >
                  {webhook.name}
                </Link>
                <span className="block sm:hidden text-xs text-muted-foreground font-mono truncate" title={webhook.url}>
                  {truncateUrl(webhook.url, 30)}
                </span>
              </div>
            </div>
          </TableCell>
          <TableCell className="hidden sm:table-cell">
            <span className="text-sm text-muted-foreground font-mono" title={webhook.url}>
              {truncateUrl(webhook.url)}
            </span>
          </TableCell>
          <TableCell className="hidden md:table-cell">
            <Badge variant="secondary" className="gap-1">
              {webhook.events.length} event{webhook.events.length === 1 ? "" : "s"}
            </Badge>
          </TableCell>
          <TableCell>
            {webhook.isActive ? (
              <Badge className="gap-1 bg-emerald-100 text-emerald-700 hover:bg-emerald-100 dark:bg-emerald-900/30 dark:text-emerald-400">
                <Check className="h-3 w-3" />
                Active
              </Badge>
            ) : (
              <Badge variant="outline" className="gap-1 text-muted-foreground">
                <XCircle className="h-3 w-3" />
                Inactive
              </Badge>
            )}
          </TableCell>
          <TableCell className="hidden lg:table-cell">
            <span className="text-sm text-muted-foreground">
              {formatDateTime(webhook.lastTriggeredAt as string | null | undefined, "Never")}
            </span>
          </TableCell>
          <TableCell className="hidden md:table-cell">
            {(webhook.failureCount ?? 0) > 0 ? (
              <Badge variant="destructive" className="gap-1">
                {webhook.failureCount}
              </Badge>
            ) : (
              <span className="text-sm text-muted-foreground">0</span>
            )}
          </TableCell>
          <TableCell className="text-right">
            <div className="flex items-center justify-end gap-1">
              <CollapsibleTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8"
                  title="Delivery history"
                >
                  <ChevronDown
                    className={`h-4 w-4 transition-transform ${deliveriesOpen ? "rotate-180" : ""}`}
                  />
                  <span className="sr-only">Toggle deliveries</span>
                </Button>
              </CollapsibleTrigger>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" size="icon" className="h-8 w-8" data-slot="dropdown">
                    <MoreVertical className="h-4 w-4" />
                    <span className="sr-only">Actions</span>
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem asChild>
                    <Link to="/webhooks/$webhookId" params={{ webhookId: webhook.id }}>
                      <Eye className="mr-2 h-4 w-4" />
                      View details
                    </Link>
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={onEdit}>
                    <Pencil className="mr-2 h-4 w-4" />
                    Edit
                  </DropdownMenuItem>
                  <DropdownMenuItem
                    onClick={() =>
                      testWebhookMutation.mutate(webhook.id, {
                        onSuccess: () => {
                          toast.success("Test delivery sent")
                        },
                        onError: (err) => {
                          toast.error("Failed to send test delivery", {
                            description: err instanceof Error ? err.message : undefined,
                          })
                        },
                      })
                    }
                    disabled={testWebhookMutation.isPending}
                  >
                    {testWebhookMutation.isPending ? (
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    ) : (
                      <Play className="mr-2 h-4 w-4" />
                    )}
                    Test
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => setDeliveriesOpen((prev) => !prev)}>
                    <Activity className="mr-2 h-4 w-4" />
                    Deliveries
                  </DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem className="text-destructive focus:text-destructive" onClick={onDelete}>
                    <Trash2 className="mr-2 h-4 w-4" />
                    Delete
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          </TableCell>
        </TableRow>
        <CollapsibleContent asChild>
          <tr>
            <td colSpan={8} className="p-0">
              <div className="border-t border-border/40 bg-muted/30">
                <div className="flex items-center gap-2 px-6 pt-3 pb-1">
                  <Activity className="h-4 w-4 text-muted-foreground" />
                  <span className="text-xs font-medium text-muted-foreground">
                    Recent Deliveries
                  </span>
                </div>
                <DeliveryHistoryPanel webhookId={webhook.id} />
              </div>
            </td>
          </tr>
        </CollapsibleContent>
      </>
    </Collapsible>
  )
}
