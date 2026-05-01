import { createFileRoute, Link } from "@tanstack/react-router"
import { useCallback, useState } from "react"
import {
  AlertCircle,
  Check,
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
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
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
import { SkeletonTable } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Textarea } from "@/components/ui/textarea"
import {
  useWebhooks,
  useCreateWebhook,
  useUpdateWebhook,
  useDeleteWebhook,
  useTestWebhook,
} from "@/lib/api/hooks/webhooks"
import { useDocumentTitle } from "@/hooks/use-document-title"
import type { WebhookCreate, WebhookList, WebhookUpdate } from "@/lib/generated/api"

export const Route = createFileRoute("/_app/webhooks/")({
  component: WebhooksPage,
})

// -- Constants ----------------------------------------------------------------

const PAGE_SIZE = 25

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

function formatRelativeTime(dateStr: string | null | undefined): string {
  if (!dateStr) return "Never"
  const date = new Date(dateStr)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffSec = Math.floor(diffMs / 1000)
  const diffMin = Math.floor(diffSec / 60)
  const diffHour = Math.floor(diffMin / 60)
  const diffDay = Math.floor(diffHour / 24)

  if (diffSec < 60) return "Just now"
  if (diffMin < 60) return `${diffMin}m ago`
  if (diffHour < 24) return `${diffHour}h ago`
  if (diffDay < 30) return `${diffDay}d ago`
  return date.toLocaleDateString()
}

function truncateUrl(url: string, maxLen = 40): string {
  if (url.length <= maxLen) return url
  return url.slice(0, maxLen) + "..."
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
        onSuccess: () => handleOpenChange(false),
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
        onSuccess: () => handleOpenChange(false),
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
          </div>

          <div className="space-y-2">
            <Label>Events</Label>
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
              placeholder="Optional description"
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
      onSuccess: () => onOpenChange(false),
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

  const [page, setPage] = useState(1)
  const [search, setSearch] = useState("")
  const [createOpen, setCreateOpen] = useState(false)
  const [editWebhook, setEditWebhook] = useState<WebhookList | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<WebhookList | null>(null)

  const { data, isLoading, isError, refetch } = useWebhooks(page, PAGE_SIZE, search || undefined)

  const webhooks = data?.items ?? []
  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  const hasActiveFilters = search !== ""

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
          <Button size="sm" onClick={() => setCreateOpen(true)}>
            <Plus className="mr-2 h-4 w-4" /> New webhook
          </Button>
        }
      />

      {/* Search */}
      <PageSection>
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative max-w-sm flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search webhooks..."
              value={search}
              onChange={(e) => {
                setSearch(e.target.value)
                setPage(1)
              }}
              className="pl-9 pr-8"
            />
            {search && (
              <button
                type="button"
                onClick={() => setSearch("")}
                className="absolute right-2 top-1/2 -translate-y-1/2 rounded-sm p-0.5 text-muted-foreground hover:text-foreground"
              >
                <X className="h-3.5 w-3.5" />
                <span className="sr-only">Clear search</span>
              </button>
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
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>URL</TableHead>
                    <TableHead>Events</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Last Triggered</TableHead>
                    <TableHead>Failures</TableHead>
                    <TableHead className="w-16 text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {webhooks.map((webhook, index) => (
                    <WebhookRow
                      key={webhook.id}
                      webhook={webhook}
                      index={index}
                      onEdit={() => setEditWebhook(webhook)}
                      onDelete={() => setDeleteTarget(webhook)}
                    />
                  ))}
                </TableBody>
              </Table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-end gap-2">
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
    </PageContainer>
  )
}

// -- Table row ----------------------------------------------------------------

function WebhookRow({
  webhook,
  index,
  onEdit,
  onDelete,
}: {
  webhook: WebhookList
  index: number
  onEdit: () => void
  onDelete: () => void
}) {
  const testWebhookMutation = useTestWebhook()

  return (
    <TableRow className={`transition-colors ${index % 2 === 1 ? "bg-muted/20" : ""}`}>
      <TableCell>
        <div className="flex items-center gap-2">
          <Webhook className="h-4 w-4 text-muted-foreground" />
          <span className="font-medium">{webhook.name}</span>
        </div>
      </TableCell>
      <TableCell>
        <span className="text-sm text-muted-foreground font-mono" title={webhook.url}>
          {truncateUrl(webhook.url)}
        </span>
      </TableCell>
      <TableCell>
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
      <TableCell>
        <span className="text-sm text-muted-foreground">
          {formatRelativeTime(webhook.lastTriggeredAt as string | null | undefined)}
        </span>
      </TableCell>
      <TableCell>
        {(webhook.failureCount ?? 0) > 0 ? (
          <Badge variant="destructive" className="gap-1">
            {webhook.failureCount}
          </Badge>
        ) : (
          <span className="text-sm text-muted-foreground">0</span>
        )}
      </TableCell>
      <TableCell className="text-right">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="h-8 w-8" data-slot="dropdown">
              <MoreVertical className="h-4 w-4" />
              <span className="sr-only">Actions</span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem onClick={onEdit}>
              <Pencil className="mr-2 h-4 w-4" />
              Edit
            </DropdownMenuItem>
            <DropdownMenuItem
              onClick={() => testWebhookMutation.mutate(webhook.id)}
              disabled={testWebhookMutation.isPending}
            >
              {testWebhookMutation.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Play className="mr-2 h-4 w-4" />
              )}
              Test
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem className="text-destructive focus:text-destructive" onClick={onDelete}>
              <Trash2 className="mr-2 h-4 w-4" />
              Delete
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </TableCell>
    </TableRow>
  )
}
