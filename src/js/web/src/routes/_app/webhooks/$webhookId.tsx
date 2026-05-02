import { createFileRoute, Link, useRouter } from "@tanstack/react-router"
import { useState } from "react"
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  ArrowLeft,
  Check,
  Clock,
  Copy,
  Eye,
  EyeOff,
  Fingerprint,
  Globe,
  Loader2,
  MoreHorizontal,
  Play,
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
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { EmptyState } from "@/components/ui/empty-state"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Skeleton } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { CopyButton } from "@/components/ui/copy-button"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"
import {
  useWebhook,
  useWebhookDeliveries,
  useUpdateWebhook,
  useDeleteWebhook,
  useTestWebhook,
} from "@/lib/api/hooks/webhooks"
import type { WebhookDelivery } from "@/lib/api/hooks/webhooks"

export const Route = createFileRoute("/_app/webhooks/$webhookId")({
  component: WebhookDetailPage,
})

// -- Helpers ------------------------------------------------------------------

function statusCodeBadge(code: number | null | undefined): React.ReactNode {
  if (code == null) {
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

// -- Main page ----------------------------------------------------------------

function WebhookDetailPage() {
  const { webhookId } = Route.useParams()
  const router = useRouter()
  const { data, isLoading, isError, refetch } = useWebhook(webhookId)
  const deliveriesQuery = useWebhookDeliveries(webhookId)
  const updateWebhook = useUpdateWebhook(webhookId)
  const deleteWebhook = useDeleteWebhook()
  const testWebhookMutation = useTestWebhook()

  useDocumentTitle(data?.name ? `${data.name} - Webhook` : "Webhook Details")

  const [deleteOpen, setDeleteOpen] = useState(false)
  const [showSecret, setShowSecret] = useState(false)

  // -- Loading state ----------------------------------------------------------

  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <div className="space-y-2">
          <Skeleton className="h-4 w-32" />
          <Skeleton className="h-8 w-56" />
          <Skeleton className="h-4 w-40" />
        </div>
        <PageSection>
          <div className="space-y-6">
            <div className="rounded-xl border border-border/60 bg-card/80 p-6 space-y-4">
              <div className="flex items-center gap-2">
                <Skeleton className="h-5 w-5 rounded" />
                <Skeleton className="h-6 w-32" />
              </div>
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                {Array.from({ length: 6 }).map((_, i) => (
                  <div key={i} className="space-y-1.5">
                    <Skeleton className="h-3.5 w-20" />
                    <Skeleton className="h-5 w-32" />
                  </div>
                ))}
              </div>
            </div>
            <div className="rounded-xl border border-border/60 bg-card/80 p-6 space-y-4">
              <div className="flex items-center gap-2">
                <Skeleton className="h-5 w-5 rounded" />
                <Skeleton className="h-6 w-24" />
              </div>
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                {Array.from({ length: 4 }).map((_, i) => (
                  <div key={i} className="space-y-1.5">
                    <Skeleton className="h-3.5 w-20" />
                    <Skeleton className="h-5 w-40" />
                  </div>
                ))}
              </div>
            </div>
            <div className="rounded-xl border border-border/60 bg-card/80 p-6 space-y-4">
              <div className="flex items-center gap-2">
                <Skeleton className="h-5 w-5 rounded" />
                <Skeleton className="h-6 w-36" />
              </div>
              <div className="space-y-2">
                {Array.from({ length: 5 }).map((_, i) => (
                  <Skeleton key={i} className="h-10 w-full rounded-md" />
                ))}
              </div>
            </div>
          </div>
        </PageSection>
      </PageContainer>
    )
  }

  // -- Error state ------------------------------------------------------------

  if (isError || !data) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader
          eyebrow="Webhooks"
          title="Webhook Details"
          actions={
            <Button variant="outline" size="sm" asChild>
              <Link to="/webhooks">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back to webhooks
              </Link>
            </Button>
          }
        />
        <PageSection>
          <EmptyState
            icon={AlertCircle}
            title="Unable to load webhook"
            description="Something went wrong. Please try again."
            action={<Button variant="outline" size="sm" onClick={() => refetch()}>Try again</Button>}
          />
        </PageSection>
      </PageContainer>
    )
  }

  // -- Handlers ---------------------------------------------------------------

  const handleDelete = async () => {
    await deleteWebhook.mutateAsync(webhookId)
    router.navigate({ to: "/webhooks" })
  }

  const handleToggleActive = () => {
    updateWebhook.mutate({ isActive: !data.isActive })
  }

  const handleTest = () => {
    testWebhookMutation.mutate(webhookId)
  }

  const headers = data.headers ?? {}
  const headerEntries = Object.entries(headers)
  const deliveries = deliveriesQuery.data ?? []

  // -- Render -----------------------------------------------------------------

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Webhooks"
        title={data.name}
        description={data.description || undefined}
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
                <BreadcrumbPage>{data.name}</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
        actions={
          <div className="flex items-center gap-3">
            {data.isActive ? (
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
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm">
                  <MoreHorizontal className="h-4 w-4" />
                  <span className="sr-only">Actions</span>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => navigator.clipboard.writeText(webhookId)}>
                  <Copy className="mr-2 h-4 w-4" />
                  Copy Webhook ID
                </DropdownMenuItem>
                <DropdownMenuItem
                  onClick={handleTest}
                  disabled={testWebhookMutation.isPending}
                >
                  {testWebhookMutation.isPending ? (
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  ) : (
                    <Play className="mr-2 h-4 w-4" />
                  )}
                  Send Test
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  className="text-destructive focus:text-destructive"
                  onClick={() => setDeleteOpen(true)}
                >
                  <Trash2 className="mr-2 h-4 w-4" />
                  Delete Webhook
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        }
      />

      {/* Webhook Info */}
      <PageSection>
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Globe className="h-5 w-5 text-muted-foreground" />
              <CardTitle>Webhook Info</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-3">
              <div>
                <p className="text-muted-foreground">Name</p>
                <p className="font-medium">{data.name}</p>
              </div>
              <div className="md:col-span-2 lg:col-span-2">
                <p className="text-muted-foreground">URL</p>
                <div className="flex items-center gap-1">
                  <p className="font-mono text-xs break-all">{data.url}</p>
                  <CopyButton value={data.url} label="URL" />
                </div>
              </div>
              {data.description && (
                <div className="md:col-span-2 lg:col-span-3">
                  <p className="text-muted-foreground">Description</p>
                  <p>{data.description}</p>
                </div>
              )}
              <div>
                <p className="text-muted-foreground">Status</p>
                <div className="mt-1 flex items-center gap-3">
                  <Switch
                    id="webhook-active-toggle"
                    checked={data.isActive}
                    onCheckedChange={handleToggleActive}
                    disabled={updateWebhook.isPending}
                    aria-label={data.isActive ? "Disable webhook" : "Enable webhook"}
                  />
                  <Label htmlFor="webhook-active-toggle" className="cursor-pointer">
                    {data.isActive ? "Active" : "Inactive"}
                  </Label>
                  {updateWebhook.isPending && (
                    <Loader2 className="h-3.5 w-3.5 animate-spin text-muted-foreground" />
                  )}
                </div>
              </div>
              <div className="md:col-span-2 lg:col-span-2">
                <p className="text-muted-foreground">Events</p>
                <div className="mt-1 flex flex-wrap gap-1.5">
                  {data.events.length > 0 ? (
                    data.events.map((event) => (
                      <Badge key={event} variant="secondary" className="font-mono text-xs">
                        {event}
                      </Badge>
                    ))
                  ) : (
                    <span className="text-muted-foreground text-sm">All events</span>
                  )}
                </div>
              </div>
            </div>

            {/* Headers */}
            {headerEntries.length > 0 && (
              <div className="mt-6">
                <p className="text-muted-foreground text-sm mb-2">Custom Headers</p>
                <div className="rounded-md border">
                  <div className="grid grid-cols-[minmax(120px,1fr)_2fr] text-sm">
                    {headerEntries.map(([key, value], idx) => (
                      <div key={key} className="contents">
                        <div
                          className={`px-3 py-2 font-mono text-xs text-muted-foreground ${idx !== headerEntries.length - 1 ? "border-b" : ""}`}
                        >
                          {key}
                        </div>
                        <div
                          className={`border-l px-3 py-2 font-mono text-xs ${idx !== headerEntries.length - 1 ? "border-b" : ""}`}
                        >
                          {value}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Secret */}
            {data.secret != null && (
              <div className="mt-6">
                <p className="text-muted-foreground text-sm mb-1">Signing Secret</p>
                <div className="flex items-center gap-2">
                  <code className="rounded bg-muted px-2 py-1 font-mono text-xs">
                    {showSecret ? data.secret : "•".repeat(24)}
                  </code>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="h-7 w-7"
                    onClick={() => setShowSecret(!showSecret)}
                    aria-label={showSecret ? "Hide secret" : "Reveal secret"}
                  >
                    {showSecret ? (
                      <EyeOff className="h-3.5 w-3.5 text-muted-foreground" />
                    ) : (
                      <Eye className="h-3.5 w-3.5 text-muted-foreground" />
                    )}
                  </Button>
                  {data.secret && <CopyButton value={data.secret} label="secret" />}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </PageSection>

      {/* Metadata */}
      <PageSection delay={0.1}>
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Fingerprint className="h-5 w-5 text-muted-foreground" />
              <CardTitle>Metadata</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-4">
              <div>
                <p className="text-muted-foreground text-sm">Webhook ID</p>
                <div className="flex items-center gap-1">
                  <p className="font-mono text-xs">{webhookId}</p>
                  <CopyButton value={webhookId} label="webhook ID" />
                </div>
              </div>
              <TimestampField label="Created" value={data.createdAt} />
              <TimestampField label="Updated" value={data.updatedAt} />
              <TimestampField label="Last Triggered" value={data.lastTriggeredAt} />
              <div>
                <p className="text-muted-foreground text-sm">Failure Count</p>
                <p className="text-sm">
                  {(data.failureCount ?? 0) > 0 ? (
                    <Badge variant="destructive" className="gap-1">
                      {data.failureCount}
                    </Badge>
                  ) : (
                    "0"
                  )}
                </p>
              </div>
              <div>
                <p className="text-muted-foreground text-sm">Last Status Code</p>
                <div className="mt-0.5">{statusCodeBadge(data.lastStatusCode)}</div>
              </div>
            </div>
          </CardContent>
        </Card>
      </PageSection>

      {/* Delivery Log */}
      <PageSection delay={0.15}>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="h-5 w-5 text-muted-foreground" />
              <CardTitle>Delivery Log</CardTitle>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => deliveriesQuery.refetch()}
              disabled={deliveriesQuery.isRefetching}
            >
              {deliveriesQuery.isRefetching ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Activity className="mr-2 h-4 w-4" />
              )}
              Refresh
            </Button>
          </CardHeader>
          <CardContent>
            {deliveriesQuery.isLoading ? (
              <div className="space-y-2">
                {Array.from({ length: 5 }).map((_, i) => (
                  <Skeleton key={i} className="h-10 w-full rounded-md" />
                ))}
              </div>
            ) : deliveriesQuery.isError ? (
              <EmptyState
                icon={AlertCircle}
                title="Failed to load delivery history"
                description="Something went wrong. Please try again."
                action={
                  <Button variant="outline" size="sm" onClick={() => deliveriesQuery.refetch()}>
                    Try again
                  </Button>
                }
              />
            ) : deliveries.length === 0 ? (
              <EmptyState
                icon={Activity}
                title="No deliveries yet"
                description="No delivery attempts have been recorded. Use the Send Test action to send a test payload."
              />
            ) : (
              <div className="overflow-x-auto rounded-md border border-border/60">
                <Table aria-label="Webhook deliveries">
                  <TableHeader className="sticky top-0 z-10 bg-background">
                    <TableRow>
                      <TableHead>Event</TableHead>
                      <TableHead>Result</TableHead>
                      <TableHead>HTTP Status</TableHead>
                      <TableHead>Response Time</TableHead>
                      <TableHead>Timestamp</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {deliveries.map((delivery: WebhookDelivery) => (
                      <TableRow key={delivery.id} className="hover:bg-muted/50 transition-colors">
                        <TableCell>
                          <span className="text-sm font-mono">{delivery.event}</span>
                        </TableCell>
                        <TableCell>
                          {delivery.success ? (
                            <Badge className="gap-1 bg-emerald-100 text-emerald-700 hover:bg-emerald-100 dark:bg-emerald-900/30 dark:text-emerald-400">
                              <Check className="h-3 w-3" />
                              Success
                            </Badge>
                          ) : (
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <Badge variant="destructive" className="gap-1 cursor-default">
                                  <XCircle className="h-3 w-3" />
                                  Failed
                                </Badge>
                              </TooltipTrigger>
                              {delivery.error && (
                                <TooltipContent className="max-w-xs">
                                  {delivery.error}
                                </TooltipContent>
                              )}
                            </Tooltip>
                          )}
                        </TableCell>
                        <TableCell>{statusCodeBadge(delivery.statusCode)}</TableCell>
                        <TableCell>
                          <span className="text-sm text-muted-foreground">
                            {delivery.responseTimeMs}ms
                          </span>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-1.5">
                            <Clock className="h-3 w-3 text-muted-foreground" />
                            <span className="text-sm text-muted-foreground">
                              {formatDateTime(delivery.createdAt, "--")}
                            </span>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>
      </PageSection>

      {/* Danger Zone */}
      <PageSection delay={0.25}>
        <Card className="border-destructive/30">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-destructive">
              <AlertTriangle className="h-4 w-4" />
              Danger Zone
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium text-sm">Delete this webhook</p>
                <p className="text-sm text-muted-foreground">
                  This action cannot be undone. All delivery history and configuration will be
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
              Delete webhook?
            </AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete <strong>{data.name}</strong> and all associated
              delivery history. This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel
              onClick={() => setDeleteOpen(false)}
              disabled={deleteWebhook.isPending}
            >
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              className={buttonVariants({ variant: "destructive" })}
              onClick={() => {
                handleDelete()
                setDeleteOpen(false)
              }}
              disabled={deleteWebhook.isPending}
            >
              {deleteWebhook.isPending && (
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
