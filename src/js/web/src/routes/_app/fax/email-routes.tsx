import { toast } from "sonner"
import { createFileRoute, Link } from "@tanstack/react-router"
import { useDebouncedValue } from "@/hooks/use-debounced-value"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { cn } from "@/lib/utils"
import {
  AlertCircle,
  AlertTriangle,
  Bell,
  BellOff,
  Download,
  Eye,
  Mail,
  MailPlus,
  MoreVertical,
  Pencil,
  Search,
  Trash2,
  X,
} from "lucide-react"
import { useCallback, useMemo, useState } from "react"
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
import { BulkActionBar, createBulkDeleteAction, createExportAction } from "@/components/ui/bulk-action-bar"
import { Button, buttonVariants } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { CopyButton } from "@/components/ui/copy-button"
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
import { DataFreshness } from "@/components/ui/data-freshness"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { SkeletonTable } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import {
  type FaxEmailRouteWithNumber,
  useAllFaxEmailRoutes,
  useCreateFaxEmailRoute,
  useDeleteFaxEmailRoute,
  useFaxNumbers,
  useUpdateFaxEmailRoute,
} from "@/lib/api/hooks/fax"
import { exportToCsv, type CsvHeader } from "@/lib/csv-export"
import { formatDateTime } from "@/lib/date-utils"
import { client } from "@/lib/generated/api/client.gen"

export const Route = createFileRoute("/_app/fax/email-routes")({
  component: FaxEmailRoutesPage,
})

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

// ---------------------------------------------------------------------------
// CSV Headers
// ---------------------------------------------------------------------------

const csvHeaders: CsvHeader<FaxEmailRouteWithNumber>[] = [
  { label: "Email Address", accessor: (r) => r.emailAddress },
  { label: "Fax Number", accessor: (r) => r.faxNumber },
  { label: "Fax Number Label", accessor: (r) => r.faxNumberLabel ?? "" },
  { label: "Status", accessor: (r) => (r.isActive ? "Active" : "Inactive") },
  { label: "Failure Alerts", accessor: (r) => (r.notifyOnFailure ? "On" : "Off") },
  { label: "Created", accessor: (r) => formatDateTime(r.createdAt, "") },
]

// ---------------------------------------------------------------------------
// Create Dialog
// ---------------------------------------------------------------------------

function CreateEmailRouteDialog({
  open,
  onOpenChange,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const { data: numbers } = useFaxNumbers(1, 200)
  const [faxNumberId, setFaxNumberId] = useState("")
  const [emailAddress, setEmailAddress] = useState("")
  const [isActive, setIsActive] = useState(true)
  const [notifyOnFailure, setNotifyOnFailure] = useState(true)
  const [errors, setErrors] = useState<Record<string, string>>({})

  const createMutation = useCreateFaxEmailRoute(faxNumberId)

  function resetForm() {
    setFaxNumberId("")
    setEmailAddress("")
    setIsActive(true)
    setNotifyOnFailure(true)
    setErrors({})
  }

  function handleSubmit() {
    const fieldErrors: Record<string, string> = {}
    if (!faxNumberId) {
      fieldErrors.faxNumberId = "Please select a fax number"
    }
    const trimmed = emailAddress.trim()
    if (!trimmed) {
      fieldErrors.emailAddress = "This field is required"
    } else if (!EMAIL_REGEX.test(trimmed)) {
      fieldErrors.emailAddress = "Please enter a valid email address"
    }
    setErrors(fieldErrors)
    if (Object.keys(fieldErrors).length > 0) return
    createMutation.mutate(
      { emailAddress: trimmed, isActive, notifyOnFailure },
      {
        onSuccess: () => {
          toast.success("Email route created")
          resetForm()
          onOpenChange(false)
        },
        onError: (err) => {
          toast.error("Failed to create email route", {
            description: err instanceof Error ? err.message : undefined,
          })
        },
      },
    )
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(v) => {
        if (!v) resetForm()
        onOpenChange(v)
      }}
    >
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>New Email Route</DialogTitle>
          <DialogDescription>
            Route incoming faxes to an email address.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-2">
          <div className="space-y-2">
            <Label htmlFor="create-fax-number">Fax Number</Label>
            <Select
              value={faxNumberId}
              onValueChange={(v) => {
                setFaxNumberId(v)
                if (errors.faxNumberId) setErrors((prev) => ({ ...prev, faxNumberId: "" }))
              }}
            >
              <SelectTrigger id="create-fax-number" aria-invalid={!!errors.faxNumberId}>
                <SelectValue placeholder="Select a fax number" />
              </SelectTrigger>
              <SelectContent>
                {numbers?.items.map((n) => (
                  <SelectItem key={n.id} value={n.id}>
                    {n.number}{n.label ? ` (${n.label})` : ""}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {errors.faxNumberId && <p className="text-xs text-destructive">{errors.faxNumberId}</p>}
          </div>
          <div className="space-y-2">
            <Label htmlFor="create-email">Email Address</Label>
            <Input
              id="create-email"
              type="email"
              placeholder="user@example.com"
              value={emailAddress}
              onChange={(e) => {
                setEmailAddress(e.target.value)
                if (errors.emailAddress) setErrors((prev) => ({ ...prev, emailAddress: "" }))
              }}
              onBlur={() => {
                const trimmed = emailAddress.trim()
                if (!trimmed) {
                  setErrors((prev) => ({ ...prev, emailAddress: "This field is required" }))
                } else if (!EMAIL_REGEX.test(trimmed)) {
                  setErrors((prev) => ({ ...prev, emailAddress: "Please enter a valid email address" }))
                }
              }}
              onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
              aria-invalid={!!errors.emailAddress}
            />
            {errors.emailAddress && <p className="text-xs text-destructive">{errors.emailAddress}</p>}
          </div>
          <div className="flex items-center justify-between">
            <Label htmlFor="create-active">Active</Label>
            <Switch
              id="create-active"
              checked={isActive}
              onCheckedChange={setIsActive}
            />
          </div>
          <div className="flex items-center justify-between">
            <Label htmlFor="create-notify">Notify on Failure</Label>
            <Switch
              id="create-notify"
              checked={notifyOnFailure}
              onCheckedChange={setNotifyOnFailure}
            />
          </div>
        </div>
        <DialogFooter>
          <Button
            variant="outline"
            onClick={() => {
              resetForm()
              onOpenChange(false)
            }}
            disabled={createMutation.isPending}
          >
            Cancel
          </Button>
          <Button
            onClick={handleSubmit}
            disabled={createMutation.isPending || !faxNumberId || !emailAddress.trim()}
          >
            {createMutation.isPending ? "Creating..." : "Create Route"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ---------------------------------------------------------------------------
// Edit Dialog
// ---------------------------------------------------------------------------

function EditEmailRouteDialog({
  route,
  onOpenChange,
}: {
  route: FaxEmailRouteWithNumber | null
  onOpenChange: (open: boolean) => void
}) {
  const [emailAddress, setEmailAddress] = useState(route?.emailAddress ?? "")
  const [isActive, setIsActive] = useState(route?.isActive ?? true)
  const [notifyOnFailure, setNotifyOnFailure] = useState(route?.notifyOnFailure ?? true)
  const [errors, setErrors] = useState<Record<string, string>>({})

  const updateMutation = useUpdateFaxEmailRoute(
    route?.faxNumberId ?? "",
    route?.id ?? "",
  )

  function handleSubmit() {
    const trimmed = emailAddress.trim()
    const fieldErrors: Record<string, string> = {}
    if (!trimmed) {
      fieldErrors.emailAddress = "This field is required"
    } else if (!EMAIL_REGEX.test(trimmed)) {
      fieldErrors.emailAddress = "Please enter a valid email address"
    }
    setErrors(fieldErrors)
    if (Object.keys(fieldErrors).length > 0) return
    if (!route) return

    const payload: Record<string, unknown> = {}
    if (trimmed !== route.emailAddress) payload.emailAddress = trimmed
    if (isActive !== route.isActive) payload.isActive = isActive
    if (notifyOnFailure !== route.notifyOnFailure) payload.notifyOnFailure = notifyOnFailure

    if (Object.keys(payload).length === 0) {
      onOpenChange(false)
      return
    }

    updateMutation.mutate(payload, {
      onSuccess: () => {
        toast.success("Email route updated")
        onOpenChange(false)
      },
      onError: (err) => {
        toast.error("Failed to update email route", {
          description: err instanceof Error ? err.message : undefined,
        })
      },
    })
  }

  // Sync form fields when route changes
  if (route && emailAddress === "" && route.emailAddress !== "") {
    setEmailAddress(route.emailAddress)
    setIsActive(route.isActive)
    setNotifyOnFailure(route.notifyOnFailure)
  }

  return (
    <Dialog open={!!route} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Edit Email Route</DialogTitle>
          <DialogDescription>
            Update the routing for{" "}
            <span className="font-mono text-foreground">
              {route?.faxNumber}
            </span>
            {route?.faxNumberLabel ? ` (${route.faxNumberLabel})` : ""}
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-2">
          <div className="space-y-2">
            <Label htmlFor="edit-email">Email Address</Label>
            <Input
              id="edit-email"
              type="email"
              placeholder="user@example.com"
              value={emailAddress}
              onChange={(e) => {
                setEmailAddress(e.target.value)
                if (errors.emailAddress) setErrors((prev) => ({ ...prev, emailAddress: "" }))
              }}
              onBlur={() => {
                const trimmed = emailAddress.trim()
                if (!trimmed) {
                  setErrors((prev) => ({ ...prev, emailAddress: "This field is required" }))
                } else if (!EMAIL_REGEX.test(trimmed)) {
                  setErrors((prev) => ({ ...prev, emailAddress: "Please enter a valid email address" }))
                }
              }}
              onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
              aria-invalid={!!errors.emailAddress}
            />
            {errors.emailAddress && <p className="text-xs text-destructive">{errors.emailAddress}</p>}
          </div>
          <div className="flex items-center justify-between">
            <Label htmlFor="edit-active">Active</Label>
            <Switch
              id="edit-active"
              checked={isActive}
              onCheckedChange={setIsActive}
            />
          </div>
          <div className="flex items-center justify-between">
            <Label htmlFor="edit-notify">Notify on Failure</Label>
            <Switch
              id="edit-notify"
              checked={notifyOnFailure}
              onCheckedChange={setNotifyOnFailure}
            />
          </div>
        </div>
        <DialogFooter>
          <Button
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={updateMutation.isPending}
          >
            Cancel
          </Button>
          <Button
            onClick={handleSubmit}
            disabled={updateMutation.isPending}
          >
            {updateMutation.isPending ? "Saving..." : "Save Changes"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ---------------------------------------------------------------------------
// Delete Dialog
// ---------------------------------------------------------------------------

function DeleteEmailRouteDialog({
  route,
  onOpenChange,
}: {
  route: FaxEmailRouteWithNumber | null
  onOpenChange: (open: boolean) => void
}) {
  const deleteMutation = useDeleteFaxEmailRoute(route?.faxNumberId ?? "")

  return (
    <AlertDialog open={!!route} onOpenChange={onOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            Delete Email Route
          </AlertDialogTitle>
          <AlertDialogDescription>
            Are you sure you want to remove the route for{" "}
            <span className="font-medium text-foreground">
              {route?.emailAddress}
            </span>{" "}
            on fax number{" "}
            <span className="font-mono text-foreground">
              {route?.faxNumber}
            </span>
            ? This action cannot be undone.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel
            onClick={() => onOpenChange(false)}
            disabled={deleteMutation.isPending}
          >
            Cancel
          </AlertDialogCancel>
          <AlertDialogAction
            className={buttonVariants({ variant: "destructive" })}
            disabled={deleteMutation.isPending}
            onClick={() => {
              if (!route) return
              deleteMutation.mutate(route.id, {
                onSuccess: () => {
                  toast.success("Email route deleted")
                  onOpenChange(false)
                },
                onError: (err) => {
                  toast.error("Failed to delete email route", {
                    description: err instanceof Error ? err.message : undefined,
                  })
                },
              })
            }}
          >
            {deleteMutation.isPending ? "Deleting..." : "Delete Route"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}

// ---------------------------------------------------------------------------
// Main Page
// ---------------------------------------------------------------------------

function FaxEmailRoutesPage() {
  useDocumentTitle("Fax Email Routes")
  const { data: routes, isLoading, isError, refetch, dataUpdatedAt, isRefetching } = useAllFaxEmailRoutes()
  const [showCreateDialog, setShowCreateDialog] = useState(false)
  const [editRoute, setEditRoute] = useState<FaxEmailRouteWithNumber | null>(null)
  const [deleteRoute, setDeleteRoute] = useState<FaxEmailRouteWithNumber | null>(null)

  // Search state
  const [search, setSearch] = useState("")
  const debouncedSearch = useDebouncedValue(search)

  const filteredRoutes = useMemo(() => {
    if (!routes) return []
    if (!debouncedSearch) return routes
    const q = debouncedSearch.toLowerCase()
    return routes.filter(
      (route) =>
        route.emailAddress?.toLowerCase().includes(q) ||
        route.faxNumber?.toLowerCase().includes(q),
    )
  }, [routes, debouncedSearch])

  // Selection state
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())

  const allVisibleIds = useMemo(() => filteredRoutes.map((r) => r.id), [filteredRoutes])
  const allSelected = filteredRoutes.length > 0 && filteredRoutes.every((r) => selectedIds.has(r.id))
  const someSelected = filteredRoutes.some((r) => selectedIds.has(r.id))

  const toggleAll = useCallback(() => {
    if (allSelected) {
      setSelectedIds(new Set())
    } else {
      setSelectedIds(new Set(allVisibleIds))
    }
  }, [allSelected, allVisibleIds])

  const toggleOne = useCallback((id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) {
        next.delete(id)
      } else {
        next.add(id)
      }
      return next
    })
  }, [])

  // Export all visible
  const handleExportAll = useCallback(() => {
    if (!routes?.length) return
    exportToCsv("fax-email-routes", csvHeaders, routes)
  }, [routes])

  // Bulk actions
  const bulkActions = useMemo(
    () => [
      createBulkDeleteAction(
        async (id) => {
          const route = routes?.find((r) => r.id === id)
          if (!route) return
          await client.request({
            method: "DELETE",
            url: `/api/fax/numbers/${route.faxNumberId}/email-routes/${id}`,
          })
        },
        () => {
          setSelectedIds(new Set())
        },
      ),
      createExportAction<FaxEmailRouteWithNumber>(
        "fax-email-routes-selected",
        csvHeaders,
        (ids) => (routes ?? []).filter((r) => ids.includes(r.id)),
      ),
    ],
    [routes],
  )

  const hasData = (routes ?? []).length > 0

  const breadcrumbs = (
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
            <Link to="/fax">Fax</Link>
          </BreadcrumbLink>
        </BreadcrumbItem>
        <BreadcrumbSeparator />
        <BreadcrumbItem>
          <BreadcrumbPage>Email Routes</BreadcrumbPage>
        </BreadcrumbItem>
      </BreadcrumbList>
    </Breadcrumb>
  )

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Communications"
        title="Email Routes"
        description="Configure where incoming faxes are delivered via email across all fax numbers."
        breadcrumbs={breadcrumbs}
        actions={
          <div className="flex items-center gap-3">
            <DataFreshness
              dataUpdatedAt={dataUpdatedAt}
              onRefresh={() => refetch()}
              isRefreshing={isRefetching}
            />
            <Button variant="outline" size="sm" onClick={handleExportAll} disabled={!hasData}>
              <Download className="mr-2 h-4 w-4" />
              Export
            </Button>
            <Button size="sm" onClick={() => setShowCreateDialog(true)}>
              <MailPlus className="mr-2 h-4 w-4" /> New Route
            </Button>
          </div>
        }
      />

      <PageSection>
        {isLoading ? (
          <SkeletonTable rows={5} />
        ) : isError ? (
          <EmptyState
            icon={AlertCircle}
            title="Unable to load email routes"
            description="Something went wrong while fetching email routes. Please try refreshing the page."
            action={
              <Button
                variant="outline"
                size="sm"
                onClick={() => window.location.reload()}
              >
                Refresh page
              </Button>
            }
          />
        ) : routes && routes.length > 0 ? (
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle>All Email Routes</CardTitle>
                <p className="text-sm text-muted-foreground">
                  {debouncedSearch
                    ? `Showing ${filteredRoutes.length} of ${routes.length} routes`
                    : `${routes.filter((r) => r.isActive).length} of ${routes.length} routes active`}
                </p>
              </div>
              <div className="relative mt-2 max-w-sm">
                <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  placeholder="Search by email or fax number..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="pl-9 pr-9"
                  aria-label="Search email routes"
                />
                {search && (
                  <button
                    type="button"
                    onClick={() => setSearch("")}
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                    aria-label="Clear search"
                  >
                    <X className="h-4 w-4" />
                  </button>
                )}
              </div>
            </CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
              <Table aria-label="Email routes">
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-10">
                      <Checkbox
                        checked={allSelected}
                        indeterminate={someSelected && !allSelected}
                        onChange={toggleAll}
                        aria-label="Select all email routes"
                      />
                    </TableHead>
                    <TableHead>Email Address</TableHead>
                    <TableHead>Fax Number</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Failure Alerts</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead className="w-16 text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredRoutes.length === 0 && debouncedSearch ? (
                    <TableRow>
                      <TableCell colSpan={7} className="h-24 text-center text-muted-foreground">
                        No routes matching "{debouncedSearch}"
                      </TableCell>
                    </TableRow>
                  ) : null}
                  {filteredRoutes.map((route, index) => (
                    <TableRow
                      key={route.id}
                      data-state={selectedIds.has(route.id) ? "selected" : undefined}
                      className={cn(
                        "cursor-pointer hover:bg-muted/50 transition-colors",
                        index % 2 === 1 ? "bg-muted/20" : "",
                      )}
                      onClick={(e) => {
                        const target = e.target as HTMLElement
                        if (
                          target.closest("[role=checkbox]") ||
                          target.closest("[data-slot=dropdown]") ||
                          target.closest("button") ||
                          target.closest("a")
                        ) {
                          return
                        }
                        setEditRoute(route)
                      }}
                    >
                      <TableCell>
                        <Checkbox
                          checked={selectedIds.has(route.id)}
                          onChange={(e) => {
                            e.stopPropagation()
                            toggleOne(route.id)
                          }}
                          aria-label={`Select route for ${route.emailAddress}`}
                        />
                      </TableCell>
                      <TableCell className="font-mono text-sm">
                        <span className="inline-flex items-center gap-1">
                          {route.emailAddress}
                          <CopyButton value={route.emailAddress} label="email address" />
                        </span>
                      </TableCell>
                      <TableCell>
                        <span className="inline-flex items-center gap-1">
                          <Link
                            to="/fax/numbers/$faxNumberId"
                            params={{ faxNumberId: route.faxNumberId }}
                            className="text-sm text-primary hover:underline"
                            onClick={(e) => e.stopPropagation()}
                          >
                            <span className="font-mono">{route.faxNumber}</span>
                            {route.faxNumberLabel && (
                              <span className="ml-1.5 text-muted-foreground">
                                ({route.faxNumberLabel})
                              </span>
                            )}
                          </Link>
                          <CopyButton value={route.faxNumber} label="fax number" />
                        </span>
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={route.isActive ? "default" : "secondary"}
                        >
                          {route.isActive ? "Active" : "Inactive"}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {route.notifyOnFailure ? (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <span className="inline-flex items-center gap-1 text-sm text-emerald-600 dark:text-emerald-400">
                                <Bell className="h-3.5 w-3.5" /> On
                              </span>
                            </TooltipTrigger>
                            <TooltipContent>
                              Failure notifications enabled
                            </TooltipContent>
                          </Tooltip>
                        ) : (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <span className="inline-flex items-center gap-1 text-sm text-muted-foreground">
                                <BellOff className="h-3.5 w-3.5" /> Off
                              </span>
                            </TooltipTrigger>
                            <TooltipContent>
                              Failure notifications disabled
                            </TooltipContent>
                          </Tooltip>
                        )}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {formatDateTime(route.createdAt, "--")}
                      </TableCell>
                      <TableCell className="text-right">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-8 w-8"
                              data-slot="dropdown"
                              onClick={(e) => e.stopPropagation()}
                            >
                              <MoreVertical className="h-4 w-4" />
                              <span className="sr-only">Actions for {route.emailAddress}</span>
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem asChild>
                              <Link to="/fax/numbers/$faxNumberId" params={{ faxNumberId: route.faxNumberId }}>
                                <Eye className="mr-2 h-4 w-4" />
                                View fax number
                              </Link>
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => setEditRoute(route)}>
                              <Pencil className="mr-2 h-4 w-4" />
                              Edit
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem
                              className="text-destructive focus:text-destructive"
                              onClick={() => setDeleteRoute(route)}
                            >
                              <Trash2 className="mr-2 h-4 w-4" />
                              Delete
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              </div>
            </CardContent>
          </Card>
        ) : (
          <EmptyState
            icon={Mail}
            title="No email routes configured"
            description="Email routes deliver incoming faxes to an email address. Add your first route to get started."
            action={
              <Button size="sm" onClick={() => setShowCreateDialog(true)}>
                <MailPlus className="mr-2 h-4 w-4" /> New Route
              </Button>
            }
          />
        )}
      </PageSection>

      <CreateEmailRouteDialog
        open={showCreateDialog}
        onOpenChange={setShowCreateDialog}
      />
      <EditEmailRouteDialog
        route={editRoute}
        onOpenChange={(open) => {
          if (!open) setEditRoute(null)
        }}
      />
      <DeleteEmailRouteDialog
        route={deleteRoute}
        onOpenChange={(open) => {
          if (!open) setDeleteRoute(null)
        }}
      />

      {/* Bulk action bar */}
      <BulkActionBar
        selectedCount={selectedIds.size}
        selectedIds={Array.from(selectedIds)}
        onClearSelection={() => setSelectedIds(new Set())}
        actions={bulkActions}
      />
    </PageContainer>
  )
}
