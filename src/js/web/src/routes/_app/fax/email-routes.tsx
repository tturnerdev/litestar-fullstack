import { createFileRoute, Link } from "@tanstack/react-router"
import {
  AlertCircle,
  AlertTriangle,
  Bell,
  BellOff,
  Mail,
  MailPlus,
  Pencil,
  Trash2,
} from "lucide-react"
import { useState } from "react"
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
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
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

export const Route = createFileRoute("/_app/fax/email-routes")({
  component: FaxEmailRoutesPage,
})

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

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
  const [error, setError] = useState<string | null>(null)

  const createMutation = useCreateFaxEmailRoute(faxNumberId)

  function resetForm() {
    setFaxNumberId("")
    setEmailAddress("")
    setIsActive(true)
    setNotifyOnFailure(true)
    setError(null)
  }

  function handleSubmit() {
    if (!faxNumberId) {
      setError("Please select a fax number")
      return
    }
    const trimmed = emailAddress.trim()
    if (!trimmed) {
      setError("Email address is required")
      return
    }
    if (!EMAIL_REGEX.test(trimmed)) {
      setError("Please enter a valid email address")
      return
    }
    setError(null)
    createMutation.mutate(
      { emailAddress: trimmed, isActive, notifyOnFailure },
      {
        onSuccess: () => {
          resetForm()
          onOpenChange(false)
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
            <Select value={faxNumberId} onValueChange={setFaxNumberId}>
              <SelectTrigger id="create-fax-number">
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
                if (error) setError(null)
              }}
              onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
              aria-invalid={!!error}
            />
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
          {error && <p className="text-sm text-destructive">{error}</p>}
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
  const [error, setError] = useState<string | null>(null)

  const updateMutation = useUpdateFaxEmailRoute(
    route?.faxNumberId ?? "",
    route?.id ?? "",
  )

  function handleSubmit() {
    const trimmed = emailAddress.trim()
    if (!trimmed) {
      setError("Email address is required")
      return
    }
    if (!EMAIL_REGEX.test(trimmed)) {
      setError("Please enter a valid email address")
      return
    }
    if (!route) return
    setError(null)

    const payload: Record<string, unknown> = {}
    if (trimmed !== route.emailAddress) payload.emailAddress = trimmed
    if (isActive !== route.isActive) payload.isActive = isActive
    if (notifyOnFailure !== route.notifyOnFailure) payload.notifyOnFailure = notifyOnFailure

    if (Object.keys(payload).length === 0) {
      onOpenChange(false)
      return
    }

    updateMutation.mutate(payload, {
      onSuccess: () => onOpenChange(false),
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
                if (error) setError(null)
              }}
              onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
              aria-invalid={!!error}
            />
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
          {error && <p className="text-sm text-destructive">{error}</p>}
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
                onSuccess: () => onOpenChange(false),
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
  const { data: routes, isLoading, isError } = useAllFaxEmailRoutes()
  const [showCreateDialog, setShowCreateDialog] = useState(false)
  const [editRoute, setEditRoute] = useState<FaxEmailRouteWithNumber | null>(null)
  const [deleteRoute, setDeleteRoute] = useState<FaxEmailRouteWithNumber | null>(null)

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
          <Button size="sm" onClick={() => setShowCreateDialog(true)}>
            <MailPlus className="mr-2 h-4 w-4" /> New Route
          </Button>
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
                  {routes.filter((r) => r.isActive).length} of {routes.length}{" "}
                  routes active
                </p>
              </div>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Email Address</TableHead>
                    <TableHead>Fax Number</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Failure Alerts</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {routes.map((route) => (
                    <TableRow key={route.id}>
                      <TableCell className="font-mono text-sm">
                        {route.emailAddress}
                      </TableCell>
                      <TableCell>
                        <Link
                          to="/fax/numbers/$faxNumberId"
                          params={{ faxNumberId: route.faxNumberId }}
                          className="text-sm text-primary hover:underline"
                        >
                          <span className="font-mono">{route.faxNumber}</span>
                          {route.faxNumberLabel && (
                            <span className="ml-1.5 text-muted-foreground">
                              ({route.faxNumberLabel})
                            </span>
                          )}
                        </Link>
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
                        {route.createdAt
                          ? new Date(route.createdAt).toLocaleDateString()
                          : "--"}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-1">
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Button
                                variant="outline"
                                size="sm"
                                onClick={() => setEditRoute(route)}
                                className="h-8 w-8 p-0"
                              >
                                <Pencil className="h-3.5 w-3.5" />
                              </Button>
                            </TooltipTrigger>
                            <TooltipContent>Edit route</TooltipContent>
                          </Tooltip>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Button
                                variant="outline"
                                size="sm"
                                onClick={() => setDeleteRoute(route)}
                                className="h-8 w-8 p-0 text-destructive hover:text-destructive hover:bg-destructive/10"
                              >
                                <Trash2 className="h-3.5 w-3.5" />
                              </Button>
                            </TooltipTrigger>
                            <TooltipContent>Delete route</TooltipContent>
                          </Tooltip>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
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
    </PageContainer>
  )
}
