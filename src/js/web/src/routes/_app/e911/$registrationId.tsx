import { createFileRoute, Link, useRouter } from "@tanstack/react-router"
import { useState } from "react"
import {
  AlertCircle,
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  ChevronRight,
  Copy,
  Fingerprint,
  Link2,
  Loader2,
  MapPin,
  MoreHorizontal,
  Pencil,
  Phone,
  ShieldAlert,
  Trash2,
  Users,
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
import { Button, buttonVariants } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { EmptyState } from "@/components/ui/empty-state"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Skeleton } from "@/components/ui/skeleton"
import { CopyButton } from "@/components/ui/copy-button"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { EntityActivityPanel } from "@/components/shared/entity-activity-panel"
import { toast } from "sonner"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"
import {
  useE911Registration,
  useUpdateE911Registration,
  useDeleteE911Registration,
  useValidateE911Registration,
} from "@/lib/api/hooks/e911"
import { useTeam } from "@/lib/api/hooks/teams"

export const Route = createFileRoute("/_app/e911/$registrationId")({
  component: E911DetailPage,
})

// -- Timestamp with tooltip ---------------------------------------------------

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

// -- Delete confirm dialog ----------------------------------------------------

function DeleteConfirmDialog({
  address,
  onDelete,
  isPending,
  open: controlledOpen,
  onOpenChange,
  showTrigger = true,
}: {
  address: string
  onDelete: () => void
  isPending: boolean
  open?: boolean
  onOpenChange?: (open: boolean) => void
  showTrigger?: boolean
}) {
  const [internalOpen, setInternalOpen] = useState(false)
  const open = controlledOpen ?? internalOpen
  const setOpen = onOpenChange ?? setInternalOpen

  return (
    <>
      {showTrigger && (
        <Button variant="destructive" size="sm" onClick={() => setOpen(true)}>
          <Trash2 className="mr-2 h-4 w-4" />
          Delete Registration
        </Button>
      )}
      <AlertDialog open={open} onOpenChange={setOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-destructive" />
              Delete E911 registration?
            </AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete the E911 registration for "{address}"? This action cannot be undone and may impact emergency services for the associated phone number.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setOpen(false)} disabled={isPending}>
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              className={buttonVariants({ variant: "destructive" })}
              onClick={onDelete}
              disabled={isPending}
            >
              {isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {isPending ? "Deleting..." : "Delete"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

// -- Main page ----------------------------------------------------------------

function E911DetailPage() {
  const { registrationId } = Route.useParams()
  const router = useRouter()
  const { data, isLoading, isError, refetch } = useE911Registration(registrationId)
  useDocumentTitle(data ? `E911 - ${data.addressLine1}` : "E911 Details")

  const updateMutation = useUpdateE911Registration(registrationId)
  const deleteMutation = useDeleteE911Registration()
  const validateMutation = useValidateE911Registration(registrationId)
  const teamQuery = useTeam(data?.teamId ?? "")

  const [showDeleteDialog, setShowDeleteDialog] = useState(false)
  const [editing, setEditing] = useState(false)
  const [editAddr1, setEditAddr1] = useState("")
  const [editAddr2, setEditAddr2] = useState("")
  const [editCity, setEditCity] = useState("")
  const [editState, setEditState] = useState("")
  const [editPostalCode, setEditPostalCode] = useState("")
  const [editCountry, setEditCountry] = useState("")

  function startEditing() {
    if (!data) return
    setEditAddr1(data.addressLine1)
    setEditAddr2(data.addressLine2 ?? "")
    setEditCity(data.city)
    setEditState(data.state)
    setEditPostalCode(data.postalCode)
    setEditCountry(data.country)
    setEditing(true)
  }

  function handleSave() {
    if (!data) return
    const payload: Record<string, unknown> = {}
    if (editAddr1 !== data.addressLine1) payload.addressLine1 = editAddr1
    if (editAddr2 !== (data.addressLine2 ?? "")) payload.addressLine2 = editAddr2 || null
    if (editCity !== data.city) payload.city = editCity
    if (editState !== data.state) payload.state = editState
    if (editPostalCode !== data.postalCode) payload.postalCode = editPostalCode
    if (editCountry !== data.country) payload.country = editCountry
    updateMutation.mutate(payload, {
      onSuccess: () => setEditing(false),
    })
  }

  const handleDelete = async () => {
    await deleteMutation.mutateAsync(registrationId)
    router.navigate({ to: "/e911" })
  }

  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <div className="space-y-2">
          <Skeleton className="h-4 w-32" />
          <Skeleton className="h-8 w-56" />
          <Skeleton className="h-4 w-40" />
        </div>
        <PageSection>
          <div className="rounded-xl border border-border/60 bg-card/80 p-6 space-y-4">
            <div className="flex items-center gap-2">
              <Skeleton className="h-5 w-5 rounded" />
              <Skeleton className="h-6 w-28" />
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
        </PageSection>
      </PageContainer>
    )
  }

  if (isError || !data) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader
          eyebrow="E911"
          title="Registration Details"
          actions={
            <Button variant="outline" size="sm" asChild>
              <Link to="/e911">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back to E911
              </Link>
            </Button>
          }
        />
        <PageSection>
          <EmptyState
            icon={AlertCircle}
            title="Unable to load E911 registration"
            description="Something went wrong. Please try again."
            action={<Button variant="outline" size="sm" onClick={() => refetch()}>Try again</Button>}
          />
        </PageSection>
      </PageContainer>
    )
  }

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="E911"
        title={data.addressLine1}
        description={`${data.city}, ${data.state} ${data.postalCode}`}
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
                  <Link to="/e911">E911</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbPage>{data.addressLine1}</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
        actions={
          <div className="flex items-center gap-3">
            {data.validated ? (
              <Badge className="bg-green-500/10 text-green-600 dark:text-green-400 border-green-500/30">
                <CheckCircle2 className="mr-1 h-3 w-3" />
                Validated
              </Badge>
            ) : (
              <Badge variant="outline" className="border-red-500/30 text-red-600 dark:text-red-400">
                <XCircle className="mr-1 h-3 w-3" />
                Pending Validation
              </Badge>
            )}
            {!data.validated && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => validateMutation.mutate()}
                disabled={validateMutation.isPending}
              >
                {validateMutation.isPending ? (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                ) : (
                  <CheckCircle2 className="mr-2 h-4 w-4" />
                )}
                Validate
              </Button>
            )}
            {!editing && (
              <Button variant="outline" size="sm" onClick={startEditing}>
                <Pencil className="mr-2 h-4 w-4" /> Edit
              </Button>
            )}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm">
                  <MoreHorizontal className="h-4 w-4" />
                  <span className="sr-only">Actions</span>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => { navigator.clipboard.writeText(registrationId); toast.success("Copied registration ID") }}>
                  <Copy className="mr-2 h-4 w-4" />
                  Copy Registration ID
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  variant="destructive"
                  onClick={() => setShowDeleteDialog(true)}
                >
                  <Trash2 className="mr-2 h-4 w-4" />
                  Delete Registration
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        }
      />

      {/* Delete dialog triggered from dropdown */}
      <DeleteConfirmDialog
        address={`${data.addressLine1}, ${data.city}`}
        onDelete={handleDelete}
        isPending={deleteMutation.isPending}
        open={showDeleteDialog}
        onOpenChange={setShowDeleteDialog}
        showTrigger={false}
      />

      {/* Address Details */}
      <PageSection>
        <SectionErrorBoundary name="Address">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <MapPin className="h-5 w-5 text-muted-foreground" />
              Address
            </CardTitle>
            {editing && (
              <div className="flex gap-2">
                <Button variant="ghost" size="sm" onClick={() => setEditing(false)}>
                  Cancel
                </Button>
                <Button size="sm" onClick={handleSave} disabled={updateMutation.isPending}>
                  {updateMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  Save
                </Button>
              </div>
            )}
          </CardHeader>
          <CardContent>
            {editing ? (
              <div className="space-y-4">
                <div className="grid gap-4 md:grid-cols-2">
                  <div className="space-y-2">
                    <Label>Address Line 1</Label>
                    <Input value={editAddr1} onChange={(e) => setEditAddr1(e.target.value)} />
                  </div>
                  <div className="space-y-2">
                    <Label>Address Line 2</Label>
                    <Input value={editAddr2} onChange={(e) => setEditAddr2(e.target.value)} placeholder="Suite, Apt, etc." />
                  </div>
                  <div className="space-y-2">
                    <Label>City</Label>
                    <Input value={editCity} onChange={(e) => setEditCity(e.target.value)} />
                  </div>
                  <div className="space-y-2">
                    <Label>State</Label>
                    <Input value={editState} onChange={(e) => setEditState(e.target.value)} />
                  </div>
                  <div className="space-y-2">
                    <Label>Postal Code</Label>
                    <Input value={editPostalCode} onChange={(e) => setEditPostalCode(e.target.value)} />
                  </div>
                  <div className="space-y-2">
                    <Label>Country</Label>
                    <Input value={editCountry} onChange={(e) => setEditCountry(e.target.value)} />
                  </div>
                </div>
              </div>
            ) : (
              <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-3">
                <div>
                  <p className="text-muted-foreground">Address Line 1</p>
                  <p className="font-medium">{data.addressLine1}</p>
                </div>
                <div>
                  <p className="text-muted-foreground">Address Line 2</p>
                  <p>{data.addressLine2 || "---"}</p>
                </div>
                <div>
                  <p className="text-muted-foreground">City</p>
                  <p>{data.city}</p>
                </div>
                <div>
                  <p className="text-muted-foreground">State</p>
                  <p>{data.state}</p>
                </div>
                <div>
                  <p className="text-muted-foreground">Postal Code</p>
                  <p>{data.postalCode}</p>
                </div>
                <div>
                  <p className="text-muted-foreground">Country</p>
                  <p>{data.country}</p>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
        </SectionErrorBoundary>
      </PageSection>

      {/* Linked Phone Number */}
      <PageSection delay={0.1}>
        <SectionErrorBoundary name="Linked Phone Number">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Phone className="h-5 w-5 text-muted-foreground" />
              Linked Phone Number
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-3">
              <div>
                <p className="text-muted-foreground">Number</p>
                <p className="font-mono">{data.phoneNumberDisplay || "---"}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Label</p>
                <p>{data.phoneNumberLabel || "---"}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Phone Number ID</p>
                <div className="flex items-center gap-1">
                  <p className="font-mono text-xs">{data.phoneNumberId || "---"}</p>
                  {data.phoneNumberId && <CopyButton value={data.phoneNumberId} label="phone number ID" />}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
        </SectionErrorBoundary>
      </PageSection>

      {/* Linked Location */}
      <PageSection delay={0.15}>
        <SectionErrorBoundary name="Linked Location">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <MapPin className="h-5 w-5 text-muted-foreground" />
              Linked Location
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-3">
              <div>
                <p className="text-muted-foreground">Location Name</p>
                <p>{data.locationName || "---"}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Location ID</p>
                <div className="flex items-center gap-1">
                  <p className="font-mono text-xs">{data.locationId || "---"}</p>
                  {data.locationId && <CopyButton value={data.locationId} label="location ID" />}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
        </SectionErrorBoundary>
      </PageSection>

      {/* Related Resources */}
      <PageSection delay={0.2}>
        <SectionErrorBoundary name="Related Resources">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Link2 className="h-5 w-5 text-muted-foreground" />
              Related Resources
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {/* Phone Number */}
              {data.phoneNumberId ? (
                <Link
                  to="/voice/phone-numbers/$phoneNumberId"
                  params={{ phoneNumberId: data.phoneNumberId }}
                  className="group flex items-center gap-3 rounded-lg border border-border/60 px-4 py-3 transition-colors hover:bg-muted/50 hover:border-primary/30"
                >
                  <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-amber-500/10 text-amber-600 dark:text-amber-400">
                    <Phone className="h-4.5 w-4.5" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="text-xs text-muted-foreground">Phone Number</p>
                    <p className="truncate text-sm font-medium group-hover:text-primary">
                      {data.phoneNumberDisplay ?? data.phoneNumberLabel ?? data.phoneNumberId.slice(0, 8)}
                    </p>
                  </div>
                  <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground/50 transition-transform group-hover:translate-x-0.5 group-hover:text-primary" />
                </Link>
              ) : (
                <div className="flex items-center gap-3 rounded-lg border border-dashed border-border/60 px-4 py-3">
                  <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-muted text-muted-foreground/50">
                    <Phone className="h-4.5 w-4.5" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="text-xs text-muted-foreground">Phone Number</p>
                    <p className="text-sm text-muted-foreground">Not assigned</p>
                  </div>
                </div>
              )}

              {/* Location */}
              {data.locationId ? (
                <Link
                  to="/locations/$locationId"
                  params={{ locationId: data.locationId }}
                  className="group flex items-center gap-3 rounded-lg border border-border/60 px-4 py-3 transition-colors hover:bg-muted/50 hover:border-primary/30"
                >
                  <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
                    <MapPin className="h-4.5 w-4.5" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="text-xs text-muted-foreground">Location</p>
                    <p className="truncate text-sm font-medium group-hover:text-primary">
                      {data.locationName ?? data.locationId.slice(0, 8)}
                    </p>
                  </div>
                  <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground/50 transition-transform group-hover:translate-x-0.5 group-hover:text-primary" />
                </Link>
              ) : (
                <div className="flex items-center gap-3 rounded-lg border border-dashed border-border/60 px-4 py-3">
                  <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-muted text-muted-foreground/50">
                    <MapPin className="h-4.5 w-4.5" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="text-xs text-muted-foreground">Location</p>
                    <p className="text-sm text-muted-foreground">Not assigned</p>
                  </div>
                </div>
              )}

              {/* Team */}
              {data.teamId ? (
                <Link
                  to="/teams/$teamId"
                  params={{ teamId: data.teamId }}
                  className="group flex items-center gap-3 rounded-lg border border-border/60 px-4 py-3 transition-colors hover:bg-muted/50 hover:border-primary/30"
                >
                  <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-blue-500/10 text-blue-600 dark:text-blue-400">
                    <Users className="h-4.5 w-4.5" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="text-xs text-muted-foreground">Team</p>
                    <p className="truncate text-sm font-medium group-hover:text-primary">
                      {teamQuery.data?.name ?? "Loading..."}
                    </p>
                  </div>
                  <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground/50 transition-transform group-hover:translate-x-0.5 group-hover:text-primary" />
                </Link>
              ) : (
                <div className="flex items-center gap-3 rounded-lg border border-dashed border-border/60 px-4 py-3">
                  <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-muted text-muted-foreground/50">
                    <Users className="h-4.5 w-4.5" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="text-xs text-muted-foreground">Team</p>
                    <p className="text-sm text-muted-foreground">Not assigned</p>
                  </div>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
        </SectionErrorBoundary>
      </PageSection>

      {/* Validation Status */}
      <PageSection delay={0.25}>
        <SectionErrorBoundary name="Validation Status">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5 text-muted-foreground" />
              Validation Status
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-4">
              <div>
                <p className="text-muted-foreground">Status</p>
                <div className="mt-0.5">
                  {data.validated ? (
                    <Badge className="bg-green-500/10 text-green-600 dark:text-green-400 border-green-500/30">
                      <CheckCircle2 className="mr-1 h-3 w-3" />
                      Validated
                    </Badge>
                  ) : (
                    <Badge variant="outline" className="border-red-500/30 text-red-600 dark:text-red-400">
                      <XCircle className="mr-1 h-3 w-3" />
                      Pending
                    </Badge>
                  )}
                </div>
              </div>
              <TimestampField label="Validated At" value={data.validatedAt} />
              <div>
                <p className="text-muted-foreground">Carrier Registration ID</p>
                <div className="flex items-center gap-1">
                  <p className="font-mono text-xs">{data.carrierRegistrationId || "---"}</p>
                  {data.carrierRegistrationId && <CopyButton value={data.carrierRegistrationId} label="carrier reg ID" />}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
        </SectionErrorBoundary>
      </PageSection>

      {/* Metadata */}
      <PageSection delay={0.3}>
        <SectionErrorBoundary name="Metadata">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Fingerprint className="h-5 w-5 text-muted-foreground" />
              Metadata
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-4">
              <div>
                <p className="text-muted-foreground text-sm">Registration ID</p>
                <div className="flex items-center gap-1">
                  <p className="font-mono text-xs">{registrationId}</p>
                  <CopyButton value={registrationId} label="registration ID" />
                </div>
              </div>
              <div>
                <p className="text-muted-foreground text-sm">Team ID</p>
                <div className="flex items-center gap-1">
                  <p className="font-mono text-xs">{data.teamId}</p>
                  <CopyButton value={data.teamId} label="team ID" />
                </div>
              </div>
              <TimestampField label="Created" value={data.createdAt} />
              <TimestampField label="Updated" value={data.updatedAt} />
            </div>
          </CardContent>
        </Card>
        </SectionErrorBoundary>
      </PageSection>

      {/* Danger Zone */}
      <PageSection delay={0.35}>
        <SectionErrorBoundary name="Danger Zone">
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
                <p className="font-medium text-sm">Delete this E911 registration</p>
                <p className="text-sm text-muted-foreground">
                  This action cannot be undone. Emergency services may not be able to locate callers using the associated phone number.
                </p>
              </div>
              <DeleteConfirmDialog
                address={`${data.addressLine1}, ${data.city}`}
                onDelete={handleDelete}
                isPending={deleteMutation.isPending}
              />
            </div>
          </CardContent>
        </Card>
        </SectionErrorBoundary>
      </PageSection>

      <PageSection delay={0.4}>
        <SectionErrorBoundary name="Activity">
        <EntityActivityPanel
          targetType="e911_registration"
          targetId={registrationId}
        />
        </SectionErrorBoundary>
      </PageSection>
    </PageContainer>
  )
}
