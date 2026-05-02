import { createFileRoute, Link, useNavigate, useRouter } from "@tanstack/react-router"
import { useEffect, useState } from "react"
import { AlertCircle, AlertTriangle, ArrowLeft, Clock, Cpu, ExternalLink, Loader2, MapPin, Pencil, RefreshCw, Trash2 } from "lucide-react"
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { EmptyState } from "@/components/ui/empty-state"
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
import { buttonVariants } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { CopyButton } from "@/components/ui/copy-button"
import { Separator } from "@/components/ui/separator"
import { Textarea } from "@/components/ui/textarea"
import { EntityActivityPanel } from "@/components/shared/entity-activity-panel"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { useAuthStore } from "@/lib/auth"
import { formatDateTime, formatRelativeTime } from "@/lib/date-utils"
import { useDevicesByLocation } from "@/lib/api/hooks/devices"
import { useDeleteLocation, useLocation, useUpdateLocation, type Location } from "@/lib/api/hooks/locations"

export const Route = createFileRoute("/_app/locations/$locationId/")({
  component: LocationDetailPage,
  validateSearch: (search: Record<string, unknown>): { edit?: boolean } => ({
    edit: search.edit === true || search.edit === "true" || undefined,
  }),
})

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildGoogleMapsUrl(location: Location): string | null {
  const parts = [
    location.addressLine1,
    location.addressLine2,
    location.city,
    location.state,
    location.postalCode,
    location.country,
  ].filter(Boolean)
  if (parts.length === 0) return null
  return `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(parts.join(", "))}`
}

function formatFullAddress(location: Location): string | null {
  const line1 = location.addressLine1
  const line2 = location.addressLine2
  const cityStateZip = [location.city, location.state].filter(Boolean).join(", ")
  const zipCountry = [location.postalCode, location.country].filter(Boolean).join(" ")
  const parts = [line1, line2, [cityStateZip, zipCountry].filter(Boolean).join(" ")].filter(Boolean)
  if (parts.length === 0) return null
  return parts.join(", ")
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

function LocationDetailPage() {
  const { locationId } = Route.useParams()
  const { edit: editParam } = Route.useSearch()
  const router = useRouter()
  const navigate = useNavigate()
  const { currentTeam } = useAuthStore()
  const teamId = currentTeam?.id ?? ""

  const { data, isLoading, isError, refetch } = useLocation(teamId, locationId)
  useDocumentTitle(data?.name ?? "Location")
  const updateLocation = useUpdateLocation(teamId, locationId)
  const deleteLocation = useDeleteLocation(teamId)
  const { data: locationDevices, isLoading: devicesLoading } = useDevicesByLocation(locationId)

  const [editing, setEditing] = useState(false)
  const [editName, setEditName] = useState("")
  const [editDescription, setEditDescription] = useState("")
  const [editAddress1, setEditAddress1] = useState("")
  const [editAddress2, setEditAddress2] = useState("")
  const [editCity, setEditCity] = useState("")
  const [editState, setEditState] = useState("")
  const [editPostalCode, setEditPostalCode] = useState("")
  const [editCountry, setEditCountry] = useState("")

  useEffect(() => {
    if (editParam && data && !editing) {
      startEditing(data)
      navigate({
        to: "/locations/$locationId",
        params: { locationId },
        search: {},
        replace: true,
      })
    }
  }, [editParam, data])

  function startEditing(location: Location) {
    setEditName(location.name)
    setEditDescription(location.description ?? "")
    setEditAddress1(location.addressLine1 ?? "")
    setEditAddress2(location.addressLine2 ?? "")
    setEditCity(location.city ?? "")
    setEditState(location.state ?? "")
    setEditPostalCode(location.postalCode ?? "")
    setEditCountry(location.country ?? "")
    setEditing(true)
  }

  function handleSave() {
    const payload: Record<string, unknown> = {}
    if (editName !== data?.name) payload.name = editName
    if (editDescription !== (data?.description ?? "")) payload.description = editDescription || null
    if (data?.locationType === "ADDRESSED") {
      if (editAddress1 !== (data?.addressLine1 ?? "")) payload.addressLine1 = editAddress1 || null
      if (editAddress2 !== (data?.addressLine2 ?? "")) payload.addressLine2 = editAddress2 || null
      if (editCity !== (data?.city ?? "")) payload.city = editCity || null
      if (editState !== (data?.state ?? "")) payload.state = editState || null
      if (editPostalCode !== (data?.postalCode ?? "")) payload.postalCode = editPostalCode || null
      if (editCountry !== (data?.country ?? "")) payload.country = editCountry || null
    }
    updateLocation.mutate(payload, {
      onSuccess: () => setEditing(false),
    })
  }

  const handleDelete = async () => {
    await deleteLocation.mutateAsync(locationId)
    router.navigate({ to: "/locations" })
  }

  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        {/* Header skeleton */}
        <div className="space-y-2">
          <Skeleton className="h-4 w-28" />
          <Skeleton className="h-8 w-52" />
          <Skeleton className="h-4 w-64" />
        </div>
        {/* Two-column layout skeleton */}
        <PageSection>
          <div className="grid gap-6 md:grid-cols-[1.1fr_0.9fr]">
            {/* Main column */}
            <div className="space-y-6">
              {/* Location Info card */}
              <div className="rounded-xl border border-border/60 bg-card/80 p-6 shadow-md shadow-primary/10 space-y-4">
                <div className="flex items-center gap-2">
                  <Skeleton className="h-5 w-5 rounded" />
                  <Skeleton className="h-6 w-40" />
                </div>
                <div className="space-y-4">
                  <Skeleton className="h-3 w-16" />
                  <div className="grid gap-4 md:grid-cols-2">
                    {Array.from({ length: 4 }).map((_, i) => (
                      <div key={i} className="space-y-1.5">
                        <Skeleton className="h-3.5 w-20" />
                        <Skeleton className="h-5 w-36" />
                      </div>
                    ))}
                  </div>
                  <Separator />
                  <Skeleton className="h-3 w-16" />
                  <div className="grid gap-4 md:grid-cols-2">
                    {Array.from({ length: 6 }).map((_, i) => (
                      <div key={i} className="space-y-1.5">
                        <Skeleton className="h-3.5 w-24" />
                        <Skeleton className="h-5 w-32" />
                      </div>
                    ))}
                  </div>
                </div>
              </div>
              {/* Danger zone */}
              <div className="rounded-xl border border-destructive/30 bg-card/80 p-6 space-y-3">
                <Skeleton className="h-6 w-28" />
                <Skeleton className="h-16 w-full rounded-lg" />
              </div>
            </div>
            {/* Sidebar */}
            <div className="space-y-4">
              {/* Metadata card */}
              <div className="rounded-xl border border-border/60 bg-card/80 p-6 shadow-md shadow-primary/10 space-y-4">
                <div className="flex items-center gap-2">
                  <Skeleton className="h-4 w-4 rounded" />
                  <Skeleton className="h-5 w-24" />
                </div>
                {Array.from({ length: 3 }).map((_, i) => (
                  <div key={i} className="space-y-1">
                    <Skeleton className="h-3 w-20" />
                    <Skeleton className="h-5 w-40" />
                  </div>
                ))}
              </div>
              {/* Sub-locations card */}
              <div className="rounded-xl border border-border/60 bg-card/80 p-6 shadow-md shadow-primary/10 space-y-3">
                <div className="flex items-center gap-2">
                  <Skeleton className="h-4 w-4 rounded" />
                  <Skeleton className="h-5 w-28" />
                </div>
                {Array.from({ length: 2 }).map((_, i) => (
                  <Skeleton key={i} className="h-14 w-full rounded-xl" />
                ))}
              </div>
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
          eyebrow="Locations"
          title="Location Details"
          actions={
            <Button variant="outline" size="sm" asChild>
              <Link to="/locations">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back to locations
              </Link>
            </Button>
          }
        />
        <PageSection>
          <EmptyState
            icon={AlertCircle}
            title="Unable to load location"
            description="Something went wrong. Please try again."
            action={
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={() => refetch()}>
                  <RefreshCw className="mr-2 h-4 w-4" /> Try again
                </Button>
                <Button variant="ghost" size="sm" asChild>
                  <Link to="/locations">Back to locations</Link>
                </Button>
              </div>
            }
          />
        </PageSection>
      </PageContainer>
    )
  }

  const isAddressed = data.locationType === "ADDRESSED"
  const children = data.children ?? []

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Locations"
        title={data.name}
        description={data.description || undefined}
        breadcrumbs={
          <Breadcrumb>
            <BreadcrumbList>
              <BreadcrumbItem><BreadcrumbLink asChild><Link to="/home">Home</Link></BreadcrumbLink></BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem><BreadcrumbLink asChild><Link to="/locations">Locations</Link></BreadcrumbLink></BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem><BreadcrumbPage>{data.name}</BreadcrumbPage></BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
        actions={
          <div className="flex items-center gap-3">
            <Badge variant="outline" className="uppercase">
              {isAddressed ? "Addressed" : "Physical"}
            </Badge>
            {!editing && (
              <Button variant="outline" size="sm" onClick={() => startEditing(data)}>
                <Pencil className="mr-2 h-4 w-4" /> Edit
              </Button>
            )}
            <Button variant="outline" size="sm" asChild>
              <Link to="/locations">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back
              </Link>
            </Button>
          </div>
        }
      />

      <PageSection>
        <div className="grid gap-6 md:grid-cols-[1.1fr_0.9fr]">
          {/* Main information card */}
          <div className="space-y-6">
            <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
              <CardHeader className="flex flex-row items-center justify-between">
                <CardTitle className="flex items-center gap-2">
                  <MapPin className="h-5 w-5 text-muted-foreground" />
                  Location Information
                </CardTitle>
                {editing && (
                  <div className="flex gap-2">
                    <Button variant="ghost" size="sm" onClick={() => setEditing(false)}>
                      Cancel
                    </Button>
                    <Button size="sm" onClick={handleSave} disabled={updateLocation.isPending}>
                      {updateLocation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                      Save
                    </Button>
                  </div>
                )}
              </CardHeader>
              <CardContent className="space-y-4">
                {editing ? (
                  <div className="space-y-4">
                    <div className="space-y-2">
                      <Label>Name</Label>
                      <Input value={editName} onChange={(e) => setEditName(e.target.value)} />
                    </div>
                    <div className="space-y-2">
                      <Label>Description</Label>
                      <Textarea value={editDescription} onChange={(e) => setEditDescription(e.target.value)} rows={3} />
                    </div>
                    {isAddressed && (
                      <>
                        <Separator />
                        <h4 className="text-sm font-medium">Address</h4>
                        <div className="space-y-3">
                          <div className="space-y-2">
                            <Label>Address Line 1</Label>
                            <Input value={editAddress1} onChange={(e) => setEditAddress1(e.target.value)} />
                          </div>
                          <div className="space-y-2">
                            <Label>Address Line 2</Label>
                            <Input value={editAddress2} onChange={(e) => setEditAddress2(e.target.value)} />
                          </div>
                          <div className="grid grid-cols-2 gap-3">
                            <div className="space-y-2">
                              <Label>City</Label>
                              <Input value={editCity} onChange={(e) => setEditCity(e.target.value)} />
                            </div>
                            <div className="space-y-2">
                              <Label>State</Label>
                              <Input value={editState} onChange={(e) => setEditState(e.target.value)} />
                            </div>
                          </div>
                          <div className="grid grid-cols-2 gap-3">
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
                      </>
                    )}
                  </div>
                ) : (
                  <div className="space-y-6">
                    {/* General section */}
                    <div className="space-y-4">
                      <h4 className="text-sm font-medium text-muted-foreground uppercase tracking-wider">General</h4>
                      <div className="grid gap-4 text-sm md:grid-cols-2">
                        <InfoField label="Name" value={data.name} />
                        <InfoField label="Type" value={isAddressed ? "Addressed" : "Physical"} />
                        {data.description && (
                          <div className="md:col-span-2">
                            <InfoField label="Description" value={data.description} />
                          </div>
                        )}
                        {data.teamId && <InfoField label="Team" value={data.teamId} mono />}
                      </div>
                    </div>

                    {/* Address section */}
                    {isAddressed && (
                      <>
                        <Separator />
                        <div className="space-y-4">
                          <div className="flex items-center justify-between">
                            <h4 className="text-sm font-medium text-muted-foreground uppercase tracking-wider">Address</h4>
                            {buildGoogleMapsUrl(data) && (
                              <Button variant="outline" size="sm" asChild>
                                <a
                                  href={buildGoogleMapsUrl(data)!}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                >
                                  <MapPin className="mr-2 h-3.5 w-3.5" />
                                  View on Map
                                  <ExternalLink className="ml-2 h-3 w-3" />
                                </a>
                              </Button>
                            )}
                          </div>
                          {formatFullAddress(data) && (
                            <div className="rounded-lg border border-border/60 bg-muted/30 p-4">
                              <p className="text-sm leading-relaxed">{formatFullAddress(data)}</p>
                            </div>
                          )}
                          <div className="grid gap-4 text-sm md:grid-cols-2">
                            <InfoField label="Address Line 1" value={data.addressLine1} />
                            <InfoField label="Address Line 2" value={data.addressLine2} />
                            <InfoField label="City" value={data.city} />
                            <InfoField label="State" value={data.state} />
                            <InfoField label="Postal Code" value={data.postalCode} />
                            <InfoField label="Country" value={data.country} />
                          </div>
                        </div>
                      </>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Devices at this Location */}
            <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
              <CardHeader className="flex flex-row items-center justify-between">
                <div className="flex items-center gap-2">
                  <CardTitle className="flex items-center gap-2">
                    <Cpu className="h-5 w-5 text-muted-foreground" />
                    Devices at this Location
                  </CardTitle>
                  {!devicesLoading && locationDevices && locationDevices.length > 0 && (
                    <Badge variant="secondary" className="ml-1">{locationDevices.length}</Badge>
                  )}
                </div>
                {!devicesLoading && locationDevices && locationDevices.length > 0 && (
                  <Button variant="outline" size="sm" asChild>
                    <Link to="/devices" search={{ search: data.name }}>
                      View all
                      <ExternalLink className="ml-2 h-3 w-3" />
                    </Link>
                  </Button>
                )}
              </CardHeader>
              <CardContent>
                {devicesLoading ? (
                  <div className="space-y-3">
                    {Array.from({ length: 3 }).map((_, i) => (
                      <Skeleton key={i} className="h-10 w-full" />
                    ))}
                  </div>
                ) : locationDevices && locationDevices.length > 0 ? (
                  <Table aria-label="Devices at this location">
                    <TableHeader>
                      <TableRow>
                        <TableHead>Name</TableHead>
                        <TableHead>Type</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>MAC Address</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {locationDevices.map((device) => (
                        <TableRow key={device.id}>
                          <TableCell>
                            <Link
                              to="/devices/$deviceId"
                              params={{ deviceId: device.id }}
                              className="font-medium text-primary hover:underline"
                            >
                              {device.name}
                            </Link>
                          </TableCell>
                          <TableCell>
                            <span className="capitalize">{device.deviceType.replace(/_/g, " ")}</span>
                          </TableCell>
                          <TableCell>
                            <Badge variant={device.status === "online" ? "default" : "secondary"}>
                              {device.status}
                            </Badge>
                          </TableCell>
                          <TableCell className="font-mono text-xs">
                            {device.macAddress ?? "---"}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                ) : (
                  <EmptyState
                    icon={Cpu}
                    title="No devices at this location"
                    description="Devices assigned to this location will appear here."
                  />
                )}
              </CardContent>
            </Card>

            {/* Danger Zone */}
            <Card className="border-destructive/30 bg-card/80 shadow-md">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-destructive">
                  <AlertTriangle className="h-4 w-4" />
                  Danger Zone
                </CardTitle>
                <CardDescription>
                  Irreversible and destructive actions for this location.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="flex items-center justify-between rounded-lg border border-destructive/20 bg-destructive/5 p-4">
                  <div>
                    <p className="font-medium text-sm">Delete this location</p>
                    <p className="text-xs text-muted-foreground">
                      {children.length > 0
                        ? "This will also delete all sub-locations. This action cannot be undone."
                        : "Once deleted, this location cannot be recovered."}
                    </p>
                  </div>
                  <DeleteLocationDialog
                    locationName={data.name}
                    hasChildren={children.length > 0}
                    onDelete={handleDelete}
                    isPending={deleteLocation.isPending}
                  />
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Sidebar */}
          <div className="space-y-4">
            {/* Metadata card */}
            <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Clock className="h-4 w-4" />
                  Metadata
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-1">
                  <p className="text-xs font-medium text-muted-foreground">Location ID</p>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs break-all">{data.id}</span>
                    <CopyButton value={data.id} label="location ID" />
                  </div>
                </div>
                <div className="space-y-1">
                  <p className="text-xs font-medium text-muted-foreground">Type</p>
                  <Badge variant="outline" className="uppercase text-xs">
                    {isAddressed ? "Addressed" : "Physical"}
                  </Badge>
                </div>
                {data.parentId && (
                  <div className="space-y-1">
                    <p className="text-xs font-medium text-muted-foreground">Parent Location</p>
                    <Link
                      to="/locations/$locationId"
                      params={{ locationId: data.parentId }}
                      className="text-sm text-primary hover:underline"
                    >
                      View parent location
                    </Link>
                  </div>
                )}
                {data.createdAt && (
                  <div className="space-y-1">
                    <p className="text-xs font-medium text-muted-foreground">Created</p>
                    <p className="text-sm">{formatRelativeTime(data.createdAt)}</p>
                    <p className="text-xs text-muted-foreground">{formatDateTime(data.createdAt)}</p>
                  </div>
                )}
                {data.updatedAt && (
                  <div className="space-y-1">
                    <p className="text-xs font-medium text-muted-foreground">Last Updated</p>
                    <p className="text-sm">{formatRelativeTime(data.updatedAt)}</p>
                    <p className="text-xs text-muted-foreground">{formatDateTime(data.updatedAt)}</p>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Activity */}
            <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Clock className="h-4 w-4" />
                  Activity
                </CardTitle>
              </CardHeader>
              <CardContent>
                <EntityActivityPanel targetType="location" targetId={locationId} />
              </CardContent>
            </Card>

            {/* Sub-locations card */}
            <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <MapPin className="h-4 w-4" />
                  Sub-locations
                  {children.length > 0 && (
                    <Badge variant="secondary" className="ml-1">{children.length}</Badge>
                  )}
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {children.length > 0 ? (
                  children.map((child) => (
                    <Link
                      key={child.id}
                      to="/locations/$locationId"
                      params={{ locationId: child.id }}
                      className="group flex items-center justify-between rounded-xl border bg-background/60 p-3 border-border/60 hover:border-border transition-colors"
                    >
                      <div className="flex items-center gap-3">
                        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-emerald-500/15 text-emerald-600 dark:text-emerald-400">
                          <MapPin className="h-4 w-4" />
                        </div>
                        <div>
                          <p className="font-medium text-sm group-hover:text-primary transition-colors">{child.name}</p>
                          {child.description && <p className="text-xs text-muted-foreground line-clamp-1">{child.description}</p>}
                        </div>
                      </div>
                      <ArrowLeft className="h-4 w-4 rotate-180 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
                    </Link>
                  ))
                ) : (
                  <div className="text-muted-foreground text-sm py-4 text-center">
                    <p>No sub-locations yet.</p>
                    <Button variant="link" size="sm" className="mt-1" asChild>
                      <Link to="/locations/new">Add a physical location</Link>
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      </PageSection>
    </PageContainer>
  )
}

// ---------------------------------------------------------------------------
// Delete dialog
// ---------------------------------------------------------------------------

function DeleteLocationDialog({
  locationName,
  hasChildren,
  onDelete,
  isPending,
}: {
  locationName: string
  hasChildren: boolean
  onDelete: () => void
  isPending: boolean
}) {
  const [open, setOpen] = useState(false)

  return (
    <>
      <Button variant="destructive" size="sm" onClick={() => setOpen(true)}>
        <Trash2 className="mr-2 h-4 w-4" />
        Delete
      </Button>
      <AlertDialog open={open} onOpenChange={setOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-destructive" />
              Delete "{locationName}"?
            </AlertDialogTitle>
            <AlertDialogDescription>
              {hasChildren
                ? "This location has sub-locations. Deleting it will also delete all sub-locations. This action cannot be undone."
                : "This action cannot be undone. The location will be permanently removed."}
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

// ---------------------------------------------------------------------------
// Info Field helper
// ---------------------------------------------------------------------------

function InfoField({
  label,
  value,
  mono,
}: {
  label: string
  value?: string | null
  mono?: boolean
}) {
  return (
    <div>
      <p className="text-muted-foreground">{label}</p>
      <p className={mono ? "font-mono text-xs" : ""}>{value ?? "---"}</p>
    </div>
  )
}
