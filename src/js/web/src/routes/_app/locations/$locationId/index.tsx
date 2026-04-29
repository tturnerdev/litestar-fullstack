import { createFileRoute, Link, useRouter } from "@tanstack/react-router"
import { useState } from "react"
import { ArrowLeft, Building2, Loader2, MapPin, Trash2 } from "lucide-react"
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Separator } from "@/components/ui/separator"
import { Textarea } from "@/components/ui/textarea"
import { useAuthStore } from "@/lib/auth"
import { useDeleteLocation, useLocation, useUpdateLocation, type Location } from "@/lib/api/hooks/locations"

export const Route = createFileRoute("/_app/locations/$locationId/")({
  component: LocationDetailPage,
})

function LocationDetailPage() {
  const { locationId } = Route.useParams()
  const router = useRouter()
  const { currentTeam } = useAuthStore()
  const teamId = currentTeam?.id ?? ""

  const { data, isLoading, isError } = useLocation(teamId, locationId)
  const updateLocation = useUpdateLocation(teamId, locationId)
  const deleteLocation = useDeleteLocation(teamId)

  const [editing, setEditing] = useState(false)
  const [editName, setEditName] = useState("")
  const [editDescription, setEditDescription] = useState("")
  const [editAddress1, setEditAddress1] = useState("")
  const [editAddress2, setEditAddress2] = useState("")
  const [editCity, setEditCity] = useState("")
  const [editState, setEditState] = useState("")
  const [editPostalCode, setEditPostalCode] = useState("")
  const [editCountry, setEditCountry] = useState("")

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
        <PageHeader eyebrow="Locations" title="Location Details" />
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
          <Card>
            <CardHeader>
              <CardTitle>Location detail</CardTitle>
            </CardHeader>
            <CardContent className="text-muted-foreground">We could not load this location.</CardContent>
          </Card>
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
          <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle>Location Information</CardTitle>
              {!editing ? (
                <Button variant="outline" size="sm" onClick={() => startEditing(data)}>
                  Edit
                </Button>
              ) : (
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
                <div className="grid gap-4 text-sm md:grid-cols-2">
                  <InfoField label="Name" value={data.name} />
                  <InfoField label="Type" value={isAddressed ? "Addressed" : "Physical"} />
                  {data.description && <InfoField label="Description" value={data.description} />}
                  {!isAddressed && data.parentId && <InfoField label="Parent ID" value={data.parentId} mono />}
                  {isAddressed && (
                    <>
                      <InfoField label="Address Line 1" value={data.addressLine1} />
                      <InfoField label="Address Line 2" value={data.addressLine2} />
                      <InfoField label="City" value={data.city} />
                      <InfoField label="State" value={data.state} />
                      <InfoField label="Postal Code" value={data.postalCode} />
                      <InfoField label="Country" value={data.country} />
                    </>
                  )}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Sidebar: children or actions */}
          <div className="space-y-4">
            {isAddressed && (
              <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <MapPin className="h-4 w-4" />
                    Sub-locations
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  {children.length > 0 ? (
                    children.map((child) => (
                      <Link
                        key={child.id}
                        to="/locations/$locationId"
                        params={{ locationId: child.id }}
                        className="flex items-center justify-between rounded-xl border bg-background/60 p-3 border-border/60 hover:border-border transition-colors"
                      >
                        <div className="flex items-center gap-3">
                          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-emerald-500/15 text-emerald-600 dark:text-emerald-400">
                            <MapPin className="h-4 w-4" />
                          </div>
                          <div>
                            <p className="font-medium text-sm">{child.name}</p>
                            {child.description && <p className="text-xs text-muted-foreground">{child.description}</p>}
                          </div>
                        </div>
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
            )}

            <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
              <CardHeader>
                <CardTitle>Actions</CardTitle>
              </CardHeader>
              <CardContent>
                <DeleteLocationDialog
                  locationName={data.name}
                  hasChildren={children.length > 0}
                  onDelete={handleDelete}
                  isPending={deleteLocation.isPending}
                />
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
  return (
    <Dialog>
      <DialogTrigger asChild>
        <Button variant="destructive" size="sm" className="w-full">
          <Trash2 className="mr-2 h-4 w-4" />
          Delete location
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Delete "{locationName}"?</DialogTitle>
          <DialogDescription>
            {hasChildren
              ? "This location has sub-locations. Deleting it will also delete all sub-locations. This action cannot be undone."
              : "This action cannot be undone. The location will be permanently removed."}
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="destructive" onClick={onDelete} disabled={isPending}>
            {isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {isPending ? "Deleting..." : "Delete"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
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
