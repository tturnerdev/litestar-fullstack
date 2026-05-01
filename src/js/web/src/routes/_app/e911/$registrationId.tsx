import { createFileRoute, Link, useRouter } from "@tanstack/react-router"
import { useEffect, useState } from "react"
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  Fingerprint,
  Loader2,
  MapPin,
  Pencil,
  Phone,
  ShieldAlert,
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
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Skeleton } from "@/components/ui/skeleton"
import { CopyButton } from "@/components/ui/copy-button"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"
import {
  useE911Registration,
  useUpdateE911Registration,
  useDeleteE911Registration,
  useValidateE911Registration,
} from "@/lib/api/hooks/e911"

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
}: {
  address: string
  onDelete: () => void
  isPending: boolean
}) {
  const [open, setOpen] = useState(false)
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="destructive" size="sm">
          Delete Registration
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Delete E911 Registration</DialogTitle>
          <DialogDescription>
            Are you sure you want to delete the E911 registration for "{address}"? This action cannot be undone and may impact emergency services for the associated phone number.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button
            variant="destructive"
            onClick={() => {
              onDelete()
              setOpen(false)
            }}
            disabled={isPending}
          >
            {isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            Delete
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// -- Main page ----------------------------------------------------------------

function E911DetailPage() {
  const { registrationId } = Route.useParams()
  const router = useRouter()
  const { data, isLoading, isError } = useE911Registration(registrationId)
  useDocumentTitle(data ? `E911 - ${data.addressLine1}` : "E911 Details")

  const updateMutation = useUpdateE911Registration(registrationId)
  const deleteMutation = useDeleteE911Registration()
  const validateMutation = useValidateE911Registration(registrationId)

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
          <Card>
            <CardHeader>
              <CardTitle>Registration detail</CardTitle>
            </CardHeader>
            <CardContent className="text-muted-foreground">We could not load this E911 registration.</CardContent>
          </Card>
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
          </div>
        }
      />

      {/* Address Details */}
      <PageSection>
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
      </PageSection>

      {/* Linked Phone Number */}
      <PageSection delay={0.1}>
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
      </PageSection>

      {/* Linked Location */}
      <PageSection delay={0.15}>
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
      </PageSection>

      {/* Validation Status */}
      <PageSection delay={0.2}>
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
      </PageSection>

      {/* Metadata */}
      <PageSection delay={0.25}>
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
      </PageSection>

      {/* Danger Zone */}
      <PageSection delay={0.3}>
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
      </PageSection>
    </PageContainer>
  )
}
