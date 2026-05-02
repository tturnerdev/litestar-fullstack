import { createFileRoute, Link, useBlocker, useRouter } from "@tanstack/react-router"
import { useEffect, useMemo, useRef, useState } from "react"
import { AlertCircle, AlertTriangle, Loader2 } from "lucide-react"
import { Alert, AlertDescription } from "@/components/ui/alert"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { Separator } from "@/components/ui/separator"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Textarea } from "@/components/ui/textarea"
import { useAuthStore } from "@/lib/auth"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { useLocation, useUpdateLocation, type LocationUpdate } from "@/lib/api/hooks/locations"
import { cn } from "@/lib/utils"

// ── Field limits ──────────────────────────────────────────────────────

const NAME_MAX = 100
const DESC_MAX = 500

export const Route = createFileRoute("/_app/locations/$locationId/edit")({
  component: EditLocationPage,
})

// ── Helpers ─────────────────────────────────────────────────────────────

function RequiredMark() {
  return <span className="text-destructive">*</span>
}

function FieldHint({ children }: { children: React.ReactNode }) {
  return <p className="text-xs text-muted-foreground">{children}</p>
}

function FieldError({ message }: { message?: string }) {
  if (!message) return null
  return <p className="text-sm text-destructive">{message}</p>
}

// ── Page component ──────────────────────────────────────────────────────

function EditLocationPage() {
  useDocumentTitle("Edit Location")
  const { locationId } = Route.useParams()
  const router = useRouter()
  const { currentTeam } = useAuthStore()
  const teamId = currentTeam?.id ?? ""

  const { data, isLoading, isError, refetch } = useLocation(teamId, locationId)
  const updateLocation = useUpdateLocation(teamId, locationId)

  // Form state
  const [name, setName] = useState("")
  const [description, setDescription] = useState("")
  const [addressLine1, setAddressLine1] = useState("")
  const [addressLine2, setAddressLine2] = useState("")
  const [city, setCity] = useState("")
  const [state, setState] = useState("")
  const [postalCode, setPostalCode] = useState("")
  const [country, setCountry] = useState("")
  const [initialized, setInitialized] = useState(false)

  // Validation state
  const [nameError, setNameError] = useState<string | undefined>()
  const [nameTouched, setNameTouched] = useState(false)

  // Reset form state when navigating to a different location
  useEffect(() => {
    setInitialized(false)
    setNameTouched(false)
    setNameError(undefined)
  }, [locationId])

  // Pre-populate form fields when data loads
  useEffect(() => {
    if (data && !initialized) {
      setName(data.name)
      setDescription(data.description ?? "")
      setAddressLine1(data.addressLine1 ?? "")
      setAddressLine2(data.addressLine2 ?? "")
      setCity(data.city ?? "")
      setState(data.state ?? "")
      setPostalCode(data.postalCode ?? "")
      setCountry(data.country ?? "")
      setInitialized(true)
    }
  }, [data, initialized])

  // Track whether the form has been modified relative to original data
  const formDirty = useMemo(() => {
    if (!data || !initialized) return false
    const base =
      name !== data.name ||
      description !== (data.description ?? "")

    if (data.locationType !== "ADDRESSED") return base

    return (
      base ||
      addressLine1 !== (data.addressLine1 ?? "") ||
      addressLine2 !== (data.addressLine2 ?? "") ||
      city !== (data.city ?? "") ||
      state !== (data.state ?? "") ||
      postalCode !== (data.postalCode ?? "") ||
      country !== (data.country ?? "")
    )
  }, [name, description, addressLine1, addressLine2, city, state, postalCode, country, data, initialized])

  // Ref to skip blocking after a successful submit
  const justSubmittedRef = useRef(false)

  // Block navigation when form is dirty
  useBlocker({
    shouldBlockFn: () => formDirty && !justSubmittedRef.current,
    withResolver: true,
  })

  // ── Validation ──────────────────────────────────────────────────────

  const validateName = (value: string) => {
    const error = value.trim() === "" ? "Name is required" : undefined
    setNameError(error)
    return error
  }

  const handleNameChange = (value: string) => {
    setName(value)
    if (nameTouched) validateName(value)
  }

  const handleNameBlur = () => {
    setNameTouched(true)
    validateName(name)
  }

  // ── Submit ──────────────────────────────────────────────────────────

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!data) return

    // Validate
    const error = validateName(name)
    setNameTouched(true)
    if (error) return

    const payload: LocationUpdate = {}

    // Only include fields that changed
    if (name !== data.name) payload.name = name
    if (description !== (data.description ?? "")) payload.description = description || null

    if (data.locationType === "ADDRESSED") {
      if (addressLine1 !== (data.addressLine1 ?? "")) payload.addressLine1 = addressLine1 || null
      if (addressLine2 !== (data.addressLine2 ?? "")) payload.addressLine2 = addressLine2 || null
      if (city !== (data.city ?? "")) payload.city = city || null
      if (state !== (data.state ?? "")) payload.state = state || null
      if (postalCode !== (data.postalCode ?? "")) payload.postalCode = postalCode || null
      if (country !== (data.country ?? "")) payload.country = country || null
    }

    // If nothing changed, just navigate back
    if (Object.keys(payload).length === 0) {
      router.navigate({ to: "/locations/$locationId", params: { locationId } })
      return
    }

    justSubmittedRef.current = true
    updateLocation.mutate(payload, {
      onSuccess: () => {
        router.navigate({ to: "/locations/$locationId", params: { locationId } })
      },
      onError: () => {
        justSubmittedRef.current = false
      },
    })
  }

  const isValid = name.trim() !== ""
  const isAddressed = data?.locationType === "ADDRESSED"

  // ── Loading state ───────────────────────────────────────────────────

  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader eyebrow="Locations" title="Edit Location" />
        <PageSection>
          <SkeletonCard />
        </PageSection>
      </PageContainer>
    )
  }

  // ── Error state ─────────────────────────────────────────────────────

  if (isError || !data) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader
          eyebrow="Locations"
          title="Edit Location"
          actions={
            <Button variant="outline" size="sm" asChild>
              <Link to="/locations">Back to locations</Link>
            </Button>
          }
        />
        <PageSection>
          <EmptyState
            icon={AlertCircle}
            title="Unable to load location"
            description="Something went wrong. Please try again."
            action={<Button variant="outline" size="sm" onClick={() => refetch()}>Try again</Button>}
          />
        </PageSection>
      </PageContainer>
    )
  }

  // ── Render ──────────────────────────────────────────────────────────

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Locations"
        title="Edit Location"
        description={`Editing ${data.name}`}
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
                  <Link to="/locations">Locations</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbLink asChild>
                  <Link to="/locations/$locationId" params={{ locationId }}>{data.name}</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbPage>Edit</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
      />

      <PageSection>
        <SectionErrorBoundary name="Edit Location Form">
        <Card className="max-w-2xl">
          <CardHeader>
            <CardTitle className="text-lg">Location Details</CardTitle>
            <CardDescription>
              Fields marked with <span className="text-destructive">*</span> are required.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-6">
              {/* Name */}
              <div className="space-y-2">
                <Label htmlFor="location-name">
                  Name <RequiredMark />
                </Label>
                <Input
                  id="location-name"
                  placeholder="e.g., Main Office"
                  value={name}
                  onChange={(e) => handleNameChange(e.target.value)}
                  onBlur={handleNameBlur}
                  aria-invalid={!!nameError}
                  maxLength={NAME_MAX}
                  required
                />
                <div className="flex items-center justify-between">
                  {nameError ? (
                    <FieldError message={nameError} />
                  ) : (
                    <FieldHint>A descriptive name for this location.</FieldHint>
                  )}
                  <p className={cn("shrink-0 text-xs", name.length >= NAME_MAX ? "text-destructive" : name.length >= NAME_MAX * 0.8 ? "text-amber-500" : "text-muted-foreground")}>
                    {name.length}/{NAME_MAX}
                  </p>
                </div>
              </div>

              {/* Description */}
              <div className="space-y-2">
                <Label htmlFor="location-description">Description</Label>
                <Textarea
                  id="location-description"
                  placeholder="Optional description of this location"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  maxLength={DESC_MAX}
                  rows={3}
                />
                <div className="flex items-center justify-between">
                  <FieldHint>Optional notes about this location.</FieldHint>
                  <p className={cn("shrink-0 text-xs", description.length >= DESC_MAX ? "text-destructive" : description.length >= DESC_MAX * 0.8 ? "text-amber-500" : "text-muted-foreground")}>
                    {description.length}/{DESC_MAX}
                  </p>
                </div>
              </div>

              {/* Address fields (ADDRESSED type only) */}
              {isAddressed && (
                <>
                  <Separator />
                  <h3 className="text-sm font-medium">Address</h3>

                  <div className="space-y-4">
                    <div className="space-y-2">
                      <Label htmlFor="location-address1">Address Line 1</Label>
                      <Input
                        id="location-address1"
                        placeholder="e.g., 123 Main Street"
                        value={addressLine1}
                        onChange={(e) => setAddressLine1(e.target.value)}
                      />
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="location-address2">Address Line 2</Label>
                      <Input
                        id="location-address2"
                        placeholder="e.g., Suite 400"
                        value={addressLine2}
                        onChange={(e) => setAddressLine2(e.target.value)}
                      />
                    </div>

                    <div className="grid gap-4 md:grid-cols-2">
                      <div className="space-y-2">
                        <Label htmlFor="location-city">City</Label>
                        <Input
                          id="location-city"
                          placeholder="e.g., San Francisco"
                          value={city}
                          onChange={(e) => setCity(e.target.value)}
                        />
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="location-state">State</Label>
                        <Input
                          id="location-state"
                          placeholder="e.g., CA"
                          value={state}
                          onChange={(e) => setState(e.target.value)}
                        />
                      </div>
                    </div>

                    <div className="grid gap-4 md:grid-cols-2">
                      <div className="space-y-2">
                        <Label htmlFor="location-postal">Postal Code</Label>
                        <Input
                          id="location-postal"
                          placeholder="e.g., 94105"
                          value={postalCode}
                          onChange={(e) => setPostalCode(e.target.value)}
                        />
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="location-country">Country</Label>
                        <Input
                          id="location-country"
                          placeholder="e.g., US"
                          value={country}
                          onChange={(e) => setCountry(e.target.value)}
                        />
                      </div>
                    </div>
                  </div>
                </>
              )}

              {/* Submit */}
              <div className="flex items-center justify-end gap-2 pt-2">
                <Button
                  type="button"
                  variant="ghost"
                  onClick={() => router.navigate({ to: "/locations/$locationId", params: { locationId } })}
                >
                  Cancel
                </Button>
                <Button type="submit" disabled={!isValid || updateLocation.isPending}>
                  {updateLocation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  Save Changes
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
        </SectionErrorBoundary>
      </PageSection>

      {/* Unsaved changes alert */}
      {formDirty && (
        <Alert variant="warning" className="fixed right-6 bottom-6 z-50 w-auto max-w-sm shadow-lg">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>You have unsaved changes on this form.</AlertDescription>
        </Alert>
      )}
    </PageContainer>
  )
}
