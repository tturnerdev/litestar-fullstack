import { createFileRoute, Link, useBlocker, useRouter } from "@tanstack/react-router"
import { useRef, useState } from "react"
import { AlertTriangle, ChevronRight, Loader2, MapPin, Phone, Shield, Building2 } from "lucide-react"
import { useDocumentTitle } from "@/hooks/use-document-title"
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
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader } from "@/components/ui/page-layout"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { useAuth } from "@/hooks/use-auth"
import {
  useCreateE911Registration,
  useUnregisteredPhoneNumbers,
  type E911RegistrationCreate,
  type UnregisteredPhoneNumber,
} from "@/lib/api/hooks/e911"
import { toast } from "sonner"
import { useLocations, type Location } from "@/lib/api/hooks/locations"

export const Route = createFileRoute("/_app/e911/new")({
  component: NewE911RegistrationPage,
})

const tips = [
  {
    icon: Shield,
    title: "E911 compliance",
    description: "All active phone numbers should have a registered emergency address.",
  },
  {
    icon: MapPin,
    title: "Address accuracy",
    description: "Ensure the address matches the physical location of the phone user.",
  },
  {
    icon: Building2,
    title: "Copy from location",
    description: "Use an existing location to prefill address fields quickly.",
  },
  {
    icon: Phone,
    title: "Phone number",
    description: "Associate an unregistered number now, or assign one later.",
  },
]

function NewE911RegistrationPage() {
  useDocumentTitle("New E911 Registration")
  const router = useRouter()
  const { currentTeam } = useAuth()
  const teamId = currentTeam?.id ?? ""
  const createMutation = useCreateE911Registration()
  const justSubmittedRef = useRef(false)

  const { data: unregistered } = useUnregisteredPhoneNumbers(teamId)
  const { data: locationsData } = useLocations({ teamId, pageSize: 100 })
  const locations = locationsData?.items ?? []

  // Form state
  const [phoneNumberId, setPhoneNumberId] = useState("")
  const [locationId, setLocationId] = useState("")
  const [addressLine1, setAddressLine1] = useState("")
  const [addressLine2, setAddressLine2] = useState("")
  const [city, setCity] = useState("")
  const [state, setState] = useState("")
  const [postalCode, setPostalCode] = useState("")
  const [country, setCountry] = useState("US")

  // Validation state
  const [touched, setTouched] = useState<Record<string, boolean>>({})
  const [submitAttempted, setSubmitAttempted] = useState(false)

  const formDirty =
    addressLine1.trim() !== "" ||
    addressLine2.trim() !== "" ||
    city.trim() !== "" ||
    state.trim() !== "" ||
    postalCode.trim() !== "" ||
    country.trim() !== "US" ||
    phoneNumberId !== "" ||
    (locationId !== "" && locationId !== "none")

  const blocker = useBlocker({
    shouldBlockFn: () => formDirty && !justSubmittedRef.current,
    withResolver: true,
  })

  // Field helpers
  function handleBlur(field: string) {
    setTouched((prev) => ({ ...prev, [field]: true }))
  }

  function showError(field: string, value: string): boolean {
    return (touched[field] || submitAttempted) && !value.trim()
  }

  const postalCodeFormatError =
    (touched.postalCode || submitAttempted) &&
    postalCode.trim() !== "" &&
    !/^\d{5}(-\d{4})?$/.test(postalCode.trim())

  const stateFormatError =
    (touched.state || submitAttempted) &&
    state.trim() !== "" &&
    !/^[A-Za-z]{2}$/.test(state.trim())

  const isValid =
    addressLine1.trim() !== "" &&
    city.trim() !== "" &&
    state.trim() !== "" &&
    /^[A-Za-z]{2}$/.test(state.trim()) &&
    postalCode.trim() !== "" &&
    /^\d{5}(-\d{4})?$/.test(postalCode.trim())

  function handleLocationSelect(locId: string) {
    setLocationId(locId)
    if (locId && locId !== "none") {
      const loc = locations.find((l) => l.id === locId)
      if (loc) {
        setAddressLine1(loc.addressLine1 ?? "")
        setAddressLine2(loc.addressLine2 ?? "")
        setCity(loc.city ?? "")
        setState(loc.state ?? "")
        setPostalCode(loc.postalCode ?? "")
        setCountry(loc.country ?? "US")
      }
    }
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()

    if (!isValid) {
      setSubmitAttempted(true)
      return
    }

    justSubmittedRef.current = true

    const payload: E911RegistrationCreate = {
      teamId,
      phoneNumberId: phoneNumberId || undefined,
      locationId: locationId && locationId !== "none" ? locationId : undefined,
      addressLine1: addressLine1.trim(),
      addressLine2: addressLine2.trim() || undefined,
      city: city.trim(),
      state: state.trim().toUpperCase(),
      postalCode: postalCode.trim(),
      country: country.trim() || "US",
    }

    createMutation.mutate(payload, {
      onSuccess: (data) => {
        toast.success("E911 registration created successfully")
        router.navigate({ to: "/e911/$registrationId", params: { registrationId: data.id } })
      },
      onSettled: () => {
        justSubmittedRef.current = false
      },
    })
  }

  return (
    <>
      <PageContainer className="flex-1 space-y-8">
        <PageHeader
          eyebrow="Compliance"
          title="New E911 Registration"
          description="Register an emergency address for a phone number to comply with E911 requirements."
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
                    <Link to="/e911">E911 Addresses</Link>
                  </BreadcrumbLink>
                </BreadcrumbItem>
                <BreadcrumbSeparator />
                <BreadcrumbItem>
                  <BreadcrumbPage>New Registration</BreadcrumbPage>
                </BreadcrumbItem>
              </BreadcrumbList>
            </Breadcrumb>
          }
        />

        <div className="flex gap-6">
          {/* Main form */}
          <Card className="min-w-0 flex-1">
            <CardHeader>
              <CardTitle className="text-lg">Registration Details</CardTitle>
              <CardDescription>
                Fields marked with <span className="text-destructive">*</span> are required.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleSubmit} className="space-y-6">
                {/* Phone number select */}
                <div className="space-y-2">
                  <Label htmlFor="phone-number">Phone Number</Label>
                  <Select value={phoneNumberId} onValueChange={setPhoneNumberId}>
                    <SelectTrigger id="phone-number">
                      <SelectValue placeholder="Select a phone number" />
                    </SelectTrigger>
                    <SelectContent>
                      {(unregistered ?? []).map((pn: UnregisteredPhoneNumber) => (
                        <SelectItem key={pn.id} value={pn.id}>
                          {pn.number}{pn.label ? ` (${pn.label})` : ""}
                        </SelectItem>
                      ))}
                      {(!unregistered || unregistered.length === 0) && (
                        <SelectItem value="__empty" disabled>
                          No unregistered numbers available
                        </SelectItem>
                      )}
                    </SelectContent>
                  </Select>
                  <p className="text-xs text-muted-foreground">
                    Associate an unregistered phone number with this address. You can also assign one later.
                  </p>
                </div>

                {/* Location select (prefill) */}
                <div className="space-y-2">
                  <Label htmlFor="location">Copy from Location</Label>
                  <Select value={locationId} onValueChange={handleLocationSelect}>
                    <SelectTrigger id="location">
                      <SelectValue placeholder="Select a location to prefill address" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="none">-- None --</SelectItem>
                      {locations.map((loc: Location) => (
                        <SelectItem key={loc.id} value={loc.id}>
                          {loc.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <p className="text-xs text-muted-foreground">
                    Optionally prefill the address from an existing location.
                  </p>
                </div>

                {/* Address Line 1 */}
                <div className="space-y-2">
                  <Label htmlFor="address-line-1">Address Line 1 *</Label>
                  <Input
                    id="address-line-1"
                    value={addressLine1}
                    onChange={(e) => setAddressLine1(e.target.value)}
                    onBlur={() => handleBlur("addressLine1")}
                    placeholder="123 Main St"
                    aria-invalid={showError("addressLine1", addressLine1)}
                    autoFocus
                  />
                  {showError("addressLine1", addressLine1) ? (
                    <p className="text-xs text-destructive">Address line 1 is required</p>
                  ) : (
                    <p className="text-xs text-muted-foreground">
                      The street address where the phone is located.
                    </p>
                  )}
                </div>

                {/* Address Line 2 */}
                <div className="space-y-2">
                  <Label htmlFor="address-line-2">Address Line 2</Label>
                  <Input
                    id="address-line-2"
                    value={addressLine2}
                    onChange={(e) => setAddressLine2(e.target.value)}
                    placeholder="Suite 100, Floor 2, etc."
                  />
                </div>

                {/* City / State row */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="city">City *</Label>
                    <Input
                      id="city"
                      value={city}
                      onChange={(e) => setCity(e.target.value)}
                      onBlur={() => handleBlur("city")}
                      placeholder="Springfield"
                      aria-invalid={showError("city", city)}
                    />
                    {showError("city", city) && (
                      <p className="text-xs text-destructive">City is required</p>
                    )}
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="state">State *</Label>
                    <Input
                      id="state"
                      value={state}
                      onChange={(e) => setState(e.target.value)}
                      onBlur={() => handleBlur("state")}
                      placeholder="IL"
                      maxLength={2}
                      aria-invalid={showError("state", state) || !!stateFormatError}
                    />
                    {showError("state", state) ? (
                      <p className="text-xs text-destructive">State is required</p>
                    ) : stateFormatError ? (
                      <p className="text-xs text-destructive">Enter a valid 2-letter state code</p>
                    ) : (
                      <p className="text-xs text-muted-foreground">2-letter code (e.g. IL, CA)</p>
                    )}
                  </div>
                </div>

                {/* Postal Code / Country row */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="postal-code">Postal Code *</Label>
                    <Input
                      id="postal-code"
                      value={postalCode}
                      onChange={(e) => setPostalCode(e.target.value)}
                      onBlur={() => handleBlur("postalCode")}
                      placeholder="62701"
                      aria-invalid={showError("postalCode", postalCode) || !!postalCodeFormatError}
                    />
                    {showError("postalCode", postalCode) ? (
                      <p className="text-xs text-destructive">Postal code is required</p>
                    ) : postalCodeFormatError ? (
                      <p className="text-xs text-destructive">Enter a valid ZIP code (e.g. 62701 or 62701-1234)</p>
                    ) : (
                      <p className="text-xs text-muted-foreground">5-digit ZIP or ZIP+4</p>
                    )}
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="country">Country</Label>
                    <Input
                      id="country"
                      value={country}
                      onChange={(e) => setCountry(e.target.value)}
                      placeholder="US"
                    />
                    <p className="text-xs text-muted-foreground">Defaults to US</p>
                  </div>
                </div>

                {/* Actions */}
                <div className="flex items-center justify-end gap-2 pt-2">
                  <Button
                    type="button"
                    variant="ghost"
                    onClick={() => router.navigate({ to: "/e911" })}
                  >
                    Cancel
                  </Button>
                  <Button type="submit" disabled={!isValid || createMutation.isPending}>
                    {createMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                    Register Address
                  </Button>
                </div>
              </form>
            </CardContent>
          </Card>

          {/* Sidebar tips */}
          <Card className="h-fit w-72 shrink-0 border-border/40 bg-linear-to-br from-muted/30 to-muted/10">
            <CardHeader className="space-y-1 pb-3">
              <CardTitle className="text-lg">Getting Started</CardTitle>
              <CardDescription>Tips for E911 registration</CardDescription>
            </CardHeader>
            <CardContent className="space-y-1.5">
              {tips.map((tip) => (
                <div key={tip.title} className="group flex items-start gap-3 rounded-lg bg-background/60 p-3">
                  <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
                    <tip.icon className="h-4 w-4" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="font-medium text-sm">{tip.title}</p>
                    <p className="text-xs leading-relaxed text-muted-foreground">{tip.description}</p>
                  </div>
                  <ChevronRight className="mt-0.5 h-4 w-4 text-muted-foreground/30" />
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </PageContainer>

      {/* Unsaved changes dialog */}
      <AlertDialog open={blocker.status === "blocked"} onOpenChange={(open) => !open && blocker.reset?.()}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-amber-500" />
              Unsaved Changes
            </AlertDialogTitle>
            <AlertDialogDescription>
              You have unsaved changes on this form. If you leave now, your progress will be lost.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => blocker.reset?.()}>Stay on Page</AlertDialogCancel>
            <AlertDialogAction onClick={() => blocker.proceed?.()}>Discard Changes</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
