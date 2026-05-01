import { toast } from "sonner"
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router"
import { useCallback, useEffect, useMemo, useState } from "react"
import {
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  Download,
  Eye,
  Home,
  Loader2,
  MoreVertical,
  Pencil,
  Plus,
  Search,
  ShieldAlert,
  Trash2,
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
import { BulkActionBar, createBulkDeleteAction, createExportAction } from "@/components/ui/bulk-action-bar"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import {
  useE911Registrations,
  useCreateE911Registration,
  useDeleteE911Registration,
  useValidateE911Registration,
  useUnregisteredPhoneNumbers,
  type E911Registration,
  type E911RegistrationCreate,
  type UnregisteredPhoneNumber,
} from "@/lib/api/hooks/e911"
import { useLocations, type Location } from "@/lib/api/hooks/locations"
import { exportToCsv, type CsvHeader } from "@/lib/csv-export"
import { useAuthStore } from "@/lib/auth"
import { useDebouncedValue } from "@/hooks/use-debounced-value"
import { useDocumentTitle } from "@/hooks/use-document-title"

export const Route = createFileRoute("/_app/e911/")({
  component: E911Page,
})

// -- Constants ----------------------------------------------------------------

const PAGE_SIZE = 20

const csvHeaders: CsvHeader<E911Registration>[] = [
  { label: "Phone Number", accessor: (r) => r.phoneNumberDisplay ?? "" },
  { label: "Phone Number Label", accessor: (r) => r.phoneNumberLabel ?? "" },
  { label: "Address Line 1", accessor: (r) => r.addressLine1 },
  { label: "Address Line 2", accessor: (r) => r.addressLine2 ?? "" },
  { label: "City", accessor: (r) => r.city },
  { label: "State", accessor: (r) => r.state },
  { label: "Postal Code", accessor: (r) => r.postalCode },
  { label: "Country", accessor: (r) => r.country },
  { label: "Validated", accessor: (r) => (r.validated ? "Yes" : "No") },
  { label: "Validated At", accessor: (r) => r.validatedAt ?? "" },
  { label: "Carrier Reg ID", accessor: (r) => r.carrierRegistrationId ?? "" },
  { label: "Location", accessor: (r) => r.locationName ?? "" },
]

// -- E911 Row -----------------------------------------------------------------

function E911Row({
  reg,
  index,
  selected,
  onToggle,
  onRowClick,
}: {
  reg: E911Registration
  index: number
  selected: boolean
  onToggle: () => void
  onRowClick: () => void
}) {
  const validateMutation = useValidateE911Registration(reg.id)
  const deleteMutation = useDeleteE911Registration()

  return (
    <TableRow
      data-state={selected ? "selected" : undefined}
      className={`cursor-pointer hover:bg-muted/50 transition-colors ${index % 2 === 1 ? "bg-muted/20" : ""}`}
      onClick={(e) => {
        const target = e.target as HTMLElement
        if (target.closest("[role=checkbox]") || target.closest("[data-slot=dropdown]") || target.closest("button") || target.closest("a")) {
          return
        }
        onRowClick()
      }}
    >
      <TableCell>
        <Checkbox
          checked={selected}
          onChange={(e) => {
            e.stopPropagation()
            onToggle()
          }}
          aria-label={`Select ${reg.phoneNumberDisplay ?? reg.id}`}
        />
      </TableCell>
      <TableCell>
        <Link
          to="/e911/$registrationId"
          params={{ registrationId: reg.id }}
          className="group flex flex-col gap-0.5"
          onClick={(e) => e.stopPropagation()}
        >
          <span className="font-medium group-hover:underline font-mono text-sm">
            {reg.phoneNumberDisplay ?? "No number"}
          </span>
          {reg.phoneNumberLabel && (
            <span className="text-xs text-muted-foreground">{reg.phoneNumberLabel}</span>
          )}
        </Link>
      </TableCell>
      <TableCell>
        <Link
          to="/e911/$registrationId"
          params={{ registrationId: reg.id }}
          className="group-hover:underline text-sm"
          onClick={(e) => e.stopPropagation()}
        >
          {reg.addressLine1}
          {reg.addressLine2 ? `, ${reg.addressLine2}` : ""}
        </Link>
      </TableCell>
      <TableCell className="hidden md:table-cell">
        <span className="text-sm">{reg.city}, {reg.state} {reg.postalCode}</span>
      </TableCell>
      <TableCell>
        {reg.validated ? (
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
      </TableCell>
      <TableCell className="hidden md:table-cell">
        {reg.carrierRegistrationId ? (
          <span className="font-mono text-xs text-muted-foreground">{reg.carrierRegistrationId}</span>
        ) : (
          <span className="text-xs text-muted-foreground">--</span>
        )}
      </TableCell>
      <TableCell className="text-right">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="sm"
              className="h-8 w-8 p-0"
              data-slot="dropdown"
              onClick={(e) => e.stopPropagation()}
            >
              <MoreVertical className="h-4 w-4" />
              <span className="sr-only">Actions for {reg.phoneNumberDisplay ?? reg.id}</span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem asChild>
              <Link to="/e911/$registrationId" params={{ registrationId: reg.id }}>
                <Eye className="mr-2 h-4 w-4" />
                View details
              </Link>
            </DropdownMenuItem>
            <DropdownMenuItem asChild>
              <Link to="/e911/$registrationId" params={{ registrationId: reg.id }} search={{ edit: true }}>
                <Pencil className="mr-2 h-4 w-4" />
                Edit
              </Link>
            </DropdownMenuItem>
            {!reg.validated && (
              <DropdownMenuItem
                disabled={validateMutation.isPending}
                onClick={() => validateMutation.mutate(undefined, {
                  onSuccess: () => toast.success("E911 registration validated"),
                  onError: (err) => toast.error("Failed to validate E911 registration", {
                    description: err instanceof Error ? err.message : undefined,
                  }),
                })}
              >
                {validateMutation.isPending ? (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                ) : (
                  <CheckCircle2 className="mr-2 h-4 w-4" />
                )}
                Validate
              </DropdownMenuItem>
            )}
            <DropdownMenuSeparator />
            <DropdownMenuItem
              variant="destructive"
              disabled={deleteMutation.isPending}
              onClick={() => deleteMutation.mutate(reg.id, {
                onSuccess: () => toast.success("E911 registration deleted"),
                onError: (err) => toast.error("Failed to delete E911 registration", {
                  description: err instanceof Error ? err.message : undefined,
                }),
              })}
            >
              <Trash2 className="mr-2 h-4 w-4" />
              Delete
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </TableCell>
    </TableRow>
  )
}

// -- Register dialog ----------------------------------------------------------

function RegisterNumberDialog({ teamId }: { teamId: string }) {
  const [open, setOpen] = useState(false)
  const createMutation = useCreateE911Registration()
  const { data: unregistered } = useUnregisteredPhoneNumbers(teamId)
  const { data: locationsData } = useLocations({ teamId, pageSize: 100 })

  const [phoneNumberId, setPhoneNumberId] = useState("")
  const [locationId, setLocationId] = useState("")
  const [addressLine1, setAddressLine1] = useState("")
  const [addressLine2, setAddressLine2] = useState("")
  const [city, setCity] = useState("")
  const [state, setState] = useState("")
  const [postalCode, setPostalCode] = useState("")
  const [country, setCountry] = useState("US")

  const locations = locationsData?.items ?? []

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

  function resetForm() {
    setPhoneNumberId("")
    setLocationId("")
    setAddressLine1("")
    setAddressLine2("")
    setCity("")
    setState("")
    setPostalCode("")
    setCountry("US")
  }

  function handleSubmit() {
    const payload: E911RegistrationCreate = {
      teamId,
      phoneNumberId: phoneNumberId || undefined,
      locationId: locationId && locationId !== "none" ? locationId : undefined,
      addressLine1,
      addressLine2: addressLine2 || undefined,
      city,
      state,
      postalCode,
      country,
    }
    createMutation.mutate(payload, {
      onSuccess: () => {
        toast.success("E911 registration created")
        setOpen(false)
        resetForm()
      },
      onError: (err) => {
        toast.error("Failed to create E911 registration", {
          description: err instanceof Error ? err.message : undefined,
        })
      },
    })
  }

  const isValid = addressLine1.trim() && city.trim() && state.trim() && postalCode.trim()

  return (
    <Dialog open={open} onOpenChange={(v) => { setOpen(v); if (!v) resetForm() }}>
      <DialogTrigger asChild>
        <Button size="sm">
          <Plus className="mr-2 h-4 w-4" /> Register Number
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Register E911 Address</DialogTitle>
          <DialogDescription>
            Associate a phone number with an E911 emergency address.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-2">
          {/* Phone number select */}
          <div className="space-y-2">
            <Label>Phone Number</Label>
            <Select value={phoneNumberId} onValueChange={setPhoneNumberId}>
              <SelectTrigger>
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
          </div>

          {/* Location select (prefill address) */}
          <div className="space-y-2">
            <Label>Copy from Location (optional)</Label>
            <Select value={locationId} onValueChange={handleLocationSelect}>
              <SelectTrigger>
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
          </div>

          {/* Address fields */}
          <div className="space-y-2">
            <Label>Address Line 1 *</Label>
            <Input value={addressLine1} onChange={(e) => setAddressLine1(e.target.value)} placeholder="123 Main St" />
          </div>
          <div className="space-y-2">
            <Label>Address Line 2</Label>
            <Input value={addressLine2} onChange={(e) => setAddressLine2(e.target.value)} placeholder="Suite 100" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-2">
              <Label>City *</Label>
              <Input value={city} onChange={(e) => setCity(e.target.value)} placeholder="Springfield" />
            </div>
            <div className="space-y-2">
              <Label>State *</Label>
              <Input value={state} onChange={(e) => setState(e.target.value)} placeholder="IL" />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-2">
              <Label>Postal Code *</Label>
              <Input value={postalCode} onChange={(e) => setPostalCode(e.target.value)} placeholder="62701" />
            </div>
            <div className="space-y-2">
              <Label>Country</Label>
              <Input value={country} onChange={(e) => setCountry(e.target.value)} placeholder="US" />
            </div>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => { setOpen(false); resetForm() }}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={!isValid || createMutation.isPending}>
            {createMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            Register
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// -- Main page ----------------------------------------------------------------

function E911Page() {
  useDocumentTitle("E911 Addresses")

  const { currentTeam } = useAuthStore()
  const navigate = useNavigate()
  const teamId = currentTeam?.id ?? ""

  const [search, setSearch] = useState("")
  const debouncedSearch = useDebouncedValue(search)
  const [page, setPage] = useState(1)

  useEffect(() => {
    setPage(1)
  }, [debouncedSearch])

  const { data, isLoading, isError, refetch } = useE911Registrations({
    page,
    pageSize: PAGE_SIZE,
    search: debouncedSearch || undefined,
    teamId: teamId || undefined,
  })

  const deleteMutation = useDeleteE911Registration()
  const { data: unregistered } = useUnregisteredPhoneNumbers(teamId)

  // Selection state
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())

  const items = data?.items ?? []

  // Selection helpers
  const allVisibleIds = useMemo(() => items.map((r) => r.id), [items])
  const allSelected = items.length > 0 && items.every((r) => selectedIds.has(r.id))
  const someSelected = items.some((r) => selectedIds.has(r.id))

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

  // Bulk actions
  const bulkActions = useMemo(
    () => [
      createBulkDeleteAction(
        async (id) => {
          await deleteMutation.mutateAsync(id)
        },
        () => {
          setSelectedIds(new Set())
          deleteMutation.reset()
        },
      ),
      createExportAction<E911Registration>(
        "e911-registrations-selected",
        csvHeaders,
        (ids) => items.filter((r) => ids.includes(r.id)),
      ),
    ],
    [items, deleteMutation],
  )

  const totalPages = Math.max(1, Math.ceil((data?.total ?? 0) / PAGE_SIZE))
  const hasData = items.length > 0
  const unregisteredCount = unregistered?.length ?? 0

  const handleRowClick = useCallback(
    (registrationId: string) => {
      navigate({ to: "/e911/$registrationId", params: { registrationId } })
    },
    [navigate],
  )

  const handleExportAll = useCallback(() => {
    if (!items.length) return
    exportToCsv("e911-registrations", csvHeaders, items)
  }, [items])

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
          <BreadcrumbPage>E911 Addresses</BreadcrumbPage>
        </BreadcrumbItem>
      </BreadcrumbList>
    </Breadcrumb>
  )

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Compliance"
        title="E911 Addresses"
        description="Manage E911 emergency address registrations for your phone numbers."
        breadcrumbs={breadcrumbs}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={handleExportAll} disabled={!hasData}>
              <Download className="mr-2 h-4 w-4" />
              Export
            </Button>
            {teamId && <RegisterNumberDialog teamId={teamId} />}
          </div>
        }
      />

      {/* Search */}
      <PageSection>
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative max-w-sm flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search by address..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
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

      {/* Unregistered numbers warning */}
      {unregisteredCount > 0 && (
        <PageSection delay={0.05}>
          <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-4">
            <div className="flex items-start gap-3">
              <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-500" />
              <div className="flex-1">
                <p className="font-medium text-sm">
                  {unregisteredCount} phone number{unregisteredCount === 1 ? "" : "s"} without E911 registration
                </p>
                <p className="mt-1 text-sm text-muted-foreground">
                  The following numbers do not have E911 addresses registered. Emergency services may not be able to locate callers using these numbers.
                </p>
                <div className="mt-3 flex flex-wrap gap-2">
                  {(unregistered ?? []).map((pn: UnregisteredPhoneNumber) => (
                    <Badge key={pn.id} variant="outline" className="border-amber-500/40 text-amber-600 dark:text-amber-400">
                      <AlertTriangle className="mr-1 h-3 w-3" />
                      {pn.number}{pn.label ? ` (${pn.label})` : ""}
                    </Badge>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </PageSection>
      )}

      {/* Registrations table */}
      <PageSection delay={0.1}>
        {isLoading ? (
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            {Array.from({ length: 3 }).map((_, i) => (
              <SkeletonCard key={i} />
            ))}
          </div>
        ) : isError ? (
          <EmptyState
            icon={AlertCircle}
            title="Unable to load E911 registrations"
            description="Something went wrong while fetching your E911 registrations. Please try again."
            action={
              <Button variant="outline" size="sm" onClick={() => refetch()}>
                Try again
              </Button>
            }
          />
        ) : !hasData && !search ? (
          <EmptyState
            icon={ShieldAlert}
            title="No E911 registrations"
            description="Register E911 addresses for your phone numbers to ensure emergency services can locate callers."
            action={
              teamId ? <RegisterNumberDialog teamId={teamId} /> : undefined
            }
          />
        ) : !hasData ? (
          <EmptyState
            icon={ShieldAlert}
            variant="no-results"
            title="No results found"
            description="No E911 registrations match your search. Try adjusting your query."
            action={
              <Button variant="outline" size="sm" onClick={() => setSearch("")}>
                Clear search
              </Button>
            }
          />
        ) : (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <p className="text-xs text-muted-foreground">
                {data?.total ?? items.length} registration{(data?.total ?? items.length) === 1 ? "" : "s"}
              </p>
              {totalPages > 1 && (
                <p className="text-xs text-muted-foreground">
                  Page {page} of {totalPages}
                </p>
              )}
            </div>

            <div className="overflow-x-auto rounded-md border border-border/60 bg-card/80">
              <Table aria-label="E911 Registrations">
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-10">
                      <Checkbox
                        checked={allSelected}
                        indeterminate={someSelected && !allSelected}
                        onChange={toggleAll}
                        aria-label="Select all registrations"
                      />
                    </TableHead>
                    <TableHead>Phone Number</TableHead>
                    <TableHead>Address</TableHead>
                    <TableHead className="hidden md:table-cell">City / State</TableHead>
                    <TableHead>Validated</TableHead>
                    <TableHead className="hidden md:table-cell">Carrier Reg ID</TableHead>
                    <TableHead className="w-16 text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {items.map((reg: E911Registration, index: number) => (
                    <E911Row
                      key={reg.id}
                      reg={reg}
                      index={index}
                      selected={selectedIds.has(reg.id)}
                      onToggle={() => toggleOne(reg.id)}
                      onRowClick={() => handleRowClick(reg.id)}
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
