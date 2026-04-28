import { Link } from "@tanstack/react-router"
import { Building2, ChevronRight, MapPin, Search } from "lucide-react"
import { useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useAuthStore } from "@/lib/auth"
import { type Location, useLocations } from "@/lib/api/hooks/locations"

export function LocationList() {
  const { currentTeam } = useAuthStore()
  const [search, setSearch] = useState("")
  const [typeFilter, setTypeFilter] = useState<string>("all")

  const teamId = currentTeam?.id ?? ""

  const { data, isLoading, isError } = useLocations({
    teamId,
    search: search || undefined,
    locationType: typeFilter !== "all" ? typeFilter : undefined,
  })

  const locations = data?.items ?? []

  if (!currentTeam) {
    return (
      <Card className="border-dashed border-2">
        <CardContent className="py-16 text-center space-y-4">
          <div className="mx-auto w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center">
            <Building2 className="h-8 w-8 text-primary" />
          </div>
          <div className="space-y-2">
            <h3 className="text-lg font-semibold">Select a team first</h3>
            <p className="text-muted-foreground text-sm max-w-md mx-auto">
              Locations belong to teams. Please select a team from the sidebar to view and manage locations.
            </p>
          </div>
        </CardContent>
      </Card>
    )
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-16">
        <div className="flex flex-col items-center gap-3">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-primary border-t-transparent" />
          <p className="text-sm text-muted-foreground">Loading locations...</p>
        </div>
      </div>
    )
  }

  if (isError) {
    return (
      <Card className="border-dashed border-destructive/30 bg-destructive/5">
        <CardContent className="py-12 text-center">
          <p className="text-muted-foreground">We could not load locations yet. Try refreshing.</p>
        </CardContent>
      </Card>
    )
  }

  if (locations.length === 0 && !search && typeFilter === "all") {
    return (
      <Card className="border-dashed border-2">
        <CardContent className="py-16 text-center space-y-6">
          <div className="mx-auto w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center">
            <MapPin className="h-8 w-8 text-primary" />
          </div>
          <div className="space-y-2">
            <h3 className="text-lg font-semibold">Add your first location</h3>
            <p className="text-muted-foreground text-sm max-w-md mx-auto">
              Locations help you track where devices and extensions are physically placed. Start by creating an addressed location like an office or branch.
            </p>
          </div>
          <Button asChild size="lg">
            <Link to="/locations/new">Create location</Link>
          </Button>
        </CardContent>
      </Card>
    )
  }

  const addressedLocations = locations.filter((loc) => loc.locationType === "ADDRESSED")
  const physicalLocations = locations.filter((loc) => loc.locationType === "PHYSICAL")

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <div className="relative max-w-md flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input placeholder="Search locations..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-10" />
        </div>
        <Select value={typeFilter} onValueChange={setTypeFilter}>
          <SelectTrigger className="w-[180px]">
            <SelectValue placeholder="All types" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All types</SelectItem>
            <SelectItem value="ADDRESSED">Addressed</SelectItem>
            <SelectItem value="PHYSICAL">Physical</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {(typeFilter === "all" || typeFilter === "ADDRESSED") && addressedLocations.length > 0 && (
        <div className="space-y-3">
          <h3 className="text-sm font-medium text-muted-foreground uppercase tracking-wider">Addressed Locations</h3>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {addressedLocations.map((location) => (
              <LocationCard key={location.id} location={location} />
            ))}
          </div>
        </div>
      )}

      {(typeFilter === "all" || typeFilter === "PHYSICAL") && physicalLocations.length > 0 && (
        <div className="space-y-3">
          <h3 className="text-sm font-medium text-muted-foreground uppercase tracking-wider">Physical Locations</h3>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {physicalLocations.map((location) => (
              <LocationCard key={location.id} location={location} />
            ))}
          </div>
        </div>
      )}

      {locations.length === 0 && (search || typeFilter !== "all") && (
        <Card className="border-dashed">
          <CardContent className="py-12 text-center">
            <p className="text-muted-foreground">
              No locations match {search ? `"${search}"` : "the selected filter"}
            </p>
          </CardContent>
        </Card>
      )}

      {locations.length > 0 && (
        <p className="text-xs text-muted-foreground text-center">
          Showing {locations.length} location{locations.length === 1 ? "" : "s"}
        </p>
      )}
    </div>
  )
}

function LocationCard({ location }: { location: Location }) {
  const isAddressed = location.locationType === "ADDRESSED"
  const childCount = location.children?.length ?? 0

  const addressParts = [location.addressLine1, location.city, location.state, location.postalCode].filter(Boolean)
  const addressSummary = addressParts.join(", ")

  return (
    <Card className="group relative overflow-hidden transition-all hover:shadow-md border-border/60 hover:border-border">
      <CardHeader className="pb-3">
        <div className="flex items-start gap-3">
          <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg ${isAddressed ? "bg-blue-500/15 text-blue-600 dark:text-blue-400" : "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400"}`}>
            {isAddressed ? <Building2 className="h-5 w-5" /> : <MapPin className="h-5 w-5" />}
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <Link to="/locations/$locationId" params={{ locationId: location.id }} className="font-semibold hover:underline truncate text-foreground">
                {location.name}
              </Link>
            </div>
            <div className="flex items-center gap-2 mt-1">
              <Badge variant="outline" className="text-[10px]">
                {isAddressed ? "Addressed" : "Physical"}
              </Badge>
              {isAddressed && childCount > 0 && (
                <span className="text-xs text-muted-foreground">
                  {childCount} sub-location{childCount !== 1 ? "s" : ""}
                </span>
              )}
            </div>
          </div>
        </div>
      </CardHeader>

      <CardContent className="pt-0">
        {location.description ? (
          <p className="text-sm text-muted-foreground line-clamp-2 min-h-10">{location.description}</p>
        ) : isAddressed && addressSummary ? (
          <p className="text-sm text-muted-foreground line-clamp-2 min-h-10">{addressSummary}</p>
        ) : (
          <p className="text-sm text-muted-foreground/60 italic min-h-10">No description</p>
        )}

        <div className="mt-4 pt-3 border-t border-border/60">
          <Link
            to="/locations/$locationId"
            params={{ locationId: location.id }}
            className="flex items-center justify-between text-sm font-medium text-muted-foreground hover:text-foreground transition-colors group/link"
          >
            <span>View details</span>
            <ChevronRight className="h-4 w-4 transition-transform group-hover/link:translate-x-0.5" />
          </Link>
        </div>
      </CardContent>
    </Card>
  )
}
