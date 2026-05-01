import { createFileRoute, Link } from "@tanstack/react-router"
import { useCallback } from "react"
import { Download, Home, Plus } from "lucide-react"
import { LocationList } from "@/components/locations/location-list"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { useAuthStore } from "@/lib/auth"
import { type Location, useLocations } from "@/lib/api/hooks/locations"
import { exportToCsv, type CsvHeader } from "@/lib/csv-export"
import { useDocumentTitle } from "@/hooks/use-document-title"

export const Route = createFileRoute("/_app/locations/")({
  component: LocationsPage,
})

const csvHeaders: CsvHeader<Location>[] = [
  { label: "Name", accessor: (l) => l.name },
  { label: "Type", accessor: (l) => l.locationType },
  { label: "Address", accessor: (l) => l.addressLine1 ?? "" },
  { label: "City", accessor: (l) => l.city ?? "" },
  { label: "Country", accessor: (l) => l.country ?? "" },
  { label: "Description", accessor: (l) => l.description ?? "" },
]

function LocationsPage() {
  useDocumentTitle("Locations")
  const { currentTeam } = useAuthStore()
  const teamId = currentTeam?.id ?? ""

  const { data } = useLocations({ teamId })
  const items = data?.items ?? []

  const handleExport = useCallback(() => {
    if (!items.length) return
    exportToCsv("locations", csvHeaders, items)
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
          <BreadcrumbPage>Locations</BreadcrumbPage>
        </BreadcrumbItem>
      </BreadcrumbList>
    </Breadcrumb>
  )

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Workspace"
        title="Locations"
        description="Manage office locations and addresses."
        breadcrumbs={breadcrumbs}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={handleExport} disabled={!items.length}>
              <Download className="mr-2 h-4 w-4" />
              Export
            </Button>
            <Button size="sm" asChild>
              <Link to="/locations/new">
                <Plus className="mr-2 h-4 w-4" /> New location
              </Link>
            </Button>
          </div>
        }
      />
      <PageSection>
        <LocationList />
      </PageSection>
    </PageContainer>
  )
}
