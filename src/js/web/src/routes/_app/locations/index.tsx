import { createFileRoute, Link } from "@tanstack/react-router"
import { Home, Plus } from "lucide-react"
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
import { useDocumentTitle } from "@/hooks/use-document-title"

export const Route = createFileRoute("/_app/locations/")({
  component: LocationsPage,
})

function LocationsPage() {
  useDocumentTitle("Locations")

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
          <Button size="sm" asChild>
            <Link to="/locations/new">
              <Plus className="mr-2 h-4 w-4" /> New location
            </Link>
          </Button>
        }
      />
      <PageSection>
        <LocationList />
      </PageSection>
    </PageContainer>
  )
}
