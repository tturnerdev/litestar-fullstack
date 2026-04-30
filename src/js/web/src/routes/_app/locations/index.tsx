import { createFileRoute, Link } from "@tanstack/react-router"
import { Plus } from "lucide-react"
import { LocationList } from "@/components/locations/location-list"
import { Button } from "@/components/ui/button"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { useDocumentTitle } from "@/hooks/use-document-title"

export const Route = createFileRoute("/_app/locations/")({
  component: LocationsPage,
})

function LocationsPage() {
  useDocumentTitle("Locations")
  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Workspace"
        title="Locations"
        description="Manage physical and addressed locations for your team."
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
