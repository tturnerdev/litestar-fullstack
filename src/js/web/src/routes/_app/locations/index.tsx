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
  validateSearch: (
    search: Record<string, unknown>,
  ): {
    q?: string
    page?: number
    type?: string
    sort?: string
    order?: string
  } => ({
    q: typeof search.q === "string" && search.q ? search.q : undefined,
    page: Number(search.page) > 1 ? Number(search.page) : undefined,
    type: typeof search.type === "string" && search.type ? search.type : undefined,
    sort: typeof search.sort === "string" && search.sort ? search.sort : undefined,
    order:
      typeof search.order === "string" && (search.order === "asc" || search.order === "desc")
        ? search.order
        : undefined,
  }),
  component: LocationsPage,
})

function LocationsPage() {
  useDocumentTitle("Locations")

  const searchParams = Route.useSearch()
  const navigate = Route.useNavigate()

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
            <Button size="sm" asChild>
              <Link to="/locations/new">
                <Plus className="mr-2 h-4 w-4" /> New location
              </Link>
            </Button>
          </div>
        }
      />
      <PageSection>
        <LocationList searchParams={searchParams} navigate={navigate} />
      </PageSection>
    </PageContainer>
  )
}
