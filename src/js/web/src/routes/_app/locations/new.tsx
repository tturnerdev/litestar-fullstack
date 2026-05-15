import { createFileRoute, Link } from "@tanstack/react-router"
import { Building2, ChevronRight, MapPin, Navigation, ShieldAlert, Tag } from "lucide-react"
import { CreateLocationForm } from "@/components/locations/location-form"
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { usePermissions } from "@/hooks/use-permissions"

export const Route = createFileRoute("/_app/locations/new")({
  component: NewLocationPage,
})

const tips = [
  {
    icon: Building2,
    title: "Addressed locations",
    description: "Top-level locations with a mailing address",
  },
  {
    icon: MapPin,
    title: "Physical locations",
    description: "Specific rooms or areas within a location",
  },
  {
    icon: Navigation,
    title: "Assign to entities",
    description: "Link devices and extensions to locations",
  },
  {
    icon: Tag,
    title: "Team-scoped",
    description: "Locations belong to the active team",
  },
]

function NewLocationPage() {
  useDocumentTitle("Add Location")
  const { canEdit } = usePermissions()

  if (!canEdit("LOCATIONS")) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader eyebrow="Locations" title="Add Location" />
        <PageSection>
          <div className="flex flex-col items-center justify-center py-16 text-center">
            <ShieldAlert className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-semibold">Permission Denied</h3>
            <p className="text-sm text-muted-foreground mt-1">You don't have permission to perform this action. Contact your team administrator.</p>
          </div>
        </PageSection>
      </PageContainer>
    )
  }

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Locations"
        title="Add Location"
        description="Add a new location to organize where your devices and extensions are placed."
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
                <BreadcrumbPage>Add Location</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
      />

      <div className="flex gap-6">
        {/* Main form */}
        <SectionErrorBoundary name="Location Form">
          <Card className="min-w-0 flex-1">
            <CardHeader>
              <CardTitle className="text-lg">Location Details</CardTitle>
            </CardHeader>
            <CardContent>
              <CreateLocationForm />
            </CardContent>
          </Card>
        </SectionErrorBoundary>

        {/* Sidebar tips */}
        <SectionErrorBoundary name="Getting Started Tips">
          <Card className="h-fit w-72 shrink-0 border-border/40 bg-linear-to-br from-muted/30 to-muted/10">
            <CardHeader className="space-y-1 pb-3">
              <CardTitle className="text-lg">Getting Started</CardTitle>
              <CardDescription>Tips for adding locations</CardDescription>
            </CardHeader>
            <CardContent className="space-y-1.5">
              {tips.map((tip) => (
                <div key={tip.title} className="group flex items-center gap-3 rounded-lg bg-background/60 p-3">
                  <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
                    <tip.icon className="h-4 w-4" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="font-medium text-sm">{tip.title}</p>
                    <p className="text-xs text-muted-foreground">{tip.description}</p>
                  </div>
                  <ChevronRight className="h-4 w-4 text-muted-foreground/30" />
                </div>
              ))}
            </CardContent>
          </Card>
        </SectionErrorBoundary>
      </div>
    </PageContainer>
  )
}
