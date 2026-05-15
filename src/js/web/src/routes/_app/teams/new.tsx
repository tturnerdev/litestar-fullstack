import { createFileRoute, Link } from "@tanstack/react-router"
import { ChevronRight, Shield, ShieldAlert, Tag, UserPlus, Users } from "lucide-react"
import { CreateTeamForm } from "@/components/teams/create-team-form"
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { usePermissions } from "@/hooks/use-permissions"

export const Route = createFileRoute("/_app/teams/new")({
  component: NewTeamPage,
})

const tips = [
  {
    icon: Users,
    title: "Collaborate together",
    description: "Group members to share resources, connections, and phone numbers across the organization.",
  },
  {
    icon: Shield,
    title: "Role-based access",
    description: "Assign roles to control what each member can view, edit, or manage within the team.",
  },
  {
    icon: UserPlus,
    title: "Invite members",
    description: "Send email invitations to add colleagues. They can accept and join instantly.",
  },
  {
    icon: Tag,
    title: "Organize with tags",
    description: "Add tags during creation or later to categorize teams for filtering and discovery.",
  },
]

function NewTeamPage() {
  useDocumentTitle("New Team")
  const { canEdit } = usePermissions()

  if (!canEdit("TEAMS")) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader eyebrow="Teams" title="Create New Team" />
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
        eyebrow="Teams"
        title="Create New Team"
        description="Set up a new team to organize members and manage access."
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
                  <Link to="/teams">Teams</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbPage>New Team</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
      />

      <div className="flex gap-6">
        {/* Main form */}
        <SectionErrorBoundary name="Create Team Form">
          <Card className="min-w-0 flex-1">
            <CardHeader>
              <CardTitle className="text-lg">Team Details</CardTitle>
              <CardDescription>Provide a name and optional description for your team. You can also add tags to help organize and find it later.</CardDescription>
            </CardHeader>
            <CardContent>
              <CreateTeamForm />
            </CardContent>
          </Card>
        </SectionErrorBoundary>

        {/* Sidebar tips */}
        <Card className="h-fit w-72 shrink-0 border-border/40 bg-linear-to-br from-muted/30 to-muted/10">
          <CardHeader className="space-y-1 pb-3">
            <CardTitle className="text-lg">Getting Started</CardTitle>
            <CardDescription>Tips for your new team</CardDescription>
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
      </div>
    </PageContainer>
  )
}
