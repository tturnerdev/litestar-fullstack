import { createFileRoute, Link } from "@tanstack/react-router"
import { ArrowLeft } from "lucide-react"
import { EmailRouteEditor } from "@/components/fax/email-route-editor"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonCard } from "@/components/ui/skeleton"
import { useFaxNumber, useUpdateFaxNumber } from "@/lib/api/hooks/fax"

export const Route = createFileRoute("/_app/fax/numbers/$faxNumberId/")({
  component: FaxNumberDetailPage,
})

function FaxNumberDetailPage() {
  const { faxNumberId } = Route.useParams()
  const { data, isLoading, isError } = useFaxNumber(faxNumberId)
  const updateFaxNumber = useUpdateFaxNumber(faxNumberId)

  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader eyebrow="Communications" title="Fax Number Details" />
        <PageSection>
          <SkeletonCard />
        </PageSection>
      </PageContainer>
    )
  }

  if (isError || !data) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader
          eyebrow="Communications"
          title="Fax Number Details"
          actions={
            <Button variant="outline" size="sm" asChild>
              <Link to="/fax/numbers">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back to numbers
              </Link>
            </Button>
          }
        />
        <PageSection>
          <Card>
            <CardContent className="py-8 text-center text-muted-foreground">
              We could not load this fax number.
            </CardContent>
          </Card>
        </PageSection>
      </PageContainer>
    )
  }

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Communications"
        title={data.label ?? data.number}
        description={data.label ? data.number : undefined}
        actions={
          <Button variant="outline" size="sm" asChild>
            <Link to="/fax/numbers">
              <ArrowLeft className="mr-2 h-4 w-4" /> Back to numbers
            </Link>
          </Button>
        }
      />

      <PageSection>
        <Card>
          <CardContent className="space-y-4">
            <div className="grid gap-3 text-sm md:grid-cols-2">
              <div>
                <p className="text-muted-foreground">Number</p>
                <p className="font-mono">{data.number}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Label</p>
                <p>{data.label ?? "—"}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Status</p>
                <Badge variant={data.isActive ? "default" : "secondary"}>
                  {data.isActive ? "Active" : "Inactive"}
                </Badge>
              </div>
              <div>
                <p className="text-muted-foreground">Team</p>
                <p>{data.teamId ?? "Personal"}</p>
              </div>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button
                variant="outline"
                onClick={() => updateFaxNumber.mutate({ isActive: !data.isActive })}
                disabled={updateFaxNumber.isPending}
              >
                {data.isActive ? "Deactivate" : "Activate"}
              </Button>
            </div>
          </CardContent>
        </Card>
      </PageSection>

      <PageSection delay={0.1}>
        <EmailRouteEditor faxNumberId={faxNumberId} />
      </PageSection>
    </PageContainer>
  )
}
