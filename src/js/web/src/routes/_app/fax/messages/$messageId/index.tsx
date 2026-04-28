import { createFileRoute, Link, useRouter } from "@tanstack/react-router"
import { ArrowLeft } from "lucide-react"
import { FaxMessageDetail } from "@/components/fax/fax-message-detail"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonCard } from "@/components/ui/skeleton"
import { useDeleteFaxMessage, useFaxMessage } from "@/lib/api/hooks/fax"

export const Route = createFileRoute("/_app/fax/messages/$messageId/")({
  component: FaxMessageDetailPage,
})

function FaxMessageDetailPage() {
  const { messageId } = Route.useParams()
  const router = useRouter()
  const { data, isLoading, isError } = useFaxMessage(messageId)
  const deleteMutation = useDeleteFaxMessage()

  function handleDelete() {
    deleteMutation.mutate(messageId, {
      onSuccess: () => {
        router.navigate({ to: "/fax/messages" })
      },
    })
  }

  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader eyebrow="Communications" title="Message Details" />
        <PageSection>
          <SkeletonCard />
        </PageSection>
        <PageSection delay={0.1}>
          <SkeletonCard className="h-[400px]" />
        </PageSection>
      </PageContainer>
    )
  }

  if (isError || !data) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader
          eyebrow="Communications"
          title="Message Details"
          actions={
            <Button variant="outline" size="sm" asChild>
              <Link to="/fax/messages">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back to messages
              </Link>
            </Button>
          }
        />
        <PageSection>
          <Card>
            <CardContent className="py-8 text-center text-muted-foreground">
              We could not load this message.
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
        title="Fax Message"
        description={`${data.direction === "inbound" ? "From" : "To"} ${data.remoteNumber}`}
        actions={
          <Button variant="outline" size="sm" asChild>
            <Link to="/fax/messages">
              <ArrowLeft className="mr-2 h-4 w-4" /> Back to messages
            </Link>
          </Button>
        }
      />

      <PageSection>
        <FaxMessageDetail
          message={data}
          onDelete={handleDelete}
          isDeleting={deleteMutation.isPending}
        />
      </PageSection>
    </PageContainer>
  )
}
