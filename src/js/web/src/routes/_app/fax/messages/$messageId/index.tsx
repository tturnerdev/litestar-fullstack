import { createFileRoute, Link } from "@tanstack/react-router"
import { ArrowLeft, Download } from "lucide-react"
import { DirectionBadge, FaxStatusBadge } from "@/components/fax/fax-status-badge"
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
  const { data, isLoading, isError } = useFaxMessage(messageId)
  const deleteMutation = useDeleteFaxMessage()

  function formatDate(dateStr: string | null): string {
    if (!dateStr) return "—"
    return new Date(dateStr).toLocaleString()
  }

  function formatBytes(bytes: number): string {
    if (bytes === 0) return "0 B"
    const k = 1024
    const sizes = ["B", "KB", "MB", "GB"]
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return `${Number.parseFloat((bytes / k ** i).toFixed(1))} ${sizes[i]}`
  }

  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader eyebrow="Communications" title="Message Details" />
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
          <div className="flex gap-2">
            <Button variant="outline" size="sm" asChild>
              <Link to="/fax/messages">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back to messages
              </Link>
            </Button>
          </div>
        }
      />

      <PageSection>
        <Card>
          <CardContent className="space-y-4">
            <div className="grid gap-3 text-sm md:grid-cols-2">
              <div>
                <p className="text-muted-foreground">Direction</p>
                <div className="mt-1">
                  <DirectionBadge direction={data.direction} />
                </div>
              </div>
              <div>
                <p className="text-muted-foreground">Status</p>
                <div className="mt-1">
                  <FaxStatusBadge status={data.status} />
                </div>
              </div>
              <div>
                <p className="text-muted-foreground">Remote Number</p>
                <p className="font-mono">{data.remoteNumber}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Remote Name</p>
                <p>{data.remoteName ?? "—"}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Pages</p>
                <p>{data.pageCount}</p>
              </div>
              <div>
                <p className="text-muted-foreground">File Size</p>
                <p>{formatBytes(data.fileSizeBytes)}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Date</p>
                <p>{formatDate(data.receivedAt)}</p>
              </div>
              {data.errorMessage && (
                <div className="md:col-span-2">
                  <p className="text-muted-foreground">Error</p>
                  <p className="text-red-600 dark:text-red-400">{data.errorMessage}</p>
                </div>
              )}
              {data.deliveredToEmails && data.deliveredToEmails.length > 0 && (
                <div className="md:col-span-2">
                  <p className="text-muted-foreground">Delivered To</p>
                  <p>{data.deliveredToEmails.join(", ")}</p>
                </div>
              )}
            </div>
            <div className="flex flex-wrap gap-2">
              <Button variant="outline" asChild>
                <a href={`/api/fax/messages/${data.id}/download`} download>
                  <Download className="mr-2 h-4 w-4" /> Download Document
                </a>
              </Button>
              <Button
                variant="destructive"
                onClick={() => deleteMutation.mutate(data.id)}
                disabled={deleteMutation.isPending}
              >
                {deleteMutation.isPending ? "Deleting..." : "Delete Message"}
              </Button>
            </div>
          </CardContent>
        </Card>
      </PageSection>
    </PageContainer>
  )
}
