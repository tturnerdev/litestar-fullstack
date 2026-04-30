import { createFileRoute, Link, useRouter } from "@tanstack/react-router"
import { useEffect, useState } from "react"
import { Loader2 } from "lucide-react"
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonCard } from "@/components/ui/skeleton"
import { useTag, useUpdateTag, type TagUpdate } from "@/lib/api/hooks/tags"

export const Route = createFileRoute("/_app/tags/$tagId/edit")({
  component: EditTagPage,
})

function EditTagPage() {
  const { tagId } = Route.useParams()
  const router = useRouter()
  const { data, isLoading, isError } = useTag(tagId)
  const updateTag = useUpdateTag(tagId)

  const [name, setName] = useState("")
  const [initialized, setInitialized] = useState(false)

  // Pre-populate form fields when tag data loads
  useEffect(() => {
    if (data && !initialized) {
      setName(data.name)
      setInitialized(true)
    }
  }, [data, initialized])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    if (!data) return

    const payload: TagUpdate = {}

    // Only include fields that changed
    if (name.trim() !== data.name) payload.name = name.trim()

    updateTag.mutate(payload, {
      onSuccess: () => {
        router.navigate({ to: "/tags" })
      },
    })
  }

  const isValid = name.trim() !== ""

  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader eyebrow="Tags" title="Edit Tag" />
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
          eyebrow="Tags"
          title="Edit Tag"
          actions={
            <Button variant="outline" size="sm" asChild>
              <Link to="/tags">Back to tags</Link>
            </Button>
          }
        />
        <PageSection>
          <Card>
            <CardHeader>
              <CardTitle>Error</CardTitle>
            </CardHeader>
            <CardContent className="text-muted-foreground">We could not load this tag.</CardContent>
          </Card>
        </PageSection>
      </PageContainer>
    )
  }

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Tags"
        title="Edit Tag"
        description={`Editing "${data.name}"`}
        breadcrumbs={
          <Breadcrumb>
            <BreadcrumbList>
              <BreadcrumbItem><BreadcrumbLink asChild><Link to="/home">Home</Link></BreadcrumbLink></BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem><BreadcrumbLink asChild><Link to="/tags">Tags</Link></BreadcrumbLink></BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem><BreadcrumbPage>{data.name}</BreadcrumbPage></BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem><BreadcrumbPage>Edit</BreadcrumbPage></BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
      />

      <Card className="max-w-xl">
        <CardHeader>
          <CardTitle className="text-lg">Tag Details</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="space-y-2">
              <Label htmlFor="tag-name">Name *</Label>
              <Input
                id="tag-name"
                placeholder="e.g., Production, Priority, VIP"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                autoFocus
              />
              <p className="text-xs text-muted-foreground">
                Current slug: <span className="font-mono">{data.slug}</span>
              </p>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2">
              <Button
                type="button"
                variant="ghost"
                onClick={() => router.navigate({ to: "/tags" })}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={!isValid || updateTag.isPending}>
                {updateTag.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Save Changes
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </PageContainer>
  )
}
