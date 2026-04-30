import { createFileRoute, Link, useRouter } from "@tanstack/react-router"
import { useState } from "react"
import { Loader2 } from "lucide-react"
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader } from "@/components/ui/page-layout"
import { useCreateTag, type TagCreate } from "@/lib/api/hooks/tags"

export const Route = createFileRoute("/_app/tags/new")({
  component: NewTagPage,
})

function NewTagPage() {
  const router = useRouter()
  const createTag = useCreateTag()

  const [name, setName] = useState("")

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    const payload: TagCreate = { name: name.trim() }

    createTag.mutate(payload, {
      onSuccess: () => {
        router.navigate({ to: "/tags" })
      },
    })
  }

  const isValid = name.trim() !== ""

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Tags"
        title="New Tag"
        description="Create a new tag for organizing resources."
        breadcrumbs={
          <Breadcrumb>
            <BreadcrumbList>
              <BreadcrumbItem><BreadcrumbLink asChild><Link to="/home">Home</Link></BreadcrumbLink></BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem><BreadcrumbLink asChild><Link to="/tags">Tags</Link></BreadcrumbLink></BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem><BreadcrumbPage>New Tag</BreadcrumbPage></BreadcrumbItem>
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
                A URL-friendly slug will be generated automatically from the name.
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
              <Button type="submit" disabled={!isValid || createTag.isPending}>
                {createTag.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Create Tag
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </PageContainer>
  )
}
