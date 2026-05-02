import { createFileRoute, Link, useBlocker, useRouter } from "@tanstack/react-router"
import { AlertCircle, Loader2 } from "lucide-react"
import { useEffect, useRef, useState } from "react"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { SkeletonCard } from "@/components/ui/skeleton"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { type TagUpdate, useTag, useUpdateTag } from "@/lib/api/hooks/tags"

export const Route = createFileRoute("/_app/tags/$tagId/edit")({
  component: EditTagPage,
})

function EditTagPage() {
  useDocumentTitle("Edit Tag")
  const { tagId } = Route.useParams()
  const router = useRouter()
  const { data, isLoading, isError, refetch } = useTag(tagId)
  const updateTag = useUpdateTag(tagId)

  const [name, setName] = useState("")
  const [initialized, setInitialized] = useState(false)
  const justSubmittedRef = useRef(false)

  // Reset form state when navigating to a different tag
  // biome-ignore lint/correctness/useExhaustiveDependencies: intentional trigger dependency
  useEffect(() => {
    setInitialized(false)
  }, [tagId])

  // Pre-populate form fields when tag data loads
  useEffect(() => {
    if (data && !initialized) {
      setName(data.name)
      setInitialized(true)
    }
  }, [data, initialized])

  const isDirty = initialized && data != null && name !== data.name

  // Block navigation when form has unsaved changes
  const blocker = useBlocker({
    shouldBlockFn: () => isDirty && !justSubmittedRef.current,
    withResolver: true,
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    if (!data) return

    const payload: TagUpdate = {}

    // Only include fields that changed
    if (name.trim() !== data.name) payload.name = name.trim()

    justSubmittedRef.current = true
    updateTag.mutate(payload, {
      onSuccess: () => {
        router.navigate({ to: "/tags" })
      },
      onError: () => {
        justSubmittedRef.current = false
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
          <EmptyState
            icon={AlertCircle}
            title="Unable to load tag"
            description="Something went wrong. Please try again."
            action={
              <Button variant="outline" size="sm" onClick={() => refetch()}>
                Try again
              </Button>
            }
          />
        </PageSection>
      </PageContainer>
    )
  }

  return (
    <>
      <PageContainer className="flex-1 space-y-8">
        <PageHeader
          eyebrow="Tags"
          title="Edit Tag"
          description={`Editing "${data.name}"`}
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
                    <Link to="/tags">Tags</Link>
                  </BreadcrumbLink>
                </BreadcrumbItem>
                <BreadcrumbSeparator />
                <BreadcrumbItem>
                  <BreadcrumbPage>{data.name}</BreadcrumbPage>
                </BreadcrumbItem>
                <BreadcrumbSeparator />
                <BreadcrumbItem>
                  <BreadcrumbPage>Edit</BreadcrumbPage>
                </BreadcrumbItem>
              </BreadcrumbList>
            </Breadcrumb>
          }
        />

        <SectionErrorBoundary name="Edit Tag Form">
          <Card className="max-w-xl">
            <CardHeader>
              <CardTitle className="text-lg">Tag Details</CardTitle>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleSubmit} className="space-y-6">
                <div className="space-y-2">
                  <Label htmlFor="tag-name">Name *</Label>
                  <Input id="tag-name" placeholder="e.g., Production, Priority, VIP" value={name} onChange={(e) => setName(e.target.value)} maxLength={50} required autoFocus />
                  <p className="text-xs text-muted-foreground">The display name shown when tagging resources.</p>
                  <div className="flex items-center justify-between">
                    <p className="text-xs text-muted-foreground">
                      Current slug: <span className="font-mono">{data.slug}</span>
                    </p>
                    <span className={`text-xs ${name.length >= 50 ? "text-destructive" : name.length > 40 ? "text-amber-500" : "text-muted-foreground"}`}>{name.length}/50</span>
                  </div>
                </div>

                <div className="flex items-center justify-end gap-2 pt-2">
                  <Button type="button" variant="ghost" onClick={() => router.navigate({ to: "/tags" })}>
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
        </SectionErrorBoundary>
      </PageContainer>

      {/* -- Unsaved changes dialog ---------------------------------------- */}
      <AlertDialog open={blocker.status === "blocked"} onOpenChange={() => blocker.reset?.()}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Unsaved changes</AlertDialogTitle>
            <AlertDialogDescription>You have unsaved changes to this tag. Are you sure you want to leave? Your changes will be lost.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => blocker.reset?.()}>Stay on page</AlertDialogCancel>
            <AlertDialogAction onClick={() => blocker.proceed?.()}>Discard changes</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
