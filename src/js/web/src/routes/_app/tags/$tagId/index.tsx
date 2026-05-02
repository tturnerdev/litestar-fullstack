import { createFileRoute, Link, useBlocker, useNavigate } from "@tanstack/react-router"
import { useCallback, useEffect, useMemo, useState } from "react"
import { toast } from "sonner"
import {
  AlertCircle,
  ArrowLeft,
  Clock,
  Copy,
  Home,
  Loader2,
  MoreHorizontal,
  Pencil,
  Save,
  Tags,
  Trash2,
  X,
} from "lucide-react"
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
import { Badge } from "@/components/ui/badge"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Skeleton, SkeletonCard } from "@/components/ui/skeleton"
import { CopyButton } from "@/components/ui/copy-button"
import { EntityActivityPanel } from "@/components/shared/entity-activity-panel"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { formatRelativeTime, formatDateTime } from "@/lib/date-utils"
import { useTag, useUpdateTag, useDeleteTag } from "@/lib/api/hooks/tags"

export const Route = createFileRoute("/_app/tags/$tagId/")({
  component: TagDetailPage,
})

function TagDetailPage() {
  const { tagId } = Route.useParams()
  const navigate = useNavigate()
  const { data: tag, isLoading, isError, refetch } = useTag(tagId)
  const updateTag = useUpdateTag(tagId)
  const deleteTag = useDeleteTag()

  const [editing, setEditing] = useState(false)
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)
  const [name, setName] = useState("")

  useDocumentTitle(isLoading ? "Tag" : tag?.name ?? "Tag")

  // Sync form data when tag loads or changes
  const syncForm = useCallback(() => {
    if (tag) {
      setName(tag.name)
    }
  }, [tag])

  useEffect(() => {
    syncForm()
  }, [syncForm])

  const formDirty = useMemo(() => {
    if (!editing || !tag) return false
    return name !== tag.name
  }, [editing, tag, name])

  const blocker = useBlocker({
    shouldBlockFn: () => formDirty,
    withResolver: true,
  })

  function handleEdit() {
    syncForm()
    setEditing(true)
  }

  function handleCancel() {
    syncForm()
    setEditing(false)
  }

  function handleSave() {
    if (!tag) return
    const trimmed = name.trim()
    if (!trimmed) return

    if (trimmed === tag.name) {
      setEditing(false)
      return
    }

    updateTag.mutate(
      { name: trimmed },
      {
        onSuccess: () => {
          setEditing(false)
        },
      },
    )
  }

  function handleDelete() {
    deleteTag.mutate(tagId, {
      onSuccess: () => {
        navigate({ to: "/tags" })
      },
    })
  }

  const isValid = name.trim() !== ""

  // -- Loading state ----------------------------------------------------------

  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <div className="space-y-2">
          <Skeleton className="h-4 w-20" />
          <Skeleton className="h-8 w-64" />
        </div>
        <PageSection>
          <SkeletonCard />
        </PageSection>
      </PageContainer>
    )
  }

  // -- Error state ------------------------------------------------------------

  if (isError || !tag) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader
          eyebrow="Tags"
          title="Tag"
          actions={
            <Button variant="outline" size="sm" asChild>
              <Link to="/tags">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back to Tags
              </Link>
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

  // -- Main view --------------------------------------------------------------

  return (
    <>
      <PageContainer className="flex-1 space-y-8">
        <PageHeader
          eyebrow="Tags"
          title={tag.name}
          description={`Slug: ${tag.slug}`}
          breadcrumbs={
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
                  <BreadcrumbLink asChild>
                    <Link to="/tags">Tags</Link>
                  </BreadcrumbLink>
                </BreadcrumbItem>
                <BreadcrumbSeparator />
                <BreadcrumbItem>
                  <BreadcrumbPage>{tag.name}</BreadcrumbPage>
                </BreadcrumbItem>
              </BreadcrumbList>
            </Breadcrumb>
          }
          actions={
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" asChild>
                <Link to="/tags">
                  <ArrowLeft className="mr-2 h-4 w-4" /> Back
                </Link>
              </Button>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline" size="sm">
                    <MoreHorizontal className="h-4 w-4" />
                    <span className="sr-only">Actions</span>
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem
                    onClick={() => {
                      navigator.clipboard.writeText(tag.id)
                      toast.success("Tag ID copied to clipboard")
                    }}
                  >
                    <Copy className="mr-2 h-4 w-4" />
                    Copy Tag ID
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={handleEdit}>
                    <Pencil className="mr-2 h-4 w-4" />
                    Edit
                  </DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem
                    className="text-destructive focus:text-destructive"
                    onClick={() => setShowDeleteDialog(true)}
                  >
                    <Trash2 className="mr-2 h-4 w-4" />
                    Delete
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          }
        />

        {/* Tag Details Card */}
        <PageSection>
          <Card className="max-w-xl">
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="flex items-center gap-2">
                  <Tags className="h-4 w-4 text-muted-foreground" />
                  Tag Details
                </CardTitle>
                <div className="flex items-center gap-2">
                  {editing ? (
                    <>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={handleCancel}
                        disabled={updateTag.isPending}
                      >
                        <X className="mr-2 h-4 w-4" /> Cancel
                      </Button>
                      <Button
                        size="sm"
                        onClick={handleSave}
                        disabled={updateTag.isPending || !isValid}
                      >
                        {updateTag.isPending ? (
                          <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                        ) : (
                          <Save className="mr-2 h-4 w-4" />
                        )}
                        {updateTag.isPending ? "Saving..." : "Save changes"}
                      </Button>
                    </>
                  ) : (
                    <Button size="sm" onClick={handleEdit}>
                      <Pencil className="mr-2 h-4 w-4" /> Edit
                    </Button>
                  )}
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-6">
              {editing && formDirty && (
                <div className="flex items-center gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm text-amber-700 dark:text-amber-400">
                  <span className="inline-block h-1.5 w-1.5 rounded-full bg-amber-500" />
                  You have unsaved changes
                </div>
              )}

              {/* Name */}
              <div className="space-y-2">
                <Label htmlFor="tag-name">Name</Label>
                {editing ? (
                  <>
                    <Input
                      id="tag-name"
                      placeholder="e.g., Production, Priority, VIP"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      maxLength={50}
                      autoFocus
                    />
                    <div className="flex items-center justify-end">
                      <span
                        className={`text-xs ${name.length >= 50 ? "text-destructive" : name.length > 40 ? "text-amber-500" : "text-muted-foreground"}`}
                      >
                        {name.length}/50
                      </span>
                    </div>
                  </>
                ) : (
                  <div className="flex items-center gap-2">
                    <Badge variant="secondary" className="text-sm">
                      {tag.name}
                    </Badge>
                  </div>
                )}
              </div>

              {/* Slug */}
              <div className="space-y-2">
                <Label>Slug</Label>
                <p className="font-mono text-sm text-muted-foreground">
                  {tag.slug}
                </p>
              </div>

              {/* Tag ID */}
              <div className="space-y-2">
                <Label>Tag ID</Label>
                <div className="flex items-center gap-1">
                  <p className="font-mono text-xs text-muted-foreground">
                    {tag.id}
                  </p>
                  <CopyButton value={tag.id} label="tag ID" />
                </div>
              </div>
            </CardContent>
          </Card>
        </PageSection>

        {/* Activity Section */}
        <PageSection>
          <Card className="max-w-xl">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Clock className="h-4 w-4 text-muted-foreground" />
                Activity
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                {tag.createdAt && (
                  <div className="space-y-1">
                    <p className="text-xs font-medium text-muted-foreground">Created</p>
                    <p className="text-sm">{formatRelativeTime(tag.createdAt)}</p>
                    <p className="text-xs text-muted-foreground">{formatDateTime(tag.createdAt)}</p>
                  </div>
                )}
                {tag.updatedAt && (
                  <div className="space-y-1">
                    <p className="text-xs font-medium text-muted-foreground">Last Updated</p>
                    <p className="text-sm">{formatRelativeTime(tag.updatedAt)}</p>
                    <p className="text-xs text-muted-foreground">{formatDateTime(tag.updatedAt)}</p>
                  </div>
                )}
              </div>
              <div className="border-t pt-4">
                <EntityActivityPanel targetType="tag" targetId={tagId} />
              </div>
            </CardContent>
          </Card>
        </PageSection>
      </PageContainer>

      {/* Delete confirmation dialog */}
      <AlertDialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete tag &apos;{tag.name}&apos;?</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete this tag? This action cannot be
              undone. Any resources currently using this tag will have it
              removed.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteTag.isPending}>
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDelete}
              disabled={deleteTag.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteTag.isPending && (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              )}
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Unsaved changes dialog */}
      <AlertDialog
        open={blocker.status === "blocked"}
        onOpenChange={() => blocker.reset?.()}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Unsaved changes</AlertDialogTitle>
            <AlertDialogDescription>
              You have unsaved changes to this tag. Are you sure you want to
              leave? Your changes will be lost.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => blocker.reset?.()}>
              Stay on page
            </AlertDialogCancel>
            <AlertDialogAction onClick={() => blocker.proceed?.()}>
              Discard changes
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
