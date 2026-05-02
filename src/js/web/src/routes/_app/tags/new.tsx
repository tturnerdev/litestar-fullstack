import { createFileRoute, Link, useBlocker, useRouter } from "@tanstack/react-router"
import { Hash, Loader2, Tags } from "lucide-react"
import { useCallback, useMemo, useRef, useState } from "react"
import { toast } from "sonner"
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
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader } from "@/components/ui/page-layout"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { Textarea } from "@/components/ui/textarea"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { type TagCreate, useCreateTag } from "@/lib/api/hooks/tags"
import { cn } from "@/lib/utils"

export const Route = createFileRoute("/_app/tags/new")({
  component: NewTagPage,
})

const NAME_MAX = 50
const DESC_MAX = 200

const TAG_COLORS = [
  { name: "Red", value: "#ef4444" },
  { name: "Orange", value: "#f97316" },
  { name: "Amber", value: "#f59e0b" },
  { name: "Green", value: "#22c55e" },
  { name: "Teal", value: "#14b8a6" },
  { name: "Blue", value: "#3b82f6" },
  { name: "Purple", value: "#a855f7" },
  { name: "Pink", value: "#ec4899" },
]

function nameToSlug(name: string): string {
  return name
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9\s-]/g, "")
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
}

function NewTagPage() {
  useDocumentTitle("New Tag")
  const router = useRouter()
  const createTag = useCreateTag()
  const justSubmittedRef = useRef(false)

  const [name, setName] = useState("")
  const [description, setDescription] = useState("")
  const [selectedColor, setSelectedColor] = useState<string | null>(null)

  const slug = useMemo(() => nameToSlug(name), [name])
  const formDirty = name.trim() !== "" || description.trim() !== "" || selectedColor !== null

  const blocker = useBlocker({
    shouldBlockFn: () => formDirty && !justSubmittedRef.current,
    withResolver: true,
  })

  const handleNameChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const val = e.target.value
    if (val.length <= NAME_MAX) setName(val)
  }, [])

  const handleDescriptionChange = useCallback((e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const val = e.target.value
    if (val.length <= DESC_MAX) setDescription(val)
  }, [])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    justSubmittedRef.current = true

    const payload: TagCreate = { name: name.trim() }

    createTag.mutate(payload, {
      onSuccess: () => {
        toast.success("Tag created successfully")
        router.navigate({ to: "/tags" })
      },
      onSettled: () => {
        justSubmittedRef.current = false
      },
    })
  }

  const isValid = name.trim() !== "" && name.length <= NAME_MAX

  return (
    <>
      <PageContainer className="flex-1 space-y-8">
        <PageHeader
          eyebrow="Tags"
          title="New Tag"
          description="Create a new tag for organizing resources."
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
                  <BreadcrumbPage>New Tag</BreadcrumbPage>
                </BreadcrumbItem>
              </BreadcrumbList>
            </Breadcrumb>
          }
        />

        <SectionErrorBoundary name="Create Tag Form">
          <Card className="max-w-xl">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-lg">
                <Tags className="h-5 w-5" />
                Tag Details
              </CardTitle>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleSubmit} className="space-y-6">
                {/* Name field */}
                <div className="space-y-2">
                  <Label htmlFor="tag-name">
                    Name <span className="text-red-500">*</span>
                  </Label>
                  <Input id="tag-name" placeholder="e.g., Production, Priority, VIP" value={name} onChange={handleNameChange} maxLength={NAME_MAX} required autoFocus />
                  <div className="flex items-center justify-between">
                    <p className="text-xs text-muted-foreground">The display name shown when tagging resources.</p>
                    <p className={cn("text-xs", name.length >= NAME_MAX ? "text-destructive" : "text-muted-foreground")}>
                      {name.length}/{NAME_MAX}
                    </p>
                  </div>
                </div>

                {/* Slug preview */}
                {name.trim() !== "" && (
                  <div className="space-y-1">
                    <div className="flex items-center gap-2 rounded-md border border-dashed px-3 py-2">
                      <Hash className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                      <span className="text-sm text-muted-foreground">Slug:</span>
                      <code className="text-sm font-mono">{slug || "—"}</code>
                    </div>
                    <p className="text-xs text-muted-foreground">URL-friendly identifier, auto-generated from name.</p>
                  </div>
                )}

                {/* Description field */}
                <div className="space-y-2">
                  <Label htmlFor="tag-description">Description</Label>
                  <Textarea
                    id="tag-description"
                    placeholder="Optional description for this tag..."
                    value={description}
                    onChange={handleDescriptionChange}
                    maxLength={DESC_MAX}
                    rows={3}
                    className="resize-none"
                  />
                  <div className="flex items-center justify-between">
                    <p className="text-xs text-muted-foreground">Optional notes about when or how to use this tag.</p>
                    <p className={cn("shrink-0 text-xs", description.length >= DESC_MAX ? "text-destructive" : "text-muted-foreground")}>
                      {description.length}/{DESC_MAX}
                    </p>
                  </div>
                </div>

                {/* Color picker */}
                <div className="space-y-2">
                  <Label>Color</Label>
                  <div className="flex flex-wrap gap-2">
                    {TAG_COLORS.map((color) => (
                      <button
                        key={color.value}
                        type="button"
                        title={color.name}
                        className={cn(
                          "h-8 w-8 rounded-full border-2 transition-all duration-150 hover:scale-110",
                          selectedColor === color.value ? "border-foreground ring-2 ring-foreground/20" : "border-transparent",
                        )}
                        style={{ backgroundColor: color.value }}
                        onClick={() => setSelectedColor((prev) => (prev === color.value ? null : color.value))}
                      />
                    ))}
                  </div>
                  <p className="text-xs text-muted-foreground">Choose a color to visually distinguish this tag. Click again to deselect.</p>
                </div>

                <div className="flex items-center justify-end gap-2 pt-2">
                  <Button type="button" variant="ghost" onClick={() => router.navigate({ to: "/tags" })}>
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
