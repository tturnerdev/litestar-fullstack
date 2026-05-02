import { createFileRoute, Link, useBlocker, useRouter } from "@tanstack/react-router"
import { AlertCircle, AlertTriangle, Loader2 } from "lucide-react"
import { useEffect, useMemo, useRef, useState } from "react"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Textarea } from "@/components/ui/textarea"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { useTeam, useUpdateTeam } from "@/lib/api/hooks/teams"
import { cn } from "@/lib/utils"

// ── Field limits ──────────────────────────────────────────────────────

const NAME_MAX = 100
const DESC_MAX = 500

export const Route = createFileRoute("/_app/teams/$teamId/edit")({
  component: EditTeamPage,
})

// ── Helpers ─────────────────────────────────────────────────────────────

function RequiredMark() {
  return <span className="text-destructive">*</span>
}

function FieldHint({ children }: { children: React.ReactNode }) {
  return <p className="text-xs text-muted-foreground">{children}</p>
}

function FieldError({ message }: { message?: string }) {
  if (!message) return null
  return <p className="text-sm text-destructive">{message}</p>
}

// ── Page component ──────────────────────────────────────────────────────

function EditTeamPage() {
  useDocumentTitle("Edit Team")
  const { teamId } = Route.useParams()
  const router = useRouter()
  const { data, isLoading, isError, refetch } = useTeam(teamId)
  const updateTeam = useUpdateTeam(teamId)

  // Form state
  const [name, setName] = useState("")
  const [description, setDescription] = useState("")
  const [tagsInput, setTagsInput] = useState("")
  const [initialized, setInitialized] = useState(false)

  // Validation state
  const [nameError, setNameError] = useState<string | undefined>()
  const [nameTouched, setNameTouched] = useState(false)

  // Reset form state when navigating to a different team
  // biome-ignore lint/correctness/useExhaustiveDependencies: intentional trigger dependency
  useEffect(() => {
    setInitialized(false)
    setNameTouched(false)
    setNameError(undefined)
  }, [teamId])

  // Pre-populate form fields when data loads
  useEffect(() => {
    if (data && !initialized) {
      setName(data.name)
      setDescription(data.description ?? "")
      const tagNames = (data.tags ?? []).map((t: { name: string }) => t.name).join(", ")
      setTagsInput(tagNames)
      setInitialized(true)
    }
  }, [data, initialized])

  // Track whether the form has been modified relative to original data
  const formDirty = useMemo(() => {
    if (!data || !initialized) return false
    const originalTags = (data.tags ?? []).map((t: { name: string }) => t.name).join(", ")
    return name !== data.name || description !== (data.description ?? "") || tagsInput !== originalTags
  }, [name, description, tagsInput, data, initialized])

  // Ref to skip blocking after a successful submit
  const justSubmittedRef = useRef(false)

  // Block navigation when form is dirty
  useBlocker({
    shouldBlockFn: () => formDirty && !justSubmittedRef.current,
    withResolver: true,
  })

  // ── Validation ──────────────────────────────────────────────────────

  const validateName = (value: string) => {
    const error = value.trim() === "" ? "Name is required" : undefined
    setNameError(error)
    return error
  }

  const handleNameChange = (value: string) => {
    setName(value)
    if (nameTouched) validateName(value)
  }

  const handleNameBlur = () => {
    setNameTouched(true)
    validateName(name)
  }

  // ── Submit ──────────────────────────────────────────────────────────

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!data) return

    // Validate
    const error = validateName(name)
    setNameTouched(true)
    if (error) return

    const payload: { name?: string | null; description?: string | null; tags?: string[] | null } = {}

    // Only include fields that changed
    if (name !== data.name) payload.name = name

    if (description !== (data.description ?? "")) {
      payload.description = description || null
    }

    const originalTags = (data.tags ?? []).map((t: { name: string }) => t.name).join(", ")
    if (tagsInput !== originalTags) {
      const parsed = tagsInput
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean)
      payload.tags = parsed.length > 0 ? parsed : null
    }

    // If nothing changed, just navigate back
    if (Object.keys(payload).length === 0) {
      router.navigate({ to: "/teams/$teamId", params: { teamId } })
      return
    }

    justSubmittedRef.current = true
    updateTeam.mutate(payload, {
      onSuccess: () => {
        router.navigate({ to: "/teams/$teamId", params: { teamId } })
      },
      onError: () => {
        justSubmittedRef.current = false
      },
    })
  }

  const isValid = name.trim() !== ""

  // ── Loading state ───────────────────────────────────────────────────

  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader eyebrow="Teams" title="Edit Team" />
        <PageSection>
          <SkeletonCard />
        </PageSection>
      </PageContainer>
    )
  }

  // ── Error state ─────────────────────────────────────────────────────

  if (isError || !data) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader
          eyebrow="Teams"
          title="Edit Team"
          actions={
            <Button variant="outline" size="sm" asChild>
              <Link to="/teams">Back to teams</Link>
            </Button>
          }
        />
        <PageSection>
          <EmptyState
            icon={AlertCircle}
            title="Unable to load team"
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

  // ── Render ──────────────────────────────────────────────────────────

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Teams"
        title="Edit Team"
        description={`Editing ${data.name}`}
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
                <BreadcrumbLink asChild>
                  <Link to="/teams/$teamId" params={{ teamId }}>
                    {data.name}
                  </Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbPage>Edit</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
      />

      <PageSection>
        <SectionErrorBoundary name="Edit Team Form">
          <Card className="max-w-2xl">
            <CardHeader>
              <CardTitle className="text-lg">Team Details</CardTitle>
              <CardDescription>
                Fields marked with <span className="text-destructive">*</span> are required.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleSubmit} className="space-y-6">
                {/* Name */}
                <div className="space-y-2">
                  <Label htmlFor="team-name">
                    Name <RequiredMark />
                  </Label>
                  <Input
                    id="team-name"
                    placeholder="e.g., Engineering"
                    value={name}
                    onChange={(e) => handleNameChange(e.target.value)}
                    onBlur={handleNameBlur}
                    aria-invalid={!!nameError}
                    maxLength={NAME_MAX}
                    required
                  />
                  <div className="flex items-center justify-between">
                    {nameError ? <FieldError message={nameError} /> : <FieldHint>A descriptive name for the team.</FieldHint>}
                    <p
                      className={cn("shrink-0 text-xs", name.length >= NAME_MAX ? "text-destructive" : name.length >= NAME_MAX * 0.8 ? "text-amber-500" : "text-muted-foreground")}
                    >
                      {name.length}/{NAME_MAX}
                    </p>
                  </div>
                </div>

                {/* Description */}
                <div className="space-y-2">
                  <Label htmlFor="team-description">Description</Label>
                  <Textarea
                    id="team-description"
                    placeholder="Optional description of this team"
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    maxLength={DESC_MAX}
                    rows={3}
                  />
                  <div className="flex items-center justify-between">
                    <FieldHint>Optional notes about the purpose of this team.</FieldHint>
                    <p
                      className={cn(
                        "shrink-0 text-xs",
                        description.length >= DESC_MAX ? "text-destructive" : description.length >= DESC_MAX * 0.8 ? "text-amber-500" : "text-muted-foreground",
                      )}
                    >
                      {description.length}/{DESC_MAX}
                    </p>
                  </div>
                </div>

                {/* Tags */}
                <div className="space-y-2">
                  <Label htmlFor="team-tags">Tags</Label>
                  <Input id="team-tags" placeholder="e.g., engineering, backend, platform" value={tagsInput} onChange={(e) => setTagsInput(e.target.value)} />
                  <FieldHint>Comma-separated list of tags to categorize this team.</FieldHint>
                </div>

                {/* Submit */}
                <div className="flex items-center justify-end gap-2 pt-2">
                  <Button type="button" variant="ghost" onClick={() => router.navigate({ to: "/teams/$teamId", params: { teamId } })}>
                    Cancel
                  </Button>
                  <Button type="submit" disabled={!isValid || updateTeam.isPending}>
                    {updateTeam.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                    Save Changes
                  </Button>
                </div>
              </form>
            </CardContent>
          </Card>
        </SectionErrorBoundary>
      </PageSection>

      {/* Unsaved changes alert */}
      {formDirty && (
        <Alert variant="warning" className="fixed right-6 bottom-6 z-50 w-auto max-w-sm shadow-lg">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>You have unsaved changes on this form.</AlertDescription>
        </Alert>
      )}
    </PageContainer>
  )
}
