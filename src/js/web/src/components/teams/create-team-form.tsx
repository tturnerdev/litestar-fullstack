import { useQuery } from "@tanstack/react-query"
import { useBlocker, useRouter } from "@tanstack/react-router"
import { AlertCircle, AlertTriangle, Loader2, Plus, X } from "lucide-react"
import { useCallback, useRef, useState } from "react"
import { toast } from "sonner"
import { Alert, AlertDescription } from "@/components/ui/alert"
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
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Separator } from "@/components/ui/separator"
import { Textarea } from "@/components/ui/textarea"
import { createTeam, listTags } from "@/lib/generated/api"
import { cn } from "@/lib/utils"

// ── Field limits ──────────────────────────────────────────────────────

const NAME_MAX = 100
const DESC_MAX = 1000

// ── Validation ────────────────────────────────────────────────────────

interface TeamFieldErrors {
  name?: string
  description?: string
}

function validateTeamField(field: keyof TeamFieldErrors, value: string): string | undefined {
  switch (field) {
    case "name":
      if (value.trim() === "") return "Team name is required"
      if (value.trim().length < 2) return "Name must be at least 2 characters"
      return undefined
    case "description":
      if (value.trim() !== "" && value.trim().length < 3) return "Description must be at least 3 characters"
      return undefined
  }
}

function FieldError({ message }: { message?: string }) {
  if (!message) return null
  return <p className="text-sm text-destructive">{message}</p>
}

// ── Component ─────────────────────────────────────────────────────────

export function CreateTeamForm() {
  const router = useRouter()
  const [name, setName] = useState("")
  const [description, setDescription] = useState("")
  const [selectedTags, setSelectedTags] = useState<string[]>([])
  const [tagInput, setTagInput] = useState("")
  const [submitError, setSubmitError] = useState<string | undefined>()
  const [isSubmitting, setIsSubmitting] = useState(false)

  // Validation state
  const [fieldErrors, setFieldErrors] = useState<TeamFieldErrors>({})
  const touchedRef = useRef<Record<string, boolean>>({})

  const { data: existingTags = [] } = useQuery({
    queryKey: ["tags"],
    queryFn: async () => {
      const response = await listTags()
      return response.data?.items ?? []
    },
  })

  const validateField = useCallback((field: keyof TeamFieldErrors, value: string) => {
    const error = validateTeamField(field, value)
    setFieldErrors((prev) => ({ ...prev, [field]: error }))
    return error
  }, [])

  const handleFieldBlur = useCallback(
    (field: keyof TeamFieldErrors, value: string) => {
      touchedRef.current[field] = true
      validateField(field, value)
    },
    [validateField],
  )

  const handleNameChange = useCallback(
    (value: string) => {
      setName(value)
      if (touchedRef.current.name) {
        validateField("name", value)
      }
    },
    [validateField],
  )

  const handleDescriptionChange = useCallback(
    (value: string) => {
      setDescription(value)
      if (touchedRef.current.description) {
        validateField("description", value)
      }
    },
    [validateField],
  )

  const addTag = (tagName: string) => {
    const trimmed = tagName.trim().toLowerCase()
    if (trimmed && !selectedTags.includes(trimmed)) {
      setSelectedTags([...selectedTags, trimmed])
    }
    setTagInput("")
  }

  const removeTag = (tag: string) => {
    setSelectedTags(selectedTags.filter((t) => t !== tag))
  }

  const handleTagKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" || e.key === ",") {
      e.preventDefault()
      addTag(tagInput)
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    // Validate all fields before submit
    const nameErr = validateField("name", name)
    const descErr = validateField("description", description)
    // Mark all as touched so errors show
    for (const f of ["name", "description"] as const) {
      touchedRef.current[f] = true
    }
    if (nameErr || descErr) return

    setIsSubmitting(true)
    setSubmitError(undefined)

    try {
      await createTeam({
        body: {
          name: name.trim(),
          description: description.trim() || undefined,
          tags: selectedTags.length > 0 ? selectedTags : undefined,
        },
      })
      toast.success("Team created successfully")
      router.invalidate()
      router.navigate({ to: "/teams" })
    } catch (_error) {
      setSubmitError("Failed to create team. Please check your input and try again.")
      setIsSubmitting(false)
    }
  }

  // Filter suggestions based on input
  const tagSuggestions = existingTags.filter((tag) => tag.name.toLowerCase().includes(tagInput.toLowerCase()) && !selectedTags.includes(tag.name.toLowerCase()))

  const hasValidationErrors = Object.values(fieldErrors).some((e) => !!e)
  const isValid = name.trim().length >= 2 && !hasValidationErrors

  // Unsaved changes detection
  const isFormDirty = (name.trim() !== "" || description.trim() !== "" || selectedTags.length > 0) && !isSubmitting

  // Router navigation blocker
  const blocker = useBlocker({
    shouldBlockFn: () => isFormDirty,
    withResolver: true,
  })

  return (
    <>
      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Name */}
        <div className="space-y-2">
          <Label htmlFor="team-name">
            Team Name <span className="text-destructive">*</span>
          </Label>
          <Input
            id="team-name"
            placeholder="e.g., Engineering, Sales, Support"
            value={name}
            onChange={(e) => handleNameChange(e.target.value)}
            onBlur={() => handleFieldBlur("name", name)}
            aria-invalid={!!fieldErrors.name}
            maxLength={NAME_MAX}
            required
            autoFocus
          />
          <div className="flex items-center justify-between">
            {fieldErrors.name ? <FieldError message={fieldErrors.name} /> : <p className="text-xs text-muted-foreground">A unique, descriptive name for your team.</p>}
            <p className={cn("shrink-0 text-xs", name.length >= NAME_MAX ? "text-destructive" : name.length >= NAME_MAX * 0.8 ? "text-amber-500" : "text-muted-foreground")}>
              {name.length}/{NAME_MAX}
            </p>
          </div>
        </div>

        {/* Description */}
        <div className="space-y-2">
          <Label htmlFor="team-description">Description</Label>
          <Textarea
            id="team-description"
            placeholder="Briefly describe this team's purpose and responsibilities..."
            className="resize-none"
            rows={3}
            value={description}
            onChange={(e) => handleDescriptionChange(e.target.value)}
            onBlur={() => handleFieldBlur("description", description)}
            aria-invalid={!!fieldErrors.description}
            maxLength={DESC_MAX}
          />
          <div className="flex items-center justify-between">
            {fieldErrors.description ? (
              <FieldError message={fieldErrors.description} />
            ) : (
              <p className="text-xs text-muted-foreground">Help others understand what this team does. This is optional.</p>
            )}
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

        {/* Tags Section */}
        <div className="space-y-4 rounded-lg border border-border/60 bg-muted/20 p-4">
          <div className="space-y-2">
            <Label>Tags</Label>
            <p className="text-xs text-muted-foreground">Categorize your team for easier filtering and discovery. Type a tag name and press Enter to add it.</p>
            <div className="space-y-3">
              <div className="relative">
                <Input
                  placeholder="Type a tag and press Enter..."
                  value={tagInput}
                  onChange={(e) => setTagInput(e.target.value)}
                  onKeyDown={handleTagKeyDown}
                  onBlur={() => tagInput && addTag(tagInput)}
                  className="bg-background pr-10"
                />
                {tagInput && (
                  <Button type="button" variant="ghost" size="sm" className="absolute top-1/2 right-1 h-7 w-7 -translate-y-1/2 p-0" onClick={() => addTag(tagInput)}>
                    <Plus className="h-4 w-4" />
                    <span className="sr-only">Add tag</span>
                  </Button>
                )}
                {tagInput && tagSuggestions.length > 0 && (
                  <div className="absolute z-10 mt-1 w-full rounded-md border border-border bg-popover p-1 shadow-lg">
                    {tagSuggestions.slice(0, 5).map((tag) => (
                      <button
                        key={tag.id}
                        type="button"
                        className="flex w-full items-center gap-2 rounded px-3 py-2 text-left text-sm hover:bg-accent"
                        onClick={() => addTag(tag.name)}
                      >
                        <span className="text-muted-foreground">#</span>
                        {tag.name}
                      </button>
                    ))}
                  </div>
                )}
              </div>
              {selectedTags.length > 0 && (
                <div className="flex flex-wrap gap-2">
                  {selectedTags.map((tag) => (
                    <Badge key={tag} variant="secondary" className="gap-1.5 py-1 pr-1 pl-2.5">
                      <span className="text-muted-foreground">#</span>
                      {tag}
                      <button type="button" onClick={() => removeTag(tag)} className="ml-0.5 rounded-full p-0.5 transition-colors hover:bg-muted-foreground/20">
                        <X className="h-3 w-3" />
                        <span className="sr-only">Remove {tag}</span>
                      </button>
                    </Badge>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>

        {submitError && (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>{submitError}</AlertDescription>
          </Alert>
        )}

        <Separator />

        {/* Submit */}
        <div className="flex items-center justify-end gap-2 pt-2">
          <Button type="button" variant="ghost" disabled={isSubmitting} onClick={() => router.navigate({ to: "/teams" })}>
            Cancel
          </Button>
          <Button type="submit" disabled={!isValid || isSubmitting}>
            {isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {isSubmitting ? "Creating..." : "Create Team"}
          </Button>
        </div>
      </form>

      {/* Unsaved changes dialog */}
      <AlertDialog open={blocker.status === "blocked"} onOpenChange={(open) => !open && blocker.reset?.()}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-amber-500" />
              Unsaved Changes
            </AlertDialogTitle>
            <AlertDialogDescription>You have unsaved changes on this form. If you leave now, your progress will be lost.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => blocker.reset?.()}>Stay on Page</AlertDialogCancel>
            <AlertDialogAction onClick={() => blocker.proceed?.()}>Discard Changes</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
