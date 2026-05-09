import { Loader2, Users } from "lucide-react"
import { useCallback, useMemo, useRef, useState } from "react"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Separator } from "@/components/ui/separator"
import { Switch } from "@/components/ui/switch"
import { Textarea } from "@/components/ui/textarea"
import { useAdminUpdateTeam } from "@/lib/api/hooks/admin"
import type { AdminTeamUpdate } from "@/lib/generated/api"

const NAME_MAX = 100
const DESC_MAX = 500

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

interface EditTeamDialogProps {
  teamId: string
  currentName: string
  currentDescription: string | null | undefined
  currentIsActive?: boolean
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function EditTeamDialog({ teamId, currentName, currentDescription, currentIsActive, open, onOpenChange }: EditTeamDialogProps) {
  const [name, setName] = useState(currentName)
  const [description, setDescription] = useState(currentDescription ?? "")
  const [isActive, setIsActive] = useState(currentIsActive ?? true)
  const updateTeam = useAdminUpdateTeam(teamId)

  // Validation state
  const [fieldErrors, setFieldErrors] = useState<TeamFieldErrors>({})
  const touchedRef = useRef<Record<string, boolean>>({})

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
      setName(value.slice(0, NAME_MAX))
      if (touchedRef.current.name) {
        validateField("name", value)
      }
    },
    [validateField],
  )

  const handleDescriptionChange = useCallback(
    (value: string) => {
      setDescription(value.slice(0, DESC_MAX))
      if (touchedRef.current.description) {
        validateField("description", value)
      }
    },
    [validateField],
  )

  const isDirty = useMemo(() => {
    if (name !== currentName) return true
    if (description !== (currentDescription ?? "")) return true
    if (currentIsActive !== undefined && isActive !== currentIsActive) return true
    return false
  }, [name, description, isActive, currentName, currentDescription, currentIsActive])

  const hasValidationErrors = Object.values(fieldErrors).some((e) => !!e)

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    // Validate all fields before submit
    const nameErr = validateField("name", name)
    const descErr = validateField("description", description)
    for (const f of ["name", "description"] as const) {
      touchedRef.current[f] = true
    }
    if (nameErr || descErr) return

    const payload: AdminTeamUpdate = {
      name: name.trim(),
      description: description.trim() || null,
    }
    if (currentIsActive !== undefined) {
      payload.is_active = isActive
    }
    updateTeam.mutate(payload, {
      onSuccess: () => {
        onOpenChange(false)
      },
    })
  }

  const handleOpenChange = (nextOpen: boolean) => {
    if (nextOpen) {
      setName(currentName)
      setDescription(currentDescription ?? "")
      setIsActive(currentIsActive ?? true)
      setFieldErrors({})
      touchedRef.current = {}
    }
    onOpenChange(nextOpen)
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent>
        <form onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Users className="h-5 w-5 text-muted-foreground" />
              Edit Team
            </DialogTitle>
            <DialogDescription>Update the team name, description, and status.</DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            {/* Name */}
            <div className="space-y-2">
              <Label htmlFor="team-name">
                Name <span className="text-destructive">*</span>
              </Label>
              <p className="text-xs text-muted-foreground">Team display name</p>
              <Input
                id="team-name"
                value={name}
                onChange={(e) => handleNameChange(e.target.value)}
                onBlur={() => handleFieldBlur("name", name)}
                aria-invalid={!!fieldErrors.name}
                required
                maxLength={NAME_MAX}
              />
              <div className="flex items-center justify-between">
                <FieldError message={fieldErrors.name} />
                <p className="shrink-0 text-right text-xs text-muted-foreground">
                  {name.length}/{NAME_MAX}
                </p>
              </div>
            </div>

            <Separator />

            {/* Description */}
            <div className="space-y-2">
              <Label htmlFor="team-description">Description</Label>
              <p className="text-xs text-muted-foreground">Brief description of the team's purpose</p>
              <Textarea
                id="team-description"
                value={description}
                onChange={(e) => handleDescriptionChange(e.target.value)}
                onBlur={() => handleFieldBlur("description", description)}
                aria-invalid={!!fieldErrors.description}
                placeholder="Optional team description"
                rows={3}
                maxLength={DESC_MAX}
              />
              <div className="flex items-center justify-between">
                <FieldError message={fieldErrors.description} />
                <p className="shrink-0 text-right text-xs text-muted-foreground">
                  {description.length}/{DESC_MAX}
                </p>
              </div>
            </div>

            {/* Active toggle */}
            {currentIsActive !== undefined && (
              <>
                <Separator />
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label htmlFor="team-active">Active</Label>
                    <p className="text-xs text-muted-foreground">Inactive teams are hidden from members</p>
                  </div>
                  <Switch id="team-active" checked={isActive} onCheckedChange={setIsActive} />
                </div>
              </>
            )}
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={updateTeam.isPending || !name.trim() || name.trim().length < 2 || hasValidationErrors || !isDirty}>
              {updateTeam.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {updateTeam.isPending ? "Saving..." : "Save changes"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
