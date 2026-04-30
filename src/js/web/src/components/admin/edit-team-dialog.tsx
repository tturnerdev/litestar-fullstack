import { useMemo, useState } from "react"
import { Loader2, Users } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Separator } from "@/components/ui/separator"
import { Switch } from "@/components/ui/switch"
import { Textarea } from "@/components/ui/textarea"
import { useAdminUpdateTeam } from "@/lib/api/hooks/admin"

const NAME_MAX = 50
const DESC_MAX = 500

interface EditTeamDialogProps {
  teamId: string
  currentName: string
  currentDescription: string | null | undefined
  currentIsActive?: boolean
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function EditTeamDialog({
  teamId,
  currentName,
  currentDescription,
  currentIsActive,
  open,
  onOpenChange,
}: EditTeamDialogProps) {
  const [name, setName] = useState(currentName)
  const [description, setDescription] = useState(currentDescription ?? "")
  const [isActive, setIsActive] = useState(currentIsActive ?? true)
  const updateTeam = useAdminUpdateTeam(teamId)

  const isDirty = useMemo(() => {
    if (name !== currentName) return true
    if (description !== (currentDescription ?? "")) return true
    if (currentIsActive !== undefined && isActive !== currentIsActive) return true
    return false
  }, [name, description, isActive, currentName, currentDescription, currentIsActive])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const payload: Record<string, unknown> = {
      name,
      description: description || null,
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
                onChange={(e) => setName(e.target.value.slice(0, NAME_MAX))}
                required
                maxLength={NAME_MAX}
              />
              <p className="text-right text-xs text-muted-foreground">
                {name.length}/{NAME_MAX}
              </p>
            </div>

            <Separator />

            {/* Description */}
            <div className="space-y-2">
              <Label htmlFor="team-description">Description</Label>
              <p className="text-xs text-muted-foreground">Brief description of the team's purpose</p>
              <Textarea
                id="team-description"
                value={description}
                onChange={(e) => setDescription(e.target.value.slice(0, DESC_MAX))}
                placeholder="Optional team description"
                rows={3}
                maxLength={DESC_MAX}
              />
              <p className="text-right text-xs text-muted-foreground">
                {description.length}/{DESC_MAX}
              </p>
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
            <Button type="submit" disabled={updateTeam.isPending || !name.trim() || !isDirty}>
              {updateTeam.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {updateTeam.isPending ? "Saving..." : "Save changes"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
