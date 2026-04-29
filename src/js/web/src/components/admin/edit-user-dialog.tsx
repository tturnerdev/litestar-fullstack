import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { useAdminUpdateUser } from "@/lib/api/hooks/admin"
import type { AdminUserSummary, AdminUserDetail } from "@/lib/generated/api"

type UserLike = AdminUserSummary | AdminUserDetail

interface EditUserDialogProps {
  user: UserLike
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function EditUserDialog({ user, open, onOpenChange }: EditUserDialogProps) {
  const [name, setName] = useState(user.name ?? "")
  const [username, setUsername] = useState("username" in user ? (user as AdminUserDetail).username ?? "" : "")
  const [isActive, setIsActive] = useState(user.isActive ?? true)
  const updateUser = useAdminUpdateUser(user.id)

  useEffect(() => {
    if (open) {
      setName(user.name ?? "")
      setUsername("username" in user ? (user as AdminUserDetail).username ?? "" : "")
      setIsActive(user.isActive ?? true)
    }
  }, [open, user])

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    const payload: Record<string, unknown> = {}

    const currentName = user.name ?? ""
    if (name !== currentName) {
      payload.name = name || null
    }

    if ("username" in user) {
      const currentUsername = (user as AdminUserDetail).username ?? ""
      if (username !== currentUsername) {
        payload.username = username || null
      }
    }

    if (isActive !== (user.isActive ?? true)) {
      payload.is_active = isActive
    }

    if (Object.keys(payload).length === 0) {
      onOpenChange(false)
      return
    }

    updateUser.mutate(payload, {
      onSuccess: () => {
        onOpenChange(false)
      },
    })
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Edit User</DialogTitle>
          <DialogDescription>Update user account details for {user.email}.</DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="edit-user-name">Name</Label>
            <Input id="edit-user-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Full name" />
          </div>
          <div className="space-y-2">
            <Label htmlFor="edit-user-username">Username</Label>
            <Input id="edit-user-username" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="Username" />
          </div>
          <div className="flex items-center justify-between">
            <Label htmlFor="edit-user-active">Active</Label>
            <Switch id="edit-user-active" checked={isActive} onCheckedChange={setIsActive} />
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={updateUser.isPending}>
              {updateUser.isPending ? "Saving..." : "Save changes"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
