import { useState, useEffect, useMemo } from "react"
import { CheckCircle, Loader2, Shield, UserCog, XCircle } from "lucide-react"
import { Badge } from "@/components/ui/badge"
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
import { Separator } from "@/components/ui/separator"
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
  const [isSuperuser, setIsSuperuser] = useState(user.isSuperuser ?? false)
  const updateUser = useAdminUpdateUser(user.id)

  useEffect(() => {
    if (open) {
      setName(user.name ?? "")
      setUsername("username" in user ? (user as AdminUserDetail).username ?? "" : "")
      setIsActive(user.isActive ?? true)
      setIsSuperuser(user.isSuperuser ?? false)
    }
  }, [open, user])

  const isDirty = useMemo(() => {
    const nameChanged = name !== (user.name ?? "")
    const usernameChanged = "username" in user
      ? username !== ((user as AdminUserDetail).username ?? "")
      : false
    const activeChanged = isActive !== (user.isActive ?? true)
    const superuserChanged = isSuperuser !== (user.isSuperuser ?? false)
    return nameChanged || usernameChanged || activeChanged || superuserChanged
  }, [name, username, isActive, isSuperuser, user])

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

    if (isSuperuser !== (user.isSuperuser ?? false)) {
      payload.is_superuser = isSuperuser
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
          <DialogTitle className="flex items-center gap-2">
            <UserCog className="h-5 w-5 text-muted-foreground" />
            Edit User
          </DialogTitle>
          <DialogDescription>Update user account details for {user.email}.</DialogDescription>
        </DialogHeader>

        {/* User info header */}
        <div className="flex items-center justify-between rounded-md bg-muted/50 px-3 py-2.5">
          <div className="min-w-0 space-y-0.5">
            <p className="truncate text-sm font-medium">{user.email}</p>
            <div className="flex items-center gap-2">
              {user.isVerified ? (
                <span className="inline-flex items-center gap-1 text-xs text-green-600">
                  <CheckCircle className="h-3.5 w-3.5" />
                  Verified
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 text-xs text-destructive">
                  <XCircle className="h-3.5 w-3.5" />
                  Unverified
                </span>
              )}
            </div>
          </div>
          <Badge variant={user.isSuperuser ? "default" : "secondary"}>
            <Shield className="mr-1 h-3 w-3" />
            {user.isSuperuser ? "Admin" : "Member"}
          </Badge>
        </div>

        <Separator />

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="edit-user-name">Name</Label>
            <Input id="edit-user-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Full name" />
            <p className="text-xs text-muted-foreground">User's display name</p>
          </div>
          <div className="space-y-2">
            <Label htmlFor="edit-user-username">Username</Label>
            <Input id="edit-user-username" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="Username" />
            <p className="text-xs text-muted-foreground">Login username</p>
          </div>
          <div className="flex items-center justify-between">
            <div>
              <Label htmlFor="edit-user-active">Active</Label>
              <p className="text-xs text-muted-foreground">Deactivated users cannot sign in</p>
            </div>
            <Switch id="edit-user-active" checked={isActive} onCheckedChange={setIsActive} />
          </div>
          <div className="flex items-center justify-between">
            <div>
              <Label htmlFor="edit-user-superuser">Administrator</Label>
              <p className="text-xs text-muted-foreground">Grant full administrative privileges</p>
            </div>
            <Switch id="edit-user-superuser" checked={isSuperuser} onCheckedChange={setIsSuperuser} />
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={!isDirty || updateUser.isPending}>
              {updateUser.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {updateUser.isPending ? "Saving..." : "Save changes"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
