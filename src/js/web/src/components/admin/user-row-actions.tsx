import { Link } from "@tanstack/react-router"
import { MoreHorizontal, Pencil, Shield, UserCheck, UserX, Trash2, Eye } from "lucide-react"
import { useState } from "react"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { DeleteUserDialog } from "@/components/admin/delete-user-dialog"
import { EditUserDialog } from "@/components/admin/edit-user-dialog"
import { ManageRolesDialog } from "@/components/admin/manage-roles-dialog"
import { ToggleUserStatusDialog } from "@/components/admin/toggle-user-status-dialog"
import type { AdminUserSummary } from "@/lib/generated/api"

interface UserRowActionsProps {
  user: AdminUserSummary
}

export function UserRowActions({ user }: UserRowActionsProps) {
  const [editOpen, setEditOpen] = useState(false)
  const [rolesOpen, setRolesOpen] = useState(false)
  const [statusOpen, setStatusOpen] = useState(false)
  const [deleteOpen, setDeleteOpen] = useState(false)

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
            <span className="sr-only">Open menu</span>
            <MoreHorizontal className="h-4 w-4" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuLabel>Actions</DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuItem asChild>
            <Link to="/admin/users/$userId" params={{ userId: user.id }}>
              <Eye className="mr-2 h-4 w-4" />
              View details
            </Link>
          </DropdownMenuItem>
          <DropdownMenuItem onSelect={() => setEditOpen(true)}>
            <Pencil className="mr-2 h-4 w-4" />
            Edit user
          </DropdownMenuItem>
          <DropdownMenuItem onSelect={() => setRolesOpen(true)}>
            <Shield className="mr-2 h-4 w-4" />
            Manage roles
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem onSelect={() => setStatusOpen(true)}>
            {user.isActive ? (
              <>
                <UserX className="mr-2 h-4 w-4" />
                Deactivate
              </>
            ) : (
              <>
                <UserCheck className="mr-2 h-4 w-4" />
                Activate
              </>
            )}
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem variant="destructive" onSelect={() => setDeleteOpen(true)}>
            <Trash2 className="mr-2 h-4 w-4" />
            Delete user
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <EditUserDialog user={user} open={editOpen} onOpenChange={setEditOpen} />
      <ManageRolesDialog userId={user.id} userEmail={user.email} open={rolesOpen} onOpenChange={setRolesOpen} />
      <ToggleUserStatusDialog userId={user.id} userEmail={user.email} isActive={user.isActive ?? true} open={statusOpen} onOpenChange={setStatusOpen} />
      <DeleteUserDialog userId={user.id} userEmail={user.email} open={deleteOpen} onOpenChange={setDeleteOpen} />
    </>
  )
}
