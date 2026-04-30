import { useNavigate } from "@tanstack/react-router"
import { Eye, MoreHorizontal, Pencil, Trash2 } from "lucide-react"
import { useState } from "react"
import { DeleteTeamDialog } from "@/components/admin/delete-team-dialog"
import { EditTeamDialog } from "@/components/admin/edit-team-dialog"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import type { AdminTeamSummary } from "@/lib/generated/api"

interface TeamRowActionsProps {
  team: AdminTeamSummary
}

export function TeamRowActions({ team }: TeamRowActionsProps) {
  const navigate = useNavigate()
  const [editOpen, setEditOpen] = useState(false)
  const [deleteOpen, setDeleteOpen] = useState(false)

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
            <MoreHorizontal className="h-4 w-4" />
            <span className="sr-only">Open menu</span>
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuItem onClick={() => navigate({ to: "/admin/teams/$teamId", params: { teamId: team.id } })}>
            <Eye className="mr-2 h-4 w-4" />
            View details
          </DropdownMenuItem>
          <DropdownMenuItem onClick={() => setEditOpen(true)}>
            <Pencil className="mr-2 h-4 w-4" />
            Edit team
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem variant="destructive" onClick={() => setDeleteOpen(true)}>
            <Trash2 className="mr-2 h-4 w-4" />
            Delete team
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <EditTeamDialog
        teamId={team.id}
        currentName={team.name}
        currentDescription={null}
        currentIsActive={team.isActive}
        open={editOpen}
        onOpenChange={setEditOpen}
      />

      <DeleteTeamDialog teamId={team.id} teamName={team.name} open={deleteOpen} onOpenChange={setDeleteOpen} />
    </>
  )
}
