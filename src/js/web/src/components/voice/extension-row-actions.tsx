import { useNavigate } from "@tanstack/react-router"
import { Eye, MoreHorizontal, Pencil, Trash2 } from "lucide-react"
import { useState } from "react"
import { DeleteExtensionDialog } from "@/components/voice/delete-extension-dialog"
import { EditExtensionDialog } from "@/components/voice/edit-extension-dialog"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import type { Extension } from "@/lib/api/hooks/voice"

interface ExtensionRowActionsProps {
  extension: Extension
}

export function ExtensionRowActions({ extension }: ExtensionRowActionsProps) {
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
          <DropdownMenuItem
            onClick={() =>
              navigate({
                to: "/voice/extensions/$extensionId",
                params: { extensionId: extension.id },
              })
            }
          >
            <Eye className="mr-2 h-4 w-4" />
            View details
          </DropdownMenuItem>
          <DropdownMenuItem onClick={() => setEditOpen(true)}>
            <Pencil className="mr-2 h-4 w-4" />
            Edit extension
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem
            variant="destructive"
            onClick={() => setDeleteOpen(true)}
          >
            <Trash2 className="mr-2 h-4 w-4" />
            Delete extension
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <EditExtensionDialog
        extension={extension}
        open={editOpen}
        onOpenChange={setEditOpen}
      />

      <DeleteExtensionDialog
        extensionId={extension.id}
        extensionName={extension.displayName}
        extensionNumber={extension.extensionNumber}
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
      />
    </>
  )
}
