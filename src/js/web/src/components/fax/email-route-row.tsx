import { Trash2 } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { TableCell, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useUpdateFaxEmailRoute } from "@/lib/api/hooks/fax"

interface EmailRouteRowProps {
  route: {
    id: string
    emailAddress: string
    isActive: boolean
    notifyOnFailure: boolean
  }
  faxNumberId: string
  onDelete: () => void
  isDeleting: boolean
}

export function EmailRouteRow({ route, faxNumberId, onDelete, isDeleting }: EmailRouteRowProps) {
  const updateRoute = useUpdateFaxEmailRoute(faxNumberId, route.id)

  return (
    <TableRow>
      <TableCell className="font-mono text-sm">{route.emailAddress}</TableCell>
      <TableCell>
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => updateRoute.mutate({ isActive: !route.isActive })}
              disabled={updateRoute.isPending}
            >
              <Badge variant={route.isActive ? "default" : "secondary"}>
                {route.isActive ? "Active" : "Inactive"}
              </Badge>
            </Button>
          </TooltipTrigger>
          <TooltipContent>
            {route.isActive ? "Click to deactivate this route" : "Click to activate this route"}
          </TooltipContent>
        </Tooltip>
      </TableCell>
      <TableCell>
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => updateRoute.mutate({ notifyOnFailure: !route.notifyOnFailure })}
              disabled={updateRoute.isPending}
            >
              <Badge variant={route.notifyOnFailure ? "default" : "outline"}>
                {route.notifyOnFailure ? "Yes" : "No"}
              </Badge>
            </Button>
          </TooltipTrigger>
          <TooltipContent>
            {route.notifyOnFailure
              ? "Click to disable failure notifications"
              : "Click to enable failure notifications"}
          </TooltipContent>
        </Tooltip>
      </TableCell>
      <TableCell className="text-right">
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="outline"
              size="sm"
              onClick={onDelete}
              disabled={isDeleting}
              className="text-destructive hover:text-destructive hover:bg-destructive/10"
            >
              <Trash2 className="h-4 w-4" />
            </Button>
          </TooltipTrigger>
          <TooltipContent>Remove this email route</TooltipContent>
        </Tooltip>
      </TableCell>
    </TableRow>
  )
}
