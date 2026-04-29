import { CircleHelp, LifeBuoy } from "lucide-react"
import { useState } from "react"
import { Button } from "@/components/ui/button"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { HelpDialog } from "./help-dialog"

export function HelpMenu() {
  const [dialogOpen, setDialogOpen] = useState(false)

  return (
    <>
      <DropdownMenu>
        <Tooltip>
          <TooltipTrigger asChild>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" className="size-8 text-muted-foreground">
                <CircleHelp className="size-5" />
                <span className="sr-only">Help</span>
              </Button>
            </DropdownMenuTrigger>
          </TooltipTrigger>
          <TooltipContent side="bottom">Help</TooltipContent>
        </Tooltip>
        <DropdownMenuContent align="end" sideOffset={8}>
          <DropdownMenuItem onSelect={() => setDialogOpen(true)}>
            <LifeBuoy className="size-4" />
            Help
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <HelpDialog open={dialogOpen} onOpenChange={setDialogOpen} />
    </>
  )
}
