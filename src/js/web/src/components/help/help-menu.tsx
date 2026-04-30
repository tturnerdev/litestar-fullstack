import { Link } from "@tanstack/react-router"
import { CircleHelp, Keyboard, LifeBuoy, Mail, Sparkles } from "lucide-react"
import { useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuShortcut,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { HelpDialog } from "./help-dialog"

export function HelpMenu() {
  const [dialogOpen, setDialogOpen] = useState(false)
  const [defaultTab, setDefaultTab] = useState<string | undefined>(undefined)

  const openDialog = (tab?: string) => {
    setDefaultTab(tab)
    setDialogOpen(true)
  }

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
          <DropdownMenuItem onSelect={() => openDialog()}>
            <LifeBuoy className="size-4" />
            Help
            <DropdownMenuShortcut>?</DropdownMenuShortcut>
          </DropdownMenuItem>
          <DropdownMenuItem onSelect={() => openDialog("shortcuts")}>
            <Keyboard className="size-4" />
            Keyboard Shortcuts
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem onSelect={() => openDialog("resources")}>
            <Sparkles className="size-4" />
            What&apos;s New
            <Badge variant="default" className="ml-auto h-4 px-1.5 py-0 text-[10px] leading-none">
              New
            </Badge>
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem asChild>
            <Link to="/support/new">
              <Mail className="size-4" />
              Contact Support
            </Link>
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <HelpDialog open={dialogOpen} onOpenChange={setDialogOpen} defaultTab={defaultTab} />
    </>
  )
}
