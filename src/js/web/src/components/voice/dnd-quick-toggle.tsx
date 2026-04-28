import { BellOff, BellRing } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { useDndSettings, useToggleDnd } from "@/lib/api/hooks/voice"

interface DndQuickToggleProps {
  extensionId: string
  variant?: "default" | "ghost" | "outline"
  size?: "default" | "sm" | "lg" | "icon"
  showLabel?: boolean
}

export function DndQuickToggle({ extensionId, variant = "ghost", size = "sm", showLabel = false }: DndQuickToggleProps) {
  const { data, isLoading } = useDndSettings(extensionId)
  const toggleMutation = useToggleDnd(extensionId)

  if (isLoading || !data) return null

  const isEnabled = data.isEnabled

  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            variant={isEnabled ? "destructive" : variant}
            size={size}
            onClick={() => toggleMutation.mutate()}
            disabled={toggleMutation.isPending}
          >
            {isEnabled ? <BellOff className="h-4 w-4" /> : <BellRing className="h-4 w-4" />}
            {showLabel && (
              <span className="ml-2">{isEnabled ? "DND On" : "DND Off"}</span>
            )}
          </Button>
        </TooltipTrigger>
        <TooltipContent>
          {isEnabled ? "Disable Do Not Disturb" : "Enable Do Not Disturb"}
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  )
}
