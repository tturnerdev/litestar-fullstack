import { Monitor, Moon, Sun } from "lucide-react"
import { useCallback, useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import type { ThemeMode } from "@/lib/theme-context"
import { useTheme } from "@/lib/theme-context"

const MODE_CYCLE: ThemeMode[] = ["light", "dark", "system"]

const MODE_CONFIG: Record<ThemeMode, { icon: typeof Sun; label: string; dotColor: string }> = {
  light: { icon: Sun, label: "Light", dotColor: "bg-amber-400" },
  dark: { icon: Moon, label: "Dark", dotColor: "bg-blue-400" },
  system: { icon: Monitor, label: "System", dotColor: "bg-emerald-400" },
}

export function ThemeToggle() {
  const { mode, setMode } = useTheme()
  const [isPulsing, setIsPulsing] = useState(false)

  const cycleMode = useCallback(() => {
    const currentIndex = MODE_CYCLE.indexOf(mode)
    const nextMode = MODE_CYCLE[(currentIndex + 1) % MODE_CYCLE.length]
    setMode(nextMode)
    setIsPulsing(true)
  }, [mode, setMode])

  useEffect(() => {
    if (!isPulsing) return
    const timer = setTimeout(() => setIsPulsing(false), 600)
    return () => clearTimeout(timer)
  }, [isPulsing])

  const config = MODE_CONFIG[mode]
  const nextMode = MODE_CYCLE[(MODE_CYCLE.indexOf(mode) + 1) % MODE_CYCLE.length]
  const Icon = config.icon

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          onClick={cycleMode}
          className="relative size-8 text-sidebar-foreground/70 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
          aria-label={`Current theme: ${config.label}. Switch to ${MODE_CONFIG[nextMode].label} mode`}
        >
          <Icon
            className={["size-4 transition-transform duration-300", isPulsing ? "animate-pulse" : ""].join(" ")}
            style={{ transform: isPulsing ? "rotate(180deg)" : "rotate(0deg)" }}
          />
          <span className={["absolute bottom-0.5 right-0.5 size-1.5 rounded-full ring-1 ring-sidebar transition-colors duration-300", config.dotColor].join(" ")} />
          <span className="sr-only">Toggle theme</span>
        </Button>
      </TooltipTrigger>
      <TooltipContent side="right">Switch to {MODE_CONFIG[nextMode].label.toLowerCase()} mode</TooltipContent>
    </Tooltip>
  )
}
