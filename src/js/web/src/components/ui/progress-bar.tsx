import { useRouterState } from "@tanstack/react-router"
import { useEffect, useRef, useState } from "react"
import { cn } from "@/lib/utils"

/**
 * A thin animated progress bar at the top of the viewport,
 * shown during route transitions (similar to NProgress/YouTube).
 *
 * Uses CSS transitions for smooth animation and the app's
 * primary color via CSS custom properties.
 */

type Phase = "idle" | "loading" | "completing" | "done"

export function RouteProgressBar() {
  const isLoading = useRouterState({
    select: (state) => state.isLoading,
  })

  const [phase, setPhase] = useState<Phase>("idle")
  const [progress, setProgress] = useState(0)
  const tickRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  // Clean up any running timers
  const clearTimers = () => {
    if (tickRef.current) {
      clearInterval(tickRef.current)
      tickRef.current = null
    }
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current)
      timeoutRef.current = null
    }
  }

  // biome-ignore lint/correctness/useExhaustiveDependencies: clearTimers is a stable ref-based helper; phase is read inside but only isLoading should trigger
  useEffect(() => {
    if (isLoading) {
      // Start loading: reset and begin trickle
      clearTimers()
      setProgress(0)
      setPhase("loading")

      // Small delay so the bar appears at 0 first, then transitions forward
      requestAnimationFrame(() => {
        setProgress(15)
      })

      // Trickle: gradually increase but never reach 100
      tickRef.current = setInterval(() => {
        setProgress((prev) => {
          if (prev >= 90) return prev
          // Slow down as we approach 90
          const increment = prev < 30 ? 8 : prev < 60 ? 4 : prev < 80 ? 2 : 0.5
          return Math.min(prev + increment, 90)
        })
      }, 300)
    } else if (phase === "loading") {
      // Loading finished: snap to 100 then fade out
      clearTimers()
      setProgress(100)
      setPhase("completing")

      timeoutRef.current = setTimeout(() => {
        setPhase("done")
        // After fade-out transition, reset to idle
        timeoutRef.current = setTimeout(() => {
          setPhase("idle")
          setProgress(0)
        }, 300)
      }, 200)
    }

    return clearTimers
  }, [isLoading])

  if (phase === "idle") {
    return null
  }

  return (
    <div aria-hidden="true" className="pointer-events-none fixed inset-x-0 top-0 z-[9999] h-[3px]">
      <div
        className={cn(
          "h-full bg-primary transition-all ease-out",
          phase === "loading" && "duration-300",
          phase === "completing" && "duration-200",
          phase === "done" && "opacity-0 duration-300",
        )}
        style={{ width: `${progress}%` }}
      />
      {/* Pulsing glow at the leading edge */}
      {phase === "loading" && (
        <div
          className="absolute right-0 top-0 h-full w-24 -translate-x-px"
          style={{
            background: "linear-gradient(to right, transparent, hsl(var(--primary) / 0.4))",
          }}
        />
      )}
    </div>
  )
}
