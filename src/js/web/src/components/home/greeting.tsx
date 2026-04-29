import { useMemo } from "react"
import { useAuthStore } from "@/lib/auth"

function getGreeting(): string {
  const hour = new Date().getHours()
  if (hour < 12) return "Good morning"
  if (hour < 17) return "Good afternoon"
  return "Good evening"
}

export function useGreeting(): string {
  const user = useAuthStore((state) => state.user)
  const displayName = user?.name || user?.email?.split("@")[0] || "there"

  return useMemo(() => {
    return `${getGreeting()}, ${displayName}`
  }, [displayName])
}
