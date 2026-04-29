import { useQuery } from "@tanstack/react-query"
import { Link } from "@tanstack/react-router"
import { CheckCircle2, Circle, ChevronRight, Sparkles } from "lucide-react"
import { useMemo } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { useAuthStore } from "@/lib/auth"
import { listTeams } from "@/lib/generated/api"

interface ChecklistItem {
  id: string
  label: string
  description: string
  completed: boolean
  to: string
}

export function GettingStarted() {
  const user = useAuthStore((state) => state.user)
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated)

  const { data: teams = [] } = useQuery({
    queryKey: ["teams"],
    queryFn: async () => {
      const response = await listTeams()
      return response.data?.items ?? []
    },
    enabled: isAuthenticated,
  })

  const hasProfile = !!(user?.name && user.name.trim().length > 0)
  const hasTeam = teams.length > 0

  const items: ChecklistItem[] = useMemo(
    () => [
      {
        id: "profile",
        label: "Set up your profile",
        description: "Add your name and contact details",
        completed: hasProfile,
        to: "/profile",
      },
      {
        id: "team",
        label: "Create or join a team",
        description: "Teams are how you organize work and collaborate",
        completed: hasTeam,
        to: "/teams/new",
      },
      {
        id: "device",
        label: "Add a device",
        description: "Register a phone, computer, or other device",
        completed: false,
        to: "/devices",
      },
      {
        id: "voice",
        label: "Set up voice",
        description: "Configure phone numbers and extensions",
        completed: false,
        to: "/voice/phone-numbers",
      },
    ],
    [hasProfile, hasTeam],
  )

  const completedCount = items.filter((item) => item.completed).length
  const allComplete = completedCount === items.length

  if (allComplete) {
    return null
  }

  const progressPercent = Math.round((completedCount / items.length) * 100)

  return (
    <Card className="border-primary/20 bg-linear-to-br from-primary/5 via-transparent to-transparent">
      <CardHeader>
        <div className="flex items-center gap-2">
          <Sparkles className="h-5 w-5 text-primary" />
          <CardTitle className="text-lg">Getting Started</CardTitle>
        </div>
        <CardDescription>
          Complete these steps to get the most out of the platform ({completedCount} of {items.length})
        </CardDescription>
        <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-muted">
          <div
            className="h-full rounded-full bg-primary transition-all duration-500"
            style={{ width: `${progressPercent}%` }}
          />
        </div>
      </CardHeader>
      <CardContent className="space-y-1">
        {items.map((item) => (
          <Link
            key={item.id}
            to={item.to}
            className="group flex items-center gap-3 rounded-lg px-3 py-2.5 transition-colors hover:bg-muted/50"
          >
            {item.completed ? (
              <CheckCircle2 className="h-5 w-5 shrink-0 text-primary" />
            ) : (
              <Circle className="h-5 w-5 shrink-0 text-muted-foreground/40" />
            )}
            <div className="min-w-0 flex-1">
              <p className={`text-sm font-medium ${item.completed ? "text-muted-foreground line-through" : ""}`}>{item.label}</p>
              <p className="text-xs text-muted-foreground">{item.description}</p>
            </div>
            {!item.completed && (
              <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground/40 transition-transform group-hover:translate-x-0.5 group-hover:text-foreground" />
            )}
          </Link>
        ))}
      </CardContent>
    </Card>
  )
}
