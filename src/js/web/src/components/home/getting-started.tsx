import { useQuery } from "@tanstack/react-query"
import { Link } from "@tanstack/react-router"
import { CheckCircle2, ChevronRight, Clock, PartyPopper, Sparkles, X } from "lucide-react"
import { useMemo, useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { useAuthStore } from "@/lib/auth"
import { getVoicemailSettings, listDevices, listExtensions, listTeams } from "@/lib/generated/api"

const ADMIN_DISMISSED_KEY = "getting-started-admin-dismissed"
const MEMBER_DISMISSED_KEY = "getting-started-member-dismissed"

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

  const isSuperuser = user?.isSuperuser ?? false
  const isAdmin = user?.teams?.some((t) => t.role === "ADMIN") ?? false
  const isMember = !isSuperuser && !isAdmin

  const dismissedKey = isMember ? MEMBER_DISMISSED_KEY : ADMIN_DISMISSED_KEY

  const [isDismissed, setIsDismissed] = useState(() => {
    try {
      return localStorage.getItem(dismissedKey) === "true"
    } catch {
      return false
    }
  })

  // ---------- Shared queries ----------

  const { data: teams = [], isLoading: teamsLoading } = useQuery({
    queryKey: ["teams"],
    queryFn: async () => {
      const response = await listTeams()
      return response.data?.items ?? []
    },
    enabled: isAuthenticated && !isSuperuser,
  })

  // ---------- Admin-only queries ----------

  const hasFeatureAccess = isSuperuser || isAdmin

  const { data: deviceCount = 0, isLoading: devicesLoading } = useQuery({
    queryKey: ["getting-started", "devices"],
    queryFn: async () => {
      const response = await listDevices({ query: { pageSize: 1 } })
      return (response.data as { total?: number } | undefined)?.total ?? 0
    },
    enabled: isAuthenticated && hasFeatureAccess && !isSuperuser,
    staleTime: 60_000,
  })

  const { data: adminExtensionCount = 0, isLoading: adminExtensionsLoading } = useQuery({
    queryKey: ["getting-started", "admin-extensions"],
    queryFn: async () => {
      const response = await listExtensions({ query: { pageSize: 1 } })
      return (response.data as { total?: number } | undefined)?.total ?? 0
    },
    enabled: isAuthenticated && hasFeatureAccess && !isSuperuser,
    staleTime: 60_000,
  })

  // ---------- Member-only queries ----------

  const { data: memberExtensions, isLoading: memberExtensionsLoading, isError: extensionsError } = useQuery({
    queryKey: ["getting-started", "member-extensions"],
    queryFn: async () => {
      const response = await listExtensions({ query: { pageSize: 200 } })
      return response.data?.items ?? []
    },
    enabled: isAuthenticated && !isSuperuser && isMember,
    staleTime: 60_000,
    retry: false,
  })

  const userExtension = useMemo(() => {
    if (!memberExtensions || !user?.id) return undefined
    return memberExtensions.find((ext) => ext.userId === user.id)
  }, [memberExtensions, user?.id])

  const userExtensionId = userExtension?.id ?? ""

  const { data: voicemailSettings } = useQuery({
    queryKey: ["getting-started", "voicemail-settings", userExtensionId],
    queryFn: async () => {
      const response = await getVoicemailSettings({ path: { ext_id: userExtensionId } })
      return response.data
    },
    enabled: !!userExtensionId,
    staleTime: 60_000,
  })

  // ---------- Superuser: never show ----------

  if (isSuperuser) {
    return null
  }

  // ---------- Loading state ----------

  const hasVoiceAccess = isMember && !extensionsError && !memberExtensionsLoading

  const isLoading = isMember
    ? teamsLoading || memberExtensionsLoading
    : teamsLoading || devicesLoading || adminExtensionsLoading

  // ---------- Completion checks ----------

  const hasProfile = !!(user?.name && user.name.trim().length > 0)
  const hasTeam = isMember ? (user?.teams?.length ?? 0) > 0 : teams.length > 0

  // Admin checks
  const hasDevice = deviceCount > 0
  const hasVoice = adminExtensionCount > 0

  // Member checks
  const hasExtensionSetUp = !!userExtension && !!(userExtension.displayName && userExtension.displayName.trim().length > 0)
  const hasVoicemailConfigured = !!(voicemailSettings?.isEnabled && voicemailSettings?.pinSet)

  // ---------- Checklist items ----------

  const voicemailLink = userExtension ? `/voice/extensions/${userExtension.id}/voicemail` : "/voice/extensions"

  const adminItems: ChecklistItem[] = useMemo(
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
        completed: hasDevice,
        to: "/devices",
      },
      {
        id: "voice",
        label: "Set up voice",
        description: "Configure phone numbers and extensions",
        completed: hasVoice,
        to: "/voice/extensions",
      },
    ],
    [hasProfile, hasTeam, hasDevice, hasVoice],
  )

  const memberItems: ChecklistItem[] = useMemo(() => {
    const items: ChecklistItem[] = [
      {
        id: "profile",
        label: "Complete your profile",
        description: "Add your name and contact details",
        completed: hasProfile,
        to: "/profile",
      },
      {
        id: "team",
        label: "Join a team",
        description: "Teams help you collaborate with your organization",
        completed: hasTeam,
        to: "/teams",
      },
    ]
    if (hasVoiceAccess) {
      items.push(
        {
          id: "extension",
          label: "Set up your extension",
          description: "Configure your phone extension with a display name",
          completed: hasExtensionSetUp,
          to: "/voice/extensions",
        },
        {
          id: "voicemail",
          label: "Configure your voicemail",
          description: "Enable voicemail and set a PIN for your extension",
          completed: hasVoicemailConfigured,
          to: voicemailLink,
        },
      )
    }
    return items
  }, [hasProfile, hasTeam, hasVoiceAccess, hasExtensionSetUp, hasVoicemailConfigured, voicemailLink])

  const items = isMember ? memberItems : adminItems

  const completedCount = items.filter((item) => item.completed).length
  const allComplete = completedCount === items.length
  const firstIncompleteId = items.find((item) => !item.completed)?.id

  const handleDismiss = () => {
    try {
      localStorage.setItem(dismissedKey, "true")
    } catch {
      // ignore storage errors
    }
    setIsDismissed(true)
  }

  if (isDismissed || isLoading) {
    return null
  }

  if (allComplete) {
    return (
      <Card className="border-primary/20 bg-linear-to-br from-primary/5 via-transparent to-transparent">
        <CardContent className="flex flex-col items-center gap-3 py-8 text-center">
          <PartyPopper className="h-10 w-10 text-primary" />
          <div>
            <p className="text-lg font-semibold">You're all set!</p>
            <p className="text-sm text-muted-foreground">You've completed all the getting started steps.</p>
          </div>
          <Button variant="outline" size="sm" onClick={handleDismiss}>
            Dismiss
          </Button>
        </CardContent>
      </Card>
    )
  }

  const progressPercent = Math.round((completedCount / items.length) * 100)
  let stepNumber = 0

  return (
    <Card className="border-primary/20 bg-linear-to-br from-primary/5 via-transparent to-transparent">
      <CardHeader>
        <div className="flex items-center gap-2">
          <Sparkles className="h-5 w-5 text-primary" />
          <CardTitle className="text-lg">Getting Started</CardTitle>
          <Button variant="ghost" size="icon" className="ml-auto h-6 w-6 text-muted-foreground hover:text-foreground" onClick={handleDismiss} aria-label="Dismiss getting started">
            <X className="h-3.5 w-3.5" />
          </Button>
        </div>
        <CardDescription>
          Complete these steps to get the most out of the platform ({completedCount} of {items.length})
        </CardDescription>
        <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-muted">
          <div className="h-full rounded-full bg-primary transition-all duration-500" style={{ width: `${progressPercent}%` }} />
        </div>
      </CardHeader>
      <CardContent className="space-y-1">
        {items.map((item) => {
          const isActive = item.id === firstIncompleteId
          if (!item.completed) {
            stepNumber++
          }
          return (
            <Link
              key={item.id}
              to={item.to}
              className={`group flex items-center gap-3 rounded-lg px-3 py-2.5 transition-colors hover:bg-muted/50 ${
                isActive ? "rounded border-l-2 border-primary bg-primary/5" : ""
              }`}
            >
              {item.completed ? (
                <CheckCircle2 className="h-5 w-5 shrink-0 text-primary" />
              ) : (
                <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-muted-foreground/30 text-[10px] font-medium text-muted-foreground">
                  {stepNumber}
                </span>
              )}
              <div className="min-w-0 flex-1">
                <p className={`text-sm font-medium ${item.completed ? "text-muted-foreground line-through" : ""}`}>{item.label}</p>
                <p className="text-xs text-muted-foreground">{item.description}</p>
              </div>
              {!item.completed && (
                <span className="flex items-center gap-1 text-[10px] text-muted-foreground">
                  <Clock className="h-3 w-3" />
                  ~2 min
                </span>
              )}
              {!item.completed && (
                <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground/40 transition-transform group-hover:translate-x-0.5 group-hover:text-foreground" />
              )}
            </Link>
          )
        })}
      </CardContent>
    </Card>
  )
}
