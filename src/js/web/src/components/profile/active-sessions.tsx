import { Globe, Monitor, Smartphone, Tablet, Trash2, MapPin, ShieldCheck } from "lucide-react"
import { useMemo, useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { SkeletonCard } from "@/components/ui/skeleton"
import { useActiveSessions, useRevokeAllSessions, useRevokeSession } from "@/lib/api/hooks/profile"
import type { ActiveSession } from "@/lib/generated/api/types.gen"

type DeviceCategory = "Desktop" | "Mobile" | "Tablet"

function formatTimeAgo(dateStr: string): string {
  const date = new Date(dateStr)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const absDiffMs = Math.abs(diffMs)
  const isFuture = diffMs < 0

  const minutes = Math.floor(absDiffMs / 60000)
  const hours = Math.floor(absDiffMs / 3600000)
  const days = Math.floor(absDiffMs / 86400000)

  let relative: string
  if (minutes < 1) relative = "less than a minute"
  else if (minutes === 1) relative = "1 minute"
  else if (minutes < 60) relative = `${minutes} minutes`
  else if (hours === 1) relative = "1 hour"
  else if (hours < 24) relative = `${hours} hours`
  else if (days === 1) relative = "1 day"
  else if (days < 30) relative = `${days} days`
  else relative = `${Math.floor(days / 30)} month${Math.floor(days / 30) !== 1 ? "s" : ""}`

  return isFuture ? `in ${relative}` : `${relative} ago`
}

function formatLastActive(dateStr: string): string {
  const date = new Date(dateStr)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const minutes = Math.floor(diffMs / 60000)
  const hours = Math.floor(diffMs / 3600000)
  const days = Math.floor(diffMs / 86400000)

  if (minutes < 2) return "Active now"
  if (minutes < 60) return `${minutes}m ago`
  if (hours < 24) return `${hours}h ago`
  if (days === 1) return "1 day ago"
  return `${days} days ago`
}

function parseDeviceInfo(deviceInfo: string | null | undefined): {
  browser: string
  os: string
  category: DeviceCategory
} {
  if (!deviceInfo) {
    return { browser: "Unknown browser", os: "Unknown", category: "Desktop" }
  }

  const ua = deviceInfo.toLowerCase()
  const isTablet = /ipad|tablet|kindle|silk/i.test(ua) || (/android/i.test(ua) && !/mobile/i.test(ua))
  const isMobile = !isTablet && /mobile|android|iphone/i.test(ua)

  let category: DeviceCategory = "Desktop"
  if (isTablet) category = "Tablet"
  else if (isMobile) category = "Mobile"

  let browser = "Unknown browser"
  if (ua.includes("firefox")) {
    browser = "Firefox"
  } else if (ua.includes("edg/")) {
    browser = "Edge"
  } else if (ua.includes("chrome") && !ua.includes("edg")) {
    browser = "Chrome"
  } else if (ua.includes("safari") && !ua.includes("chrome")) {
    browser = "Safari"
  } else if (ua.includes("opera") || ua.includes("opr/")) {
    browser = "Opera"
  }

  let os = "Unknown"
  if (ua.includes("windows")) {
    os = "Windows"
  } else if (ua.includes("mac os")) {
    os = "macOS"
  } else if (ua.includes("linux") && !ua.includes("android")) {
    os = "Linux"
  } else if (ua.includes("android")) {
    os = "Android"
  } else if (ua.includes("iphone") || ua.includes("ipad")) {
    os = "iOS"
  }

  return { browser, os, category }
}

const deviceCategoryIcon: Record<DeviceCategory, typeof Monitor> = {
  Desktop: Monitor,
  Mobile: Smartphone,
  Tablet: Tablet,
}

function SessionItem({
  session,
  onRevoke,
  isRevoking,
}: {
  session: ActiveSession
  onRevoke: (id: string) => void
  isRevoking: boolean
}) {
  const { browser, os, category } = parseDeviceInfo(session.deviceInfo)
  const DeviceIcon = deviceCategoryIcon[category]
  const lastActive = formatLastActive(session.createdAt)
  const expiresAt = formatTimeAgo(session.expiresAt)

  // ActiveSession type may have location fields depending on the backend
  const sessionAny = session as Record<string, unknown>
  const location = sessionAny.location as string | undefined
  const city = sessionAny.city as string | undefined
  const region = sessionAny.region as string | undefined
  const country = sessionAny.country as string | undefined

  let locationStr: string | null = null
  if (location && typeof location === "string") {
    locationStr = location
  } else if (city || region || country) {
    locationStr = [city, region, country].filter(Boolean).join(", ")
  }

  return (
    <div
      className={`flex items-center justify-between gap-4 rounded-lg border px-4 py-3 ${
        session.isCurrent
          ? "border-emerald-500/30 bg-emerald-500/5"
          : "border-border/60 bg-muted/30"
      }`}
    >
      <div className="flex items-center gap-3">
        <div
          className={`flex h-9 w-9 items-center justify-center rounded-full ${
            session.isCurrent ? "bg-emerald-500/10" : "bg-muted"
          }`}
        >
          <DeviceIcon
            className={`h-4 w-4 ${session.isCurrent ? "text-emerald-600" : "text-muted-foreground"}`}
          />
        </div>
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <p className="truncate font-medium text-sm">
              {browser} on {os}
            </p>
            {session.isCurrent && (
              <Badge className="border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 text-xs gap-1">
                <ShieldCheck className="h-3 w-3" />
                This device
              </Badge>
            )}
          </div>
          <div className="flex items-center gap-1.5 text-muted-foreground text-xs">
            <span>{lastActive}</span>
            <span>&middot;</span>
            <span>Expires {expiresAt}</span>
          </div>
          <div className="flex items-center gap-1 text-muted-foreground text-xs mt-0.5">
            <MapPin className="h-3 w-3 shrink-0" />
            <span>{locationStr ?? "Unknown location"}</span>
          </div>
        </div>
      </div>

      {!session.isCurrent && (
        <Button
          variant="ghost"
          size="sm"
          onClick={() => onRevoke(session.id)}
          disabled={isRevoking}
          className="text-destructive hover:text-destructive shrink-0"
        >
          <Trash2 className="mr-1.5 h-3.5 w-3.5" />
          Revoke
        </Button>
      )}
    </div>
  )
}

interface GroupedSessions {
  category: DeviceCategory
  sessions: ActiveSession[]
}

function groupSessionsByDevice(sessions: ActiveSession[]): GroupedSessions[] {
  const groups: Record<DeviceCategory, ActiveSession[]> = {
    Desktop: [],
    Mobile: [],
    Tablet: [],
  }

  for (const session of sessions) {
    const { category } = parseDeviceInfo(session.deviceInfo)
    groups[category].push(session)
  }

  // Sort each group: current session first, then by creation date descending
  const sortSessions = (a: ActiveSession, b: ActiveSession) => {
    if (a.isCurrent && !b.isCurrent) return -1
    if (!a.isCurrent && b.isCurrent) return 1
    return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
  }

  const result: GroupedSessions[] = []
  const order: DeviceCategory[] = ["Desktop", "Mobile", "Tablet"]
  for (const cat of order) {
    if (groups[cat].length > 0) {
      groups[cat].sort(sortSessions)
      result.push({ category: cat, sessions: groups[cat] })
    }
  }
  return result
}

export function ActiveSessions() {
  const { data, isLoading, isError } = useActiveSessions()
  const revokeOne = useRevokeSession()
  const revokeAll = useRevokeAllSessions()
  const [confirmRevokeAll, setConfirmRevokeAll] = useState(false)

  const sessions: ActiveSession[] = data?.items ?? []
  const otherSessionCount = sessions.filter((s) => !s.isCurrent).length

  const grouped = useMemo(() => groupSessionsByDevice(sessions), [sessions])

  if (isLoading) {
    return <SkeletonCard />
  }

  if (isError) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Active sessions</CardTitle>
          <CardDescription>Unable to load your active sessions.</CardDescription>
        </CardHeader>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-4">
          <div className="space-y-1.5">
            <CardTitle>Active sessions</CardTitle>
            <CardDescription>
              Manage your active sessions across devices. If you see a session you don't recognize, revoke it immediately.
            </CardDescription>
          </div>
          {otherSessionCount > 0 && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => setConfirmRevokeAll(true)}
              disabled={revokeAll.isPending}
              className="shrink-0"
            >
              Revoke all others
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent>
        {sessions.length === 0 ? (
          <div className="flex flex-col items-center gap-2 py-6 text-center">
            <Globe className="h-8 w-8 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">No active sessions found.</p>
          </div>
        ) : (
          <div className="space-y-5">
            {grouped.map((group) => {
              const GroupIcon = deviceCategoryIcon[group.category]
              return (
                <div key={group.category} className="space-y-2">
                  <div className="flex items-center gap-2 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                    <GroupIcon className="h-3.5 w-3.5" />
                    {group.category}
                    <span className="text-muted-foreground/60">({group.sessions.length})</span>
                  </div>
                  <div className="space-y-2">
                    {group.sessions.map((session) => (
                      <SessionItem
                        key={session.id}
                        session={session}
                        onRevoke={(id) => revokeOne.mutate(id)}
                        isRevoking={revokeOne.isPending}
                      />
                    ))}
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </CardContent>

      <Dialog open={confirmRevokeAll} onOpenChange={setConfirmRevokeAll}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Revoke all other sessions?</DialogTitle>
            <DialogDescription>
              This will sign you out of all other devices. You'll stay signed in on this device.
            </DialogDescription>
          </DialogHeader>
          <div className="rounded-md border border-amber-500/20 bg-amber-500/5 p-3">
            <p className="text-sm text-amber-700 dark:text-amber-400">
              {otherSessionCount} other session{otherSessionCount !== 1 ? "s" : ""} will be revoked.
              Anyone using those sessions will need to sign in again.
            </p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmRevokeAll(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={async () => {
                await revokeAll.mutateAsync()
                setConfirmRevokeAll(false)
              }}
              disabled={revokeAll.isPending}
            >
              {revokeAll.isPending ? "Revoking..." : `Revoke ${otherSessionCount} session${otherSessionCount !== 1 ? "s" : ""}`}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  )
}
