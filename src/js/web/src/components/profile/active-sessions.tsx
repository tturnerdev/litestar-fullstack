import { Globe, Monitor, Smartphone, Trash2 } from "lucide-react"
import { useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { SkeletonCard } from "@/components/ui/skeleton"
import { useActiveSessions, useRevokeAllSessions, useRevokeSession } from "@/lib/api/hooks/profile"
import type { ActiveSession } from "@/lib/generated/api/types.gen"

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

function parseDeviceInfo(deviceInfo: string | null | undefined): {
  browser: string
  os: string
  isMobile: boolean
} {
  if (!deviceInfo) {
    return { browser: "Unknown browser", os: "Unknown", isMobile: false }
  }

  const ua = deviceInfo.toLowerCase()
  const isMobile = /mobile|android|iphone|ipad/i.test(ua)

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

  return { browser, os, isMobile }
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
  const { browser, os, isMobile } = parseDeviceInfo(session.deviceInfo)
  const DeviceIcon = isMobile ? Smartphone : Monitor
  const createdAgo = formatTimeAgo(session.createdAt)
  const expiresAt = formatTimeAgo(session.expiresAt)

  return (
    <div className="flex items-center justify-between gap-4 rounded-lg border border-border/60 bg-muted/30 px-4 py-3">
      <div className="flex items-center gap-3">
        <div className="flex h-9 w-9 items-center justify-center rounded-full bg-muted">
          <DeviceIcon className="h-4 w-4 text-muted-foreground" />
        </div>
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <p className="truncate font-medium text-sm">
              {browser} on {os}
            </p>
            {session.isCurrent && (
              <Badge variant="secondary" className="text-xs">
                Current
              </Badge>
            )}
          </div>
          <p className="text-muted-foreground text-xs">
            Signed in {createdAgo} &middot; Expires {expiresAt}
          </p>
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

export function ActiveSessions() {
  const { data, isLoading, isError } = useActiveSessions()
  const revokeOne = useRevokeSession()
  const revokeAll = useRevokeAllSessions()
  const [confirmRevokeAll, setConfirmRevokeAll] = useState(false)

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

  const sessions: ActiveSession[] = data?.items ?? []
  const otherSessionCount = sessions.filter((s) => !s.isCurrent).length

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
          <div className="space-y-3">
            {sessions.map((session) => (
              <SessionItem
                key={session.id}
                session={session}
                onRevoke={(id) => revokeOne.mutate(id)}
                isRevoking={revokeOne.isPending}
              />
            ))}
          </div>
        )}
      </CardContent>

      <Dialog open={confirmRevokeAll} onOpenChange={setConfirmRevokeAll}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Revoke all other sessions?</DialogTitle>
            <DialogDescription>
              This will sign you out of all other devices and browsers. Your current session will not be affected.
            </DialogDescription>
          </DialogHeader>
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
              {revokeAll.isPending ? "Revoking..." : "Revoke all"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  )
}
