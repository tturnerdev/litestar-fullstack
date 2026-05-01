import { AlertCircle, AlertTriangle, Globe, Loader2, MapPin, Monitor, RefreshCw, ShieldCheck, Smartphone, Tablet, Trash2 } from "lucide-react"
import { useCallback, useEffect, useMemo, useState } from "react"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { EmptyState } from "@/components/ui/empty-state"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useActiveSessions, useRevokeAllSessions, useRevokeSession } from "@/lib/api/hooks/profile"
import { formatFullDateTime, formatRelativeTime, formatRelativeTimeShort } from "@/lib/date-utils"
import type { ActiveSession } from "@/lib/generated/api/types.gen"

type DeviceCategory = "Desktop" | "Mobile" | "Tablet"

/** Wrap formatRelativeTime to handle future dates (e.g. session expiry). */
function formatTimeAgo(dateStr: string): string {
  const diffMs = Date.now() - new Date(dateStr).getTime()
  if (diffMs >= 0) return formatRelativeTime(dateStr)
  // Future date: rewrite "X ago" → "in X"
  const agoStr = formatRelativeTime(
    new Date(Date.now() + Math.abs(diffMs)).toISOString(),
  )
  return `in ${agoStr.replace(/ ago$/, "")}`
}

function formatLastActive(dateStr: string): string {
  const diffMs = Date.now() - new Date(dateStr).getTime()
  if (diffMs < 120_000) return "Active now"
  return formatRelativeTimeShort(dateStr)
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

const deviceCategoryIconColor: Record<DeviceCategory, string> = {
  Desktop: "text-blue-500",
  Mobile: "text-green-500",
  Tablet: "text-amber-500",
}

function SessionItem({
  session,
  onRevoke,
  isRevoking,
  confirmingId,
  onConfirmStart,
  onConfirmCancel,
}: {
  session: ActiveSession
  onRevoke: (id: string) => void
  isRevoking: boolean
  confirmingId: string | null
  onConfirmStart: (id: string) => void
  onConfirmCancel: () => void
}) {
  const { browser, os, category } = parseDeviceInfo(session.deviceInfo)
  const DeviceIcon = deviceCategoryIcon[category]
  const iconColor = deviceCategoryIconColor[category]
  const lastActive = formatLastActive(session.createdAt)
  const expiresAt = formatTimeAgo(session.expiresAt)
  const expiresAtFull = formatFullDateTime(session.expiresAt)

  // ActiveSession type may have location fields depending on the backend
  const sessionAny = session as Record<string, unknown>
  const location = sessionAny.location as string | undefined
  const city = sessionAny.city as string | undefined
  const region = sessionAny.region as string | undefined
  const country = sessionAny.country as string | undefined
  const ipAddress = sessionAny.ipAddress as string | undefined

  let locationStr: string | null = null
  if (location && typeof location === "string") {
    locationStr = location
  } else if (city || region || country) {
    locationStr = [city, region, country].filter(Boolean).join(", ")
  }

  const isConfirming = confirmingId === session.id

  useEffect(() => {
    if (confirmingId === null) return
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") {
        onConfirmCancel()
      }
    }
    document.addEventListener("keydown", onKeyDown)
    return () => document.removeEventListener("keydown", onKeyDown)
  }, [confirmingId, onConfirmCancel])

  return (
    <div
      className={`flex items-center justify-between gap-4 rounded-lg border px-4 py-3 ${
        session.isCurrent
          ? "border-emerald-500/30 bg-emerald-500/5"
          : "border-border/60 bg-muted/30 hover:bg-muted/50 transition-colors"
      }`}
    >
      <div className="flex items-center gap-3">
        <div
          className={`flex h-9 w-9 items-center justify-center rounded-full ${
            session.isCurrent ? "bg-emerald-500/10" : "bg-muted"
          }`}
        >
          <DeviceIcon
            className={`h-4 w-4 ${session.isCurrent ? "text-emerald-600" : iconColor}`}
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
            <Tooltip>
              <TooltipTrigger asChild>
                <span className="cursor-default">Expires {expiresAt}</span>
              </TooltipTrigger>
              <TooltipContent>{expiresAtFull}</TooltipContent>
            </Tooltip>
          </div>
          <div className="flex items-center gap-2 text-muted-foreground text-xs mt-0.5">
            <div className="flex items-center gap-1">
              <MapPin className="h-3 w-3 shrink-0" />
              <span>{locationStr ?? "Unknown location"}</span>
            </div>
            {ipAddress && (
              <>
                <span>&middot;</span>
                <div className="flex items-center gap-1">
                  <Globe className="h-3 w-3 shrink-0" />
                  <span>{ipAddress}</span>
                </div>
              </>
            )}
          </div>
        </div>
      </div>

      {!session.isCurrent && (
        <div className="shrink-0">
          {isConfirming ? (
            <div className="flex items-center gap-1.5">
              <span className="text-xs text-muted-foreground whitespace-nowrap">Are you sure?</span>
              <Button
                variant="destructive"
                size="sm"
                onClick={() => onRevoke(session.id)}
                disabled={isRevoking}
                className="h-7 px-2 text-xs"
                autoFocus
              >
                Confirm
              </Button>
              <Button
                variant="ghost"
                size="sm"
                onClick={onConfirmCancel}
                className="h-7 px-2 text-xs"
              >
                Cancel
              </Button>
            </div>
          ) : (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => onConfirmStart(session.id)}
              disabled={isRevoking}
              className="text-destructive hover:text-destructive"
            >
              <Trash2 className="mr-1.5 h-3.5 w-3.5" />
              Revoke
            </Button>
          )}
        </div>
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
  const { data, isLoading, isError, isFetching, refetch } = useActiveSessions()
  const revokeOne = useRevokeSession()
  const revokeAll = useRevokeAllSessions()
  const [confirmRevokeAll, setConfirmRevokeAll] = useState(false)
  const [confirmingId, setConfirmingId] = useState<string | null>(null)

  const sessions: ActiveSession[] = data?.items ?? []
  const otherSessionCount = sessions.filter((s) => !s.isCurrent).length

  const grouped = useMemo(() => groupSessionsByDevice(sessions), [sessions])

  // Auto-revert inline confirmation after 3 seconds
  useEffect(() => {
    if (confirmingId === null) return
    const timer = setTimeout(() => {
      setConfirmingId(null)
    }, 3000)
    return () => clearTimeout(timer)
  }, [confirmingId])

  const handleConfirmStart = useCallback((id: string) => {
    setConfirmingId(id)
  }, [])

  const handleConfirmCancel = useCallback(() => {
    setConfirmingId(null)
  }, [])

  const handleRevoke = useCallback(
    (id: string) => {
      revokeOne.mutate(id)
      setConfirmingId(null)
    },
    [revokeOne],
  )

  if (isLoading) {
    return <SkeletonCard />
  }

  if (isError) {
    return (
      <EmptyState
        icon={AlertCircle}
        title="Unable to load sessions"
        description="Something went wrong loading your active sessions."
        action={<Button variant="outline" size="sm" onClick={() => refetch()}>Try again</Button>}
      />
    )
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-4">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2">
              <CardTitle>Active sessions</CardTitle>
              {sessions.length > 0 && (
                <Badge variant="secondary" className="text-xs">
                  {sessions.length} active
                </Badge>
              )}
            </div>
            <CardDescription>
              Manage your active sessions across devices. If you see a session you don't recognize, revoke it immediately.
            </CardDescription>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <Button
              variant="ghost"
              size="icon"
              onClick={() => refetch()}
              disabled={isFetching}
              className="h-8 w-8"
              aria-label="Refresh sessions"
            >
              <RefreshCw className={`h-4 w-4 ${isFetching ? "animate-spin" : ""}`} />
              <span className="sr-only">Refresh sessions</span>
            </Button>
            {otherSessionCount > 0 && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => setConfirmRevokeAll(true)}
                disabled={revokeAll.isPending}
              >
                Revoke all others
              </Button>
            )}
          </div>
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
                        onRevoke={handleRevoke}
                        isRevoking={revokeOne.isPending}
                        confirmingId={confirmingId}
                        onConfirmStart={handleConfirmStart}
                        onConfirmCancel={handleConfirmCancel}
                      />
                    ))}
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </CardContent>

      <AlertDialog open={confirmRevokeAll} onOpenChange={setConfirmRevokeAll}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <div className="flex items-center gap-2">
              <div className="flex h-9 w-9 items-center justify-center rounded-full bg-amber-500/10">
                <AlertTriangle className="h-5 w-5 text-amber-500" />
              </div>
              <AlertDialogTitle>Revoke all other sessions?</AlertDialogTitle>
            </div>
            <AlertDialogDescription>
              This will sign you out of all other devices. You'll stay signed in on this device.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="rounded-md border border-amber-500/20 bg-amber-500/5 p-3">
            <p className="text-sm text-amber-700 dark:text-amber-400">
              {otherSessionCount} other session{otherSessionCount !== 1 ? "s" : ""} will be revoked.
              Anyone using those sessions will need to sign in again.
            </p>
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setConfirmRevokeAll(false)}>
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={async () => {
                await revokeAll.mutateAsync()
                setConfirmRevokeAll(false)
              }}
              disabled={revokeAll.isPending}
              className="bg-destructive text-white shadow-md hover:bg-destructive/90 focus-visible:ring-destructive/20 dark:bg-destructive/60"
            >
              {revokeAll.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {revokeAll.isPending ? "Revoking..." : `Revoke ${otherSessionCount} session${otherSessionCount !== 1 ? "s" : ""}`}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  )
}
