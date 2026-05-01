import {
  Globe,
  KeyRound,
  LogIn,
  LogOut,
  RefreshCw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  UserPen,
} from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useSecurityActivity, type SecurityActivityEntry } from "@/lib/api/hooks/profile"
import { formatFullDateTime, formatRelativeTime } from "@/lib/date-utils"

/** Map action strings to icons and color classes for visual distinction. */
function getActionMeta(action: string): {
  icon: React.ComponentType<{ className?: string }>
  colorClass: string
  bgClass: string
} {
  switch (action) {
    case "account.login":
      return { icon: LogIn, colorClass: "text-emerald-600 dark:text-emerald-400", bgClass: "bg-emerald-500/10" }
    case "account.logout":
      return { icon: LogOut, colorClass: "text-slate-500", bgClass: "bg-slate-500/10" }
    case "account.password_change":
    case "account.password_reset":
      return { icon: KeyRound, colorClass: "text-blue-600 dark:text-blue-400", bgClass: "bg-blue-500/10" }
    case "account.session_revoke":
    case "account.sessions_revoke_all":
      return { icon: ShieldAlert, colorClass: "text-amber-600 dark:text-amber-400", bgClass: "bg-amber-500/10" }
    case "account.profile_update":
      return { icon: UserPen, colorClass: "text-indigo-600 dark:text-indigo-400", bgClass: "bg-indigo-500/10" }
    case "account.oauth_unlink":
      return { icon: ShieldOff, colorClass: "text-orange-600 dark:text-orange-400", bgClass: "bg-orange-500/10" }
    case "mfa.setup.confirmed":
    case "mfa.challenge.success":
      return { icon: ShieldCheck, colorClass: "text-emerald-600 dark:text-emerald-400", bgClass: "bg-emerald-500/10" }
    case "mfa.setup.failed":
    case "mfa.challenge.failed":
      return { icon: ShieldAlert, colorClass: "text-red-600 dark:text-red-400", bgClass: "bg-red-500/10" }
    case "mfa.disabled":
    case "mfa.disabled.oauth":
    case "mfa_disable":
      return { icon: ShieldOff, colorClass: "text-red-600 dark:text-red-400", bgClass: "bg-red-500/10" }
    case "mfa.backup_codes.regenerated":
      return { icon: KeyRound, colorClass: "text-amber-600 dark:text-amber-400", bgClass: "bg-amber-500/10" }
    default:
      return { icon: Shield, colorClass: "text-muted-foreground", bgClass: "bg-muted" }
  }
}

/** True for actions that indicate a potential security concern. */
function isConcerning(action: string): boolean {
  return action === "mfa.challenge.failed" || action === "mfa.setup.failed"
}

function ActivityRow({ entry }: { entry: SecurityActivityEntry }) {
  const { icon: Icon, colorClass, bgClass } = getActionMeta(entry.action)
  const concerning = isConcerning(entry.action)

  return (
    <div className="flex items-center gap-3 rounded-lg border border-border/60 px-4 py-3 transition-colors hover:bg-muted/30">
      <div className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-full ${bgClass}`}>
        <Icon className={`h-4 w-4 ${colorClass}`} />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <p className="truncate text-sm font-medium">{entry.description}</p>
          {concerning && (
            <Badge variant="destructive" className="text-[10px] px-1.5 py-0">
              Attention
            </Badge>
          )}
        </div>
        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="cursor-default">{formatRelativeTime(entry.createdAt)}</span>
            </TooltipTrigger>
            <TooltipContent>{formatFullDateTime(entry.createdAt)}</TooltipContent>
          </Tooltip>
          {entry.ipAddress && (
            <>
              <span>&middot;</span>
              <div className="flex items-center gap-1">
                <Globe className="h-3 w-3 shrink-0" />
                <span>{entry.ipAddress}</span>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}

export function RecentSecurityActivity() {
  const { data, isLoading, isError, isFetching, refetch } = useSecurityActivity()

  if (isLoading) {
    return <SkeletonCard />
  }

  if (isError) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Recent Security Activity</CardTitle>
          <CardDescription>Unable to load security activity.</CardDescription>
        </CardHeader>
      </Card>
    )
  }

  const entries = data ?? []

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-4">
          <div className="space-y-1.5">
            <CardTitle className="flex items-center gap-2 text-base">
              <Shield className="h-4 w-4 text-muted-foreground" />
              Recent Security Activity
            </CardTitle>
            <CardDescription>
              Your most recent security-related events, including logins, password changes, and MFA activity.
            </CardDescription>
          </div>
          <button
            type="button"
            onClick={() => refetch()}
            disabled={isFetching}
            className="shrink-0 rounded-md p-2 text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
            aria-label="Refresh security activity"
          >
            <RefreshCw className={`h-4 w-4 ${isFetching ? "animate-spin" : ""}`} />
          </button>
        </div>
      </CardHeader>
      <CardContent>
        {entries.length === 0 ? (
          <div className="flex flex-col items-center gap-2 py-6 text-center">
            <Shield className="h-8 w-8 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">No security events recorded yet.</p>
          </div>
        ) : (
          <div className="space-y-2">
            {entries.map((entry) => (
              <ActivityRow key={entry.id} entry={entry} />
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
