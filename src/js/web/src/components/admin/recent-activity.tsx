import { Link } from "@tanstack/react-router"
import {
  AlertCircle,
  ArrowRight,
  KeyRound,
  LogIn,
  Pencil,
  Plus,
  Settings,
  Shield,
  Trash2,
  UserCheck,
  UserPlus,
} from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { EmptyState } from "@/components/ui/empty-state"
import { Skeleton } from "@/components/ui/skeleton"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { useAdminRecentActivity } from "@/lib/api/hooks/admin"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"

function getActionStyle(action: string) {
  const lower = action.toLowerCase()
  if (lower.includes("delete") || lower.includes("remove")) {
    return {
      icon: Trash2,
      iconColor: "text-red-600 dark:text-red-400",
      bgColor: "bg-red-500/10",
      label: "Deleted",
      variant: "destructive" as const,
    }
  }
  if (lower.includes("update") || lower.includes("edit") || lower.includes("change")) {
    return {
      icon: Pencil,
      iconColor: "text-blue-600 dark:text-blue-400",
      bgColor: "bg-blue-500/10",
      label: "Updated",
      variant: "secondary" as const,
    }
  }
  if (lower.includes("login") || lower.includes("sign_in") || lower.includes("signin")) {
    return {
      icon: LogIn,
      iconColor: "text-amber-600 dark:text-amber-400",
      bgColor: "bg-amber-500/10",
      label: "Sign In",
      variant: "outline" as const,
    }
  }
  if (lower.includes("register") || lower.includes("signup") || lower.includes("sign_up")) {
    return {
      icon: UserPlus,
      iconColor: "text-emerald-600 dark:text-emerald-400",
      bgColor: "bg-emerald-500/10",
      label: "Registered",
      variant: "outline" as const,
    }
  }
  if (lower.includes("verify") || lower.includes("confirm")) {
    return {
      icon: UserCheck,
      iconColor: "text-teal-600 dark:text-teal-400",
      bgColor: "bg-teal-500/10",
      label: "Verified",
      variant: "outline" as const,
    }
  }
  if (lower.includes("role") || lower.includes("permission")) {
    return {
      icon: Shield,
      iconColor: "text-violet-600 dark:text-violet-400",
      bgColor: "bg-violet-500/10",
      label: "Role",
      variant: "secondary" as const,
    }
  }
  if (lower.includes("password") || lower.includes("mfa") || lower.includes("2fa") || lower.includes("token")) {
    return {
      icon: KeyRound,
      iconColor: "text-orange-600 dark:text-orange-400",
      bgColor: "bg-orange-500/10",
      label: "Security",
      variant: "outline" as const,
    }
  }
  if (lower.includes("config") || lower.includes("setting")) {
    return {
      icon: Settings,
      iconColor: "text-slate-600 dark:text-slate-400",
      bgColor: "bg-slate-500/10",
      label: "Config",
      variant: "outline" as const,
    }
  }
  // Default: create / other
  return {
    icon: Plus,
    iconColor: "text-emerald-600 dark:text-emerald-400",
    bgColor: "bg-emerald-500/10",
    label: "Created",
    variant: "outline" as const,
  }
}

/** Format an action string for display (e.g. "user_login" becomes "User Login"). */
function formatAction(action: string): string {
  return action
    .replace(/[._-]/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase())
}

function TimelineSkeleton() {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <Skeleton className="h-5 w-32" />
        <Skeleton className="h-5 w-16 rounded-full" />
      </CardHeader>
      <CardContent>
        <div className="space-y-1">
          {Array.from({ length: 6 }).map((_, i) => (
            // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
            <div key={`timeline-skeleton-${i}`} className="flex items-center gap-3 rounded-lg px-2 py-3">
              <Skeleton className="h-8 w-8 shrink-0 rounded-full" />
              <div className="flex-1 space-y-1.5">
                <Skeleton className="h-3.5 w-3/4" />
                <Skeleton className="h-3 w-1/2" />
              </div>
              <Skeleton className="h-3 w-12" />
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}

export function RecentActivity() {
  const { data, isLoading, isError, refetch } = useAdminRecentActivity()

  if (isLoading) {
    return <TimelineSkeleton />
  }

  if (isError || !data) {
    return (
      <EmptyState
        icon={AlertCircle}
        title="Unable to load recent activity"
        description="Something went wrong. Please try again."
        action={<Button variant="outline" size="sm" onClick={() => refetch()}>Try again</Button>}
      />
    )
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle>Recent Activity</CardTitle>
        {data.total > 0 && (
          <Badge variant="secondary" className="font-normal tabular-nums">
            {data.total} total
          </Badge>
        )}
      </CardHeader>
      <CardContent>
        {data.activities.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-8 text-center">
            <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-muted">
              <LogIn className="h-5 w-5 text-muted-foreground" />
            </div>
            <p className="text-sm font-medium text-muted-foreground">No recent activity</p>
            <p className="mt-1 text-xs text-muted-foreground">Events will appear here as they occur.</p>
          </div>
        ) : (
          <TooltipProvider>
            <div className="space-y-1">
              {data.activities.map((activity) => {
                const style = getActionStyle(activity.action)
                const Icon = style.icon
                const actorDisplay = activity.actorName || activity.actorEmail || "System"

                return (
                  <div
                    key={activity.id}
                    className="group/item flex items-start gap-3 rounded-lg px-2 py-2.5 transition-colors hover:bg-muted/50"
                  >
                    {/* Icon */}
                    <div
                      className={`mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-full ${style.bgColor} ${style.iconColor} transition-colors`}
                    >
                      <Icon className="h-3.5 w-3.5" />
                    </div>

                    {/* Content */}
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <span className="text-sm font-medium truncate">{actorDisplay}</span>
                          </TooltipTrigger>
                          <TooltipContent>{actorDisplay}</TooltipContent>
                        </Tooltip>
                        <span className="text-xs text-muted-foreground">{formatAction(activity.action)}</span>
                      </div>
                      {activity.targetLabel && (
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <p className="mt-0.5 text-xs text-muted-foreground truncate">
                              {activity.targetLabel}
                            </p>
                          </TooltipTrigger>
                          <TooltipContent>{activity.targetLabel}</TooltipContent>
                        </Tooltip>
                      )}
                    </div>

                    {/* Timestamp */}
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <span className="mt-0.5 shrink-0 text-[11px] tabular-nums text-muted-foreground">
                          {formatRelativeTimeShort(activity.createdAt)}
                        </span>
                      </TooltipTrigger>
                      <TooltipContent side="left" className="text-xs">
                        {formatDateTime(activity.createdAt)}
                      </TooltipContent>
                    </Tooltip>
                  </div>
                )
              })}
            </div>
          </TooltipProvider>
        )}
      </CardContent>
      <CardFooter className="border-t pt-4">
        <Link
          to="/admin/audit"
          className="group inline-flex items-center gap-1.5 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground"
        >
          View all activity
          <ArrowRight className="h-3.5 w-3.5 transition-transform group-hover:translate-x-0.5" />
        </Link>
      </CardFooter>
    </Card>
  )
}
