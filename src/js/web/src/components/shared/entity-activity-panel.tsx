import { Clock, History, Minus, Plus, RefreshCw } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"
import { useTargetAuditLogs } from "@/lib/api/hooks/admin"
import type { AuditLogEntry } from "@/lib/generated/api"

// ── Helpers ────────────────────────────────────────────────────────────────

/** Derive the verb from an action string (e.g., "connection.updated" -> "updated"). */
function getActionVerb(action: string): string {
  const parts = action.split(".")
  return parts[parts.length - 1] ?? action
}

/** Map action verbs to badge styling. */
function getActionBadgeClasses(action: string): string {
  const verb = getActionVerb(action)
  switch (verb) {
    case "created":
    case "success":
    case "enabled":
    case "member_added":
    case "invite_sent":
      return "border-green-200 bg-green-50 text-green-700 dark:border-green-800 dark:bg-green-950 dark:text-green-300"
    case "updated":
    case "changed":
    case "role_changed":
    case "config_changed":
      return "border-blue-200 bg-blue-50 text-blue-700 dark:border-blue-800 dark:bg-blue-950 dark:text-blue-300"
    case "deleted":
    case "failed":
    case "disabled":
    case "member_removed":
      return "border-red-200 bg-red-50 text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-300"
    default:
      return "border-zinc-200 bg-zinc-50 text-zinc-700 dark:border-zinc-800 dark:bg-zinc-950 dark:text-zinc-300"
  }
}

/** Map action verb to a timeline dot color class. */
function getTimelineDotClass(action: string): string {
  const verb = getActionVerb(action)
  switch (verb) {
    case "created":
    case "success":
    case "enabled":
    case "member_added":
    case "invite_sent":
      return "bg-green-500"
    case "updated":
    case "changed":
    case "role_changed":
    case "config_changed":
      return "bg-blue-500"
    case "deleted":
    case "failed":
    case "disabled":
    case "member_removed":
      return "bg-red-500"
    default:
      return "bg-zinc-400"
  }
}

/** Map action verb to an icon. */
function ActionIcon({ action }: { action: string }) {
  const verb = getActionVerb(action)
  switch (verb) {
    case "created":
    case "success":
    case "enabled":
    case "member_added":
    case "invite_sent":
      return <Plus className="h-3 w-3" />
    case "deleted":
    case "failed":
    case "disabled":
    case "member_removed":
      return <Minus className="h-3 w-3" />
    default:
      return <RefreshCw className="h-3 w-3" />
  }
}

// ── Timeline Entry ─────────────────────────────────────────────────────────

function TimelineEntry({ entry }: { entry: AuditLogEntry }) {
  const changedFields = entry.details?.changed_fields as string[] | undefined
  const changedFieldsCamel = entry.details?.changedFields as string[] | undefined
  const fields = changedFields ?? changedFieldsCamel

  return (
    <div className="relative flex gap-3 pb-6 last:pb-0">
      {/* Timeline line */}
      <div className="flex flex-col items-center">
        <div
          className={`mt-1 flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-white ${getTimelineDotClass(entry.action)}`}
        >
          <ActionIcon action={entry.action} />
        </div>
        <div className="w-px flex-1 bg-border" />
      </div>

      {/* Content */}
      <div className="min-w-0 flex-1 space-y-1 pb-1">
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant="outline" className={`text-xs ${getActionBadgeClasses(entry.action)}`}>
            {entry.action}
          </Badge>
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="cursor-default text-xs text-muted-foreground">
                {formatRelativeTimeShort(entry.createdAt)}
              </span>
            </TooltipTrigger>
            <TooltipContent>{formatDateTime(entry.createdAt)}</TooltipContent>
          </Tooltip>
        </div>

        <p className="text-sm text-muted-foreground">
          {entry.actorName ? (
            <>
              <span className="font-medium text-foreground">{entry.actorName}</span>
              {entry.actorEmail && (
                <span className="text-xs"> ({entry.actorEmail})</span>
              )}
            </>
          ) : entry.actorEmail ? (
            <span className="font-medium text-foreground">{entry.actorEmail}</span>
          ) : (
            <span className="italic text-muted-foreground/60">System</span>
          )}
        </p>

        {fields && fields.length > 0 && (
          <div className="flex flex-wrap gap-1 pt-0.5">
            <span className="text-xs text-muted-foreground">Changed:</span>
            {fields.map((field) => (
              <Badge
                key={field}
                variant="outline"
                className="px-1.5 py-0 text-[10px] font-normal text-muted-foreground"
              >
                {field.replace(/_/g, " ")}
              </Badge>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ── Loading Skeleton ───────────────────────────────────────────────────────

function ActivitySkeleton() {
  return (
    <div className="space-y-4">
      {Array.from({ length: 4 }).map((_, i) => (
        <div key={i} className="flex gap-3">
          <Skeleton className="h-6 w-6 shrink-0 rounded-full" />
          <div className="flex-1 space-y-2">
            <div className="flex items-center gap-2">
              <Skeleton className="h-5 w-28 rounded-full" />
              <Skeleton className="h-3.5 w-14" />
            </div>
            <Skeleton className="h-4 w-40" />
          </div>
        </div>
      ))}
    </div>
  )
}

// ── Main Component ─────────────────────────────────────────────────────────

interface EntityActivityPanelProps {
  targetType: string
  targetId: string
  enabled?: boolean
}

export function EntityActivityPanel({
  targetType,
  targetId,
  enabled = true,
}: EntityActivityPanelProps) {
  const { data, isLoading, isError } = useTargetAuditLogs(targetType, targetId, {
    enabled,
  })

  if (isLoading) {
    return <ActivitySkeleton />
  }

  if (isError) {
    return (
      <div className="flex flex-col items-center justify-center py-8 text-center">
        <Clock className="mb-2 h-8 w-8 text-muted-foreground/40" />
        <p className="text-sm font-medium text-muted-foreground">Unable to load activity</p>
        <p className="text-xs text-muted-foreground/60">
          Something went wrong while fetching the audit trail.
        </p>
      </div>
    )
  }

  const items = data?.items ?? []

  if (items.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-8 text-center">
        <History className="mb-2 h-8 w-8 text-muted-foreground/40" />
        <p className="text-sm font-medium text-muted-foreground">No activity recorded</p>
        <p className="text-xs text-muted-foreground/60">
          Changes to this resource will appear here.
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-0">
      {items.map((entry) => (
        <TimelineEntry key={entry.id} entry={entry} />
      ))}
      {(data?.total ?? 0) > items.length && (
        <p className="pt-2 text-center text-xs text-muted-foreground">
          Showing {items.length} of {data?.total} entries
        </p>
      )}
    </div>
  )
}
