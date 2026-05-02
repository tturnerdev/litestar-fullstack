import { AnimatePresence, motion } from "framer-motion"
import {
  AlertCircle,
  Bell,
  HardDrive,
  Headphones,
  ListTodo,
  Lock,
  Mail,
  Monitor,
  Phone,
  Printer,
  Server,
  Shield,
  Users,
} from "lucide-react"
import type { LucideIcon } from "lucide-react"
import { useCallback } from "react"
import { toast } from "sonner"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { EmptyState } from "@/components/ui/empty-state"
import { Label } from "@/components/ui/label"
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { cn } from "@/lib/utils"
import { useNotificationPreferences, useUpdateNotificationPreferences } from "@/lib/api/hooks/notifications"
import {
  type NotificationPreferencesState,
  useNotificationPreferencesStore,
} from "@/lib/notification-preferences-store"

const EMAIL_CATEGORY_CONFIG = [
  {
    key: "teams",
    label: "Teams",
    description: "Team invitations, member changes, and updates",
    icon: Users,
    color: "text-violet-500",
    bgColor: "bg-violet-500/10",
  },
  {
    key: "devices",
    label: "Devices",
    description: "Device status changes and alerts",
    icon: Monitor,
    color: "text-blue-500",
    bgColor: "bg-blue-500/10",
  },
  {
    key: "voice",
    label: "Voice",
    description: "Call notifications, voicemail, and extensions",
    icon: Phone,
    color: "text-green-500",
    bgColor: "bg-green-500/10",
  },
  {
    key: "fax",
    label: "Fax",
    description: "Incoming and outgoing fax notifications",
    icon: Printer,
    color: "text-orange-500",
    bgColor: "bg-orange-500/10",
  },
  {
    key: "support",
    label: "Support",
    description: "Ticket updates and support responses",
    icon: Headphones,
    color: "text-pink-500",
    bgColor: "bg-pink-500/10",
  },
  {
    key: "system",
    label: "System",
    description: "Security alerts, password resets, and account changes",
    icon: Server,
    color: "text-red-500",
    bgColor: "bg-red-500/10",
  },
] as const

/* -----------------------------------------------------------------------
 * In-app notification category configuration
 * ----------------------------------------------------------------------- */

interface InAppCategory {
  key: keyof NotificationPreferencesState
  label: string
  description: string
  icon: LucideIcon
  color: string
  bgColor: string
  locked: boolean
}

const IN_APP_CATEGORY_CONFIG: InAppCategory[] = [
  {
    key: "systemAlerts",
    label: "System Alerts",
    description: "Critical system notifications and service status updates",
    icon: Bell,
    color: "text-red-500",
    bgColor: "bg-red-500/10",
    locked: true,
  },
  {
    key: "taskUpdates",
    label: "Task Updates",
    description: "Background task completion and failure notifications",
    icon: ListTodo,
    color: "text-blue-500",
    bgColor: "bg-blue-500/10",
    locked: false,
  },
  {
    key: "teamActivity",
    label: "Team Activity",
    description: "Member joins, leaves, and role changes",
    icon: Users,
    color: "text-violet-500",
    bgColor: "bg-violet-500/10",
    locked: false,
  },
  {
    key: "supportTickets",
    label: "Support Tickets",
    description: "New tickets, status changes, and assignments",
    icon: Headphones,
    color: "text-pink-500",
    bgColor: "bg-pink-500/10",
    locked: false,
  },
  {
    key: "deviceAlerts",
    label: "Device Alerts",
    description: "Device offline/online status and firmware updates",
    icon: HardDrive,
    color: "text-amber-500",
    bgColor: "bg-amber-500/10",
    locked: false,
  },
  {
    key: "security",
    label: "Security",
    description: "Login attempts, MFA changes, and session activity",
    icon: Shield,
    color: "text-emerald-500",
    bgColor: "bg-emerald-500/10",
    locked: false,
  },
]

/* -----------------------------------------------------------------------
 * Main component
 * ----------------------------------------------------------------------- */

export function NotificationPreferences() {
  return (
    <div className="space-y-6">
      <EmailNotificationPreferences />
      <InAppNotificationPreferences />
    </div>
  )
}

/* -----------------------------------------------------------------------
 * Email notification preferences (API-backed)
 * ----------------------------------------------------------------------- */

function EmailNotificationPreferences() {
  const { data: preferences, isLoading, isError, refetch } = useNotificationPreferences()
  const { mutate: updatePreferences } = useUpdateNotificationPreferences()

  const handleMasterToggle = useCallback(
    (checked: boolean) => {
      updatePreferences({ emailEnabled: checked })
      toast.success(checked ? "Email notifications enabled" : "Email notifications disabled")
    },
    [updatePreferences],
  )

  const handleCategoryToggle = useCallback(
    (category: string, label: string, checked: boolean) => {
      updatePreferences({ categories: { [category]: checked } })
      toast.success(`${label} notifications ${checked ? "enabled" : "disabled"}`)
    },
    [updatePreferences],
  )

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Skeleton className="h-8 w-8 rounded-lg" />
            <div className="space-y-1.5">
              <Skeleton className="h-5 w-48" />
              <Skeleton className="h-4 w-64" />
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="flex items-center justify-between rounded-lg border border-border/60 p-4">
              <div className="flex items-center gap-3">
                <Skeleton className="h-8 w-8 rounded-lg" />
                <div className="space-y-1.5">
                  <Skeleton className="h-4 w-24" />
                  <Skeleton className="h-3 w-48" />
                </div>
              </div>
              <Skeleton className="h-5 w-9 rounded-full" />
            </div>
          ))}
        </CardContent>
      </Card>
    )
  }

  if (isError || !preferences) {
    return (
      <EmptyState
        icon={AlertCircle}
        title="Unable to load notification preferences"
        description="Something went wrong. Please try again."
        action={<Button variant="outline" size="sm" onClick={() => refetch()}>Try again</Button>}
      />
    )
  }

  const emailEnabled = preferences.emailEnabled
  const enabledCount = EMAIL_CATEGORY_CONFIG.filter(({ key }) => (preferences.categories[key] ?? true) && emailEnabled).length

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between">
          <div className="flex items-start gap-3">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-500/10">
              <Bell className="h-4 w-4 text-emerald-500" />
            </div>
            <div>
              <CardTitle>Email Notifications</CardTitle>
              <CardDescription className="mt-1">Configure which notifications you receive via email</CardDescription>
            </div>
          </div>
          {emailEnabled && (
            <span className="rounded-full bg-emerald-500/10 px-2.5 py-0.5 text-xs font-medium text-emerald-600 dark:text-emerald-400">
              {enabledCount} of {EMAIL_CATEGORY_CONFIG.length} active
            </span>
          )}
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Master toggle */}
        <div className="flex items-center justify-between rounded-lg border border-border/60 bg-muted/30 p-4">
          <div className="flex items-center gap-3">
            <div className={cn("flex h-8 w-8 items-center justify-center rounded-lg", emailEnabled ? "bg-emerald-500/10" : "bg-muted")}>
              <Mail className={cn("h-4 w-4", emailEnabled ? "text-emerald-500" : "text-muted-foreground")} />
            </div>
            <div className="space-y-0.5">
              <Label htmlFor="email-enabled" className="text-sm font-medium">
                Email notifications
              </Label>
              <p className="text-xs text-muted-foreground">Master toggle for all email notifications</p>
            </div>
          </div>
          <Switch id="email-enabled" checked={emailEnabled} onCheckedChange={handleMasterToggle} />
        </div>

        <Separator />

        {/* Per-category toggles */}
        <div className="space-y-2">
          <p className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">Categories</p>
          <AnimatePresence>
            {EMAIL_CATEGORY_CONFIG.map(({ key, label, description, icon: Icon, color, bgColor }) => {
              const enabled = (preferences.categories[key] ?? true) && emailEnabled
              return (
                <motion.div
                  key={key}
                  layout
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  className={cn(
                    "flex items-center justify-between rounded-lg border p-4 transition-colors",
                    !emailEnabled ? "border-border/30 opacity-60" : enabled ? "border-border/60" : "border-border/40",
                  )}
                >
                  <div className="flex items-center gap-3">
                    <div className={cn("flex h-8 w-8 shrink-0 items-center justify-center rounded-lg", emailEnabled ? bgColor : "bg-muted")}>
                      <Icon className={cn("h-4 w-4", emailEnabled ? color : "text-muted-foreground")} />
                    </div>
                    <div className="space-y-0.5">
                      <Label
                        htmlFor={`category-${key}`}
                        className={cn("text-sm font-medium", !emailEnabled && "text-muted-foreground")}
                      >
                        {label}
                      </Label>
                      <p className="text-xs text-muted-foreground">{description}</p>
                    </div>
                  </div>
                  <Switch
                    id={`category-${key}`}
                    checked={enabled}
                    disabled={!emailEnabled}
                    onCheckedChange={(checked) => handleCategoryToggle(key, label, checked)}
                  />
                </motion.div>
              )
            })}
          </AnimatePresence>
        </div>
      </CardContent>
    </Card>
  )
}

/* -----------------------------------------------------------------------
 * In-app notification preferences (localStorage-backed)
 * ----------------------------------------------------------------------- */

function InAppNotificationPreferences() {
  const store = useNotificationPreferencesStore()

  const enabledCount = IN_APP_CATEGORY_CONFIG.filter(({ key }) => store[key]).length

  const handleToggle = useCallback(
    (key: keyof NotificationPreferencesState, label: string, checked: boolean) => {
      store.setPreference(key, checked)
      toast.success(`${label} notifications ${checked ? "enabled" : "disabled"}`)
    },
    [store],
  )

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between">
          <div className="flex items-start gap-3">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-500/10">
              <Bell className="h-4 w-4 text-blue-500" />
            </div>
            <div>
              <CardTitle>Notification Preferences</CardTitle>
              <CardDescription className="mt-1">
                Control which in-app notification categories are shown to you
              </CardDescription>
            </div>
          </div>
          <span className="rounded-full bg-blue-500/10 px-2.5 py-0.5 text-xs font-medium text-blue-600 dark:text-blue-400">
            {enabledCount} of {IN_APP_CATEGORY_CONFIG.length} active
          </span>
        </div>
      </CardHeader>
      <CardContent>
        <div className="space-y-2">
          <AnimatePresence>
            {IN_APP_CATEGORY_CONFIG.map(({ key, label, description, icon: Icon, color, bgColor, locked }) => {
              const enabled = store[key]
              return (
                <motion.div
                  key={key}
                  layout
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  className={cn(
                    "flex items-center justify-between rounded-lg border p-4 transition-colors",
                    locked
                      ? "border-border/40 bg-muted/20"
                      : enabled
                        ? "border-border/60"
                        : "border-border/40",
                  )}
                >
                  <div className="flex items-center gap-3">
                    <div className={cn("flex h-8 w-8 shrink-0 items-center justify-center rounded-lg", bgColor)}>
                      <Icon className={cn("h-4 w-4", color)} />
                    </div>
                    <div className="space-y-0.5">
                      <Label
                        htmlFor={`inapp-${key}`}
                        className="flex items-center gap-1.5 text-sm font-medium"
                      >
                        {label}
                        {locked && (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Badge variant="secondary" className="gap-1 px-1.5 py-0 text-[0.625rem] font-normal">
                                <Lock className="h-2.5 w-2.5" />
                                Required
                              </Badge>
                            </TooltipTrigger>
                            <TooltipContent>
                              System alerts cannot be disabled for safety reasons
                            </TooltipContent>
                          </Tooltip>
                        )}
                      </Label>
                      <p className="text-xs text-muted-foreground">{description}</p>
                    </div>
                  </div>
                  {locked ? (
                    <Switch
                      id={`inapp-${key}`}
                      checked
                      disabled
                      aria-label={`${label} notifications (always enabled)`}
                    />
                  ) : (
                    <Switch
                      id={`inapp-${key}`}
                      checked={enabled}
                      onCheckedChange={(checked) => handleToggle(key, label, checked)}
                    />
                  )}
                </motion.div>
              )
            })}
          </AnimatePresence>
        </div>
      </CardContent>
    </Card>
  )
}
