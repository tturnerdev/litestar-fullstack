import { AnimatePresence, motion } from "framer-motion"
import { Bell, Headphones, Mail, Monitor, Phone, Printer, Server, Users } from "lucide-react"
import { useCallback } from "react"
import { toast } from "sonner"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Label } from "@/components/ui/label"
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { cn } from "@/lib/utils"
import { useNotificationPreferences, useUpdateNotificationPreferences } from "@/lib/api/hooks/notifications"

const CATEGORY_CONFIG = [
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

export function NotificationPreferences() {
  const { data: preferences, isLoading, isError } = useNotificationPreferences()
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
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-destructive/10">
              <Bell className="h-4 w-4 text-destructive" />
            </div>
            Notification Preferences
          </CardTitle>
          <CardDescription>Configure which notifications you receive</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="rounded-lg border border-destructive/20 bg-destructive/5 p-4">
            <p className="text-sm text-muted-foreground">Unable to load notification preferences. Please try again later.</p>
          </div>
        </CardContent>
      </Card>
    )
  }

  const emailEnabled = preferences.emailEnabled
  const enabledCount = CATEGORY_CONFIG.filter(({ key }) => (preferences.categories[key] ?? true) && emailEnabled).length

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between">
          <div className="flex items-start gap-3">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-500/10">
              <Bell className="h-4 w-4 text-emerald-500" />
            </div>
            <div>
              <CardTitle>Notification Preferences</CardTitle>
              <CardDescription className="mt-1">Configure which notifications you receive via email</CardDescription>
            </div>
          </div>
          {emailEnabled && (
            <span className="rounded-full bg-emerald-500/10 px-2.5 py-0.5 text-xs font-medium text-emerald-600 dark:text-emerald-400">
              {enabledCount} of {CATEGORY_CONFIG.length} active
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
            {CATEGORY_CONFIG.map(({ key, label, description, icon: Icon, color, bgColor }) => {
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
