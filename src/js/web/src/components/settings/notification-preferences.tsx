import { Bell, Headphones, Monitor, Phone, Printer, Server, Users } from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Label } from "@/components/ui/label"
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { useNotificationPreferences, useUpdateNotificationPreferences } from "@/lib/api/hooks/notifications"

const CATEGORY_CONFIG = [
  { key: "teams", label: "Teams", description: "Team invitations, member changes, and updates", icon: Users },
  { key: "devices", label: "Devices", description: "Device status changes and alerts", icon: Monitor },
  { key: "voice", label: "Voice", description: "Call notifications, voicemail, and extensions", icon: Phone },
  { key: "fax", label: "Fax", description: "Incoming and outgoing fax notifications", icon: Printer },
  { key: "support", label: "Support", description: "Ticket updates and support responses", icon: Headphones },
  { key: "system", label: "System", description: "Security alerts, password resets, and account changes", icon: Server },
] as const

export function NotificationPreferences() {
  const { data: preferences, isLoading, isError } = useNotificationPreferences()
  const { mutate: updatePreferences } = useUpdateNotificationPreferences()

  const handleMasterToggle = (checked: boolean) => {
    updatePreferences({ emailEnabled: checked })
  }

  const handleCategoryToggle = (category: string, checked: boolean) => {
    updatePreferences({ categories: { [category]: checked } })
  }

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Notification Preferences</CardTitle>
          <CardDescription>Configure which notifications you receive</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="flex items-center justify-between">
              <Skeleton className="h-4 w-48" />
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
          <CardTitle className="text-lg">Notification Preferences</CardTitle>
          <CardDescription>Configure which notifications you receive</CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">Unable to load notification preferences. Please try again later.</p>
        </CardContent>
      </Card>
    )
  }

  const emailEnabled = preferences.emailEnabled

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-lg">
          <Bell className="h-5 w-5" />
          Notification Preferences
        </CardTitle>
        <CardDescription>Configure which notifications you receive via email</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Master toggle */}
        <div className="flex items-center justify-between">
          <div className="space-y-0.5">
            <Label htmlFor="email-enabled" className="text-sm font-medium">
              Enable notifications
            </Label>
            <p className="text-xs text-muted-foreground">
              Master toggle for all email notifications
            </p>
          </div>
          <Switch
            id="email-enabled"
            checked={emailEnabled}
            onCheckedChange={handleMasterToggle}
          />
        </div>

        <Separator />

        {/* Per-category toggles */}
        <div className="space-y-4">
          <p className="text-sm font-medium text-muted-foreground">Categories</p>
          {CATEGORY_CONFIG.map(({ key, label, description, icon: Icon }) => {
            const enabled = preferences.categories[key] ?? true
            return (
              <div
                key={key}
                className="flex items-center justify-between"
              >
                <div className="flex items-start gap-3">
                  <div className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-muted">
                    <Icon className="h-4 w-4 text-muted-foreground" />
                  </div>
                  <div className="space-y-0.5">
                    <Label
                      htmlFor={`category-${key}`}
                      className={`text-sm font-medium ${!emailEnabled ? "text-muted-foreground" : ""}`}
                    >
                      {label}
                    </Label>
                    <p className="text-xs text-muted-foreground">{description}</p>
                  </div>
                </div>
                <Switch
                  id={`category-${key}`}
                  checked={enabled && emailEnabled}
                  disabled={!emailEnabled}
                  onCheckedChange={(checked) => handleCategoryToggle(key, checked)}
                />
              </div>
            )
          })}
        </div>
      </CardContent>
    </Card>
  )
}
