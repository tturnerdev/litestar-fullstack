import { createFileRoute } from "@tanstack/react-router"
import {
  AlertTriangle,
  Bell,
  BellOff,
  CheckCheck,
  ChevronLeft,
  ChevronRight,
  Laptop,
  Loader2,
  Mail,
  MessageSquare,
  Phone,
  Printer,
  Settings,
  Trash2,
  Users,
} from "lucide-react"
import { useState } from "react"
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
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Separator } from "@/components/ui/separator"
import { Switch } from "@/components/ui/switch"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import {
  type NotificationItem,
  useDeleteAllRead,
  useDeleteNotification,
  useMarkAllRead,
  useMarkRead,
  useNotificationPreferences,
  useNotifications,
  useUnreadCount,
  useUpdateNotificationPreferences,
} from "@/lib/api/hooks/notifications"
import { Skeleton, SkeletonCard } from "@/components/ui/skeleton"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { cn } from "@/lib/utils"

export const Route = createFileRoute("/_app/notifications/")({
  component: NotificationsPage,
})

const CATEGORIES = [
  { value: "all", label: "All" },
  { value: "system", label: "System" },
  { value: "team", label: "Team" },
  { value: "ticket", label: "Ticket" },
  { value: "device", label: "Device" },
  { value: "voice", label: "Voice" },
  { value: "fax", label: "Fax" },
] as const

const categoryIcons: Record<string, typeof Bell> = {
  ticket: MessageSquare,
  team: Users,
  device: Laptop,
  system: Settings,
  voice: Phone,
  fax: Printer,
}

function getCategoryIcon(category: string) {
  return categoryIcons[category] ?? Bell
}

function getCategoryColor(category: string) {
  switch (category) {
    case "ticket":
    case "support":
      return "text-blue-500"
    case "team":
    case "teams":
      return "text-purple-500"
    case "device":
    case "devices":
      return "text-green-500"
    case "system":
      return "text-orange-500"
    case "voice":
      return "text-cyan-500"
    case "fax":
      return "text-amber-500"
    default:
      return "text-muted-foreground"
  }
}

function NotificationCard({ notification, onRequestDelete }: { notification: NotificationItem; onRequestDelete: (id: string) => void }) {
  const markRead = useMarkRead()
  const navigate = Route.useNavigate()

  const Icon = getCategoryIcon(notification.category)
  const colorClass = getCategoryColor(notification.category)

  const handleClick = () => {
    if (!notification.isRead) {
      markRead.mutate(notification.id)
    }
    if (notification.actionUrl) {
      navigate({ to: notification.actionUrl as "/" })
    }
  }

  const relativeTime = formatRelativeTimeShort(notification.createdAt)

  return (
    <Card
      hover
      className={cn(
        "group/card transition-all",
        !notification.isRead && "border-primary/20 bg-accent/30",
        notification.actionUrl && "cursor-pointer",
      )}
      onClick={handleClick}
    >
      <CardContent className="flex items-start gap-4 py-4">
        <div className={cn("flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-muted", colorClass)}>
          <Icon className="h-5 w-5" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <p className={cn("text-sm font-medium", !notification.isRead ? "text-foreground" : "text-muted-foreground")}>
              {notification.title}
            </p>
            {!notification.isRead && <span className="h-2 w-2 shrink-0 rounded-full bg-primary" />}
            <Badge variant="outline" className="ml-auto shrink-0 text-[0.6rem] capitalize">
              {notification.category}
            </Badge>
          </div>
          <p className="mt-0.5 text-sm text-muted-foreground">{notification.message}</p>
          <Tooltip>
            <TooltipTrigger asChild>
              <p className="mt-1 cursor-default text-xs text-muted-foreground/70">{relativeTime}</p>
            </TooltipTrigger>
            <TooltipContent>{formatDateTime(notification.createdAt)}</TooltipContent>
          </Tooltip>
        </div>
        {notification.actionUrl && (
          <ChevronRight className="mt-1 h-4 w-4 shrink-0 text-muted-foreground/0 transition-colors group-hover/card:text-muted-foreground" />
        )}
        <div className="flex shrink-0 items-center gap-1">
          {!notification.isRead && (
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8 text-muted-foreground hover:text-foreground"
              onClick={(e) => {
                e.stopPropagation()
                markRead.mutate(notification.id)
              }}
              title="Mark as read"
              aria-label="Mark as read"
            >
              <CheckCheck className="h-4 w-4" />
            </Button>
          )}
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8 text-muted-foreground hover:text-destructive"
            onClick={(e) => {
              e.stopPropagation()
              onRequestDelete(notification.id)
            }}
            title="Delete"
            aria-label="Delete notification"
          >
            <Trash2 className="h-4 w-4" />
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}

const PREFERENCE_CATEGORIES = [
  { key: "system", label: "System", description: "System alerts and maintenance updates", icon: Settings },
  { key: "teams", label: "Teams", description: "Team invitations and membership changes", icon: Users },
  { key: "support", label: "Support", description: "Support ticket updates and replies", icon: MessageSquare },
  { key: "devices", label: "Devices", description: "Device status and provisioning alerts", icon: Laptop },
  { key: "voice", label: "Voice", description: "Call routing and voicemail notifications", icon: Phone },
  { key: "fax", label: "Fax", description: "Inbound and outbound fax notifications", icon: Printer },
] as const

function NotificationPreferences() {
  const { data: prefs, isLoading } = useNotificationPreferences()
  const updatePrefs = useUpdateNotificationPreferences()

  if (isLoading) {
    return <SkeletonCard />
  }

  if (!prefs) return null

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <Settings className="h-5 w-5 text-muted-foreground" />
          <div>
            <CardTitle className="text-lg">Notification Preferences</CardTitle>
            <CardDescription>Choose how and when you receive notifications</CardDescription>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="flex items-center justify-between rounded-lg border p-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-full bg-primary/10">
              <Mail className="h-4 w-4 text-primary" />
            </div>
            <div>
              <Label htmlFor="email-toggle" className="text-sm font-medium">
                Email Notifications
              </Label>
              <p className="text-xs text-muted-foreground">Receive notification summaries via email</p>
            </div>
          </div>
          <Switch
            id="email-toggle"
            checked={prefs.emailEnabled}
            onCheckedChange={(checked) => updatePrefs.mutate({ emailEnabled: checked })}
          />
        </div>

        <Separator />

        <div className="space-y-1">
          <h4 className="text-sm font-medium">Category Preferences</h4>
          <p className="text-xs text-muted-foreground">Enable or disable notifications by category</p>
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          {PREFERENCE_CATEGORIES.map(({ key, label, description, icon: Icon }) => (
            <div
              key={key}
              className="flex items-center justify-between rounded-lg border p-3 transition-colors hover:bg-accent/50"
            >
              <div className="flex items-center gap-3">
                <div className={cn("flex h-8 w-8 items-center justify-center rounded-full bg-muted", getCategoryColor(key))}>
                  <Icon className="h-4 w-4" />
                </div>
                <div>
                  <Label htmlFor={`cat-${key}`} className="text-sm font-medium">
                    {label}
                  </Label>
                  <p className="text-xs text-muted-foreground">{description}</p>
                </div>
              </div>
              <Switch
                id={`cat-${key}`}
                checked={prefs.categories[key] ?? true}
                onCheckedChange={(checked) =>
                  updatePrefs.mutate({ categories: { [key]: checked } })
                }
              />
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}

function NotificationsPage() {
  useDocumentTitle("Notifications")
  const [page, setPage] = useState(1)
  const [activeCategory, setActiveCategory] = useState<string>("all")
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false)
  const [deleteId, setDeleteId] = useState<string | null>(null)
  const pageSize = 20

  const { data: unreadData } = useUnreadCount()
  const { data, isLoading } = useNotifications(page, pageSize)
  const markAllRead = useMarkAllRead()
  const deleteAllRead = useDeleteAllRead()
  const deleteNotification = useDeleteNotification()

  const unreadCount = unreadData?.count ?? 0
  const notifications = data?.items ?? []
  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  const readCount = notifications.filter((n) => n.isRead).length

  const filteredNotifications =
    activeCategory === "all" ? notifications : notifications.filter((n) => n.category === activeCategory)

  const categoryCounts = notifications.reduce<Record<string, number>>((acc, n) => {
    acc[n.category] = (acc[n.category] ?? 0) + 1
    return acc
  }, {})

  const hasAnyNotifications = total > 0
  const isEmptyUnfiltered = !isLoading && !hasAnyNotifications
  const isEmptyFiltered = !isLoading && hasAnyNotifications && filteredNotifications.length === 0

  return (
    <PageContainer>
      <PageHeader
        eyebrow="Account"
        title="Notifications"
        description={unreadCount > 0 ? `You have ${unreadCount} unread notification${unreadCount !== 1 ? "s" : ""}` : "You're all caught up"}
        actions={
          <div className="flex gap-2">
            {readCount > 0 && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => setDeleteConfirmOpen(true)}
                disabled={deleteAllRead.isPending}
                className="text-destructive hover:text-destructive"
              >
                <Trash2 className="mr-2 h-4 w-4" />
                Delete all read
              </Button>
            )}
            {unreadCount > 0 && (
              <Button variant="outline" size="sm" onClick={() => markAllRead.mutate()} disabled={markAllRead.isPending}>
                <CheckCheck className="mr-2 h-4 w-4" />
                Mark all as read
              </Button>
            )}
          </div>
        }
      />

      <PageSection delay={0.1}>
        {isEmptyUnfiltered ? (
          <div className="flex animate-in fade-in flex-col items-center justify-center py-24 text-center">
            <div className="mb-4 flex h-20 w-20 items-center justify-center rounded-full bg-muted">
              <BellOff className="h-10 w-10 text-muted-foreground/40" />
            </div>
            <h3 className="text-lg font-semibold text-foreground">No notifications yet</h3>
            <p className="mt-1 max-w-sm text-sm text-muted-foreground">
              You'll be notified when important events happen -- like team updates, device alerts, or support ticket replies.
            </p>
          </div>
        ) : (
          <>
            <div className="flex flex-wrap gap-2">
              {CATEGORIES.map(({ value, label }) => {
                const count = value === "all" ? notifications.length : (categoryCounts[value] ?? 0)
                const isActive = activeCategory === value
                return (
                  <Button
                    key={value}
                    variant={isActive ? "default" : "outline"}
                    size="sm"
                    onClick={() => {
                      setActiveCategory(value)
                      setPage(1)
                    }}
                    className="gap-1.5 text-xs"
                  >
                    {label}
                    {count > 0 && (
                      <Badge
                        variant={isActive ? "secondary" : "outline"}
                        className={cn(
                          "ml-0.5 h-5 min-w-5 justify-center px-1.5 text-[0.6rem]",
                          isActive && "bg-primary-foreground/20 text-primary-foreground",
                        )}
                      >
                        {count}
                      </Badge>
                    )}
                  </Button>
                )
              })}
            </div>

            <div className="mt-4 space-y-3">
              {isLoading ? (
                <div className="space-y-3">
                  {Array.from({ length: 5 }).map((_, i) => (
                    <Skeleton key={i} className="h-16 w-full rounded-lg" />
                  ))}
                </div>
              ) : isEmptyFiltered ? (
                <div className="flex animate-in fade-in flex-col items-center justify-center py-16 text-center">
                  <Bell className="mb-3 h-12 w-12 text-muted-foreground/30" />
                  <p className="text-lg font-medium text-muted-foreground">No notifications</p>
                  <p className="text-sm text-muted-foreground/70">
                    No {activeCategory} notifications found
                  </p>
                </div>
              ) : (
                filteredNotifications.map((notification) => (
                  <NotificationCard key={notification.id} notification={notification} onRequestDelete={setDeleteId} />
                ))
              )}
            </div>

            {totalPages > 1 && (
              <div className="mt-6 flex items-center justify-center gap-4">
                <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
                  <ChevronLeft className="mr-1 h-4 w-4" />
                  Previous
                </Button>
                <span className="text-sm text-muted-foreground">
                  Page {page} of {totalPages}
                </span>
                <Button variant="outline" size="sm" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>
                  Next
                  <ChevronRight className="ml-1 h-4 w-4" />
                </Button>
              </div>
            )}
          </>
        )}
      </PageSection>

      <PageSection delay={0.2}>
        <NotificationPreferences />
      </PageSection>

      <AlertDialog open={deleteConfirmOpen} onOpenChange={setDeleteConfirmOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-full bg-destructive/10">
                <AlertTriangle className="h-5 w-5 text-destructive" />
              </div>
              <AlertDialogTitle>Delete all read notifications</AlertDialogTitle>
            </div>
            <AlertDialogDescription>
              This will permanently delete {readCount} read notification{readCount !== 1 ? "s" : ""}. This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setDeleteConfirmOpen(false)} disabled={deleteAllRead.isPending}>
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                deleteAllRead.mutate(undefined, {
                  onSuccess: () => setDeleteConfirmOpen(false),
                })
              }}
              disabled={deleteAllRead.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteAllRead.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Delete {readCount} notification{readCount !== 1 ? "s" : ""}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Delete single notification confirmation */}
      <AlertDialog open={!!deleteId} onOpenChange={(open) => !open && setDeleteId(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete notification</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete this notification? This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setDeleteId(null)} disabled={deleteNotification.isPending}>
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (!deleteId) return
                deleteNotification.mutate(deleteId, {
                  onSuccess: () => setDeleteId(null),
                })
              }}
              disabled={deleteNotification.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteNotification.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </PageContainer>
  )
}
