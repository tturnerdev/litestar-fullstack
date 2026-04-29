import { createFileRoute } from "@tanstack/react-router"
import {
  Bell,
  CheckCheck,
  ChevronLeft,
  ChevronRight,
  Laptop,
  MessageSquare,
  Phone,
  Printer,
  Settings,
  Trash2,
  Users,
} from "lucide-react"
import { useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import {
  type NotificationItem,
  useDeleteNotification,
  useMarkAllRead,
  useMarkRead,
  useNotifications,
  useUnreadCount,
} from "@/lib/api/hooks/notifications"
import { cn } from "@/lib/utils"

function timeAgo(dateStr: string): string {
  const seconds = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000)
  if (seconds < 60) return "just now"
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  if (days < 7) return `${days}d ago`
  const weeks = Math.floor(days / 7)
  if (weeks < 5) return `${weeks}w ago`
  const months = Math.floor(days / 30)
  return `${months}mo ago`
}

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
      return "text-blue-500"
    case "team":
      return "text-purple-500"
    case "device":
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

function NotificationCard({ notification }: { notification: NotificationItem }) {
  const markRead = useMarkRead()
  const deleteNotification = useDeleteNotification()
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

  const relativeTime = timeAgo(notification.createdAt)

  return (
    <Card
      hover
      className={cn(
        "transition-all",
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
          <p className="mt-1 text-xs text-muted-foreground/70">{relativeTime}</p>
        </div>
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
              deleteNotification.mutate(notification.id)
            }}
            title="Delete"
          >
            <Trash2 className="h-4 w-4" />
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}

function NotificationsPage() {
  const [page, setPage] = useState(1)
  const [activeCategory, setActiveCategory] = useState<string>("all")
  const pageSize = 20

  const { data: unreadData } = useUnreadCount()
  const { data, isLoading } = useNotifications(page, pageSize)
  const markAllRead = useMarkAllRead()

  const unreadCount = unreadData?.count ?? 0
  const notifications = data?.items ?? []
  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / pageSize))

  const filteredNotifications =
    activeCategory === "all" ? notifications : notifications.filter((n) => n.category === activeCategory)

  return (
    <PageContainer>
      <PageHeader
        eyebrow="Account"
        title="Notifications"
        description={unreadCount > 0 ? `You have ${unreadCount} unread notification${unreadCount !== 1 ? "s" : ""}` : "You're all caught up"}
        actions={
          unreadCount > 0 ? (
            <Button variant="outline" size="sm" onClick={() => markAllRead.mutate()} disabled={markAllRead.isPending}>
              <CheckCheck className="mr-2 h-4 w-4" />
              Mark all as read
            </Button>
          ) : undefined
        }
      />

      <PageSection delay={0.1}>
        <div className="flex flex-wrap gap-2">
          {CATEGORIES.map(({ value, label }) => (
            <Button
              key={value}
              variant={activeCategory === value ? "default" : "outline"}
              size="sm"
              onClick={() => {
                setActiveCategory(value)
                setPage(1)
              }}
              className="text-xs"
            >
              {label}
            </Button>
          ))}
        </div>

        <div className="mt-4 space-y-3">
          {isLoading ? (
            <div className="flex items-center justify-center py-16">
              <div className="h-6 w-6 animate-spin rounded-full border-2 border-muted-foreground border-t-transparent" />
            </div>
          ) : filteredNotifications.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-center">
              <Bell className="mb-3 h-12 w-12 text-muted-foreground/30" />
              <p className="text-lg font-medium text-muted-foreground">No notifications</p>
              <p className="text-sm text-muted-foreground/70">
                {activeCategory !== "all" ? `No ${activeCategory} notifications found` : "You're all caught up"}
              </p>
            </div>
          ) : (
            filteredNotifications.map((notification) => (
              <NotificationCard key={notification.id} notification={notification} />
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
      </PageSection>
    </PageContainer>
  )
}
