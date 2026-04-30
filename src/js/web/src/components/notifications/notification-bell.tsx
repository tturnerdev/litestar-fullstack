import { useNavigate } from "@tanstack/react-router"
import {
  Bell,
  CheckCheck,
  Laptop,
  MessageSquare,
  Phone,
  Printer,
  Settings,
  Users,
  X,
} from "lucide-react"
import { useEffect, useRef, useState } from "react"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
  type NotificationItem,
  useDeleteNotification,
  useMarkAllRead,
  useMarkRead,
  useNotifications,
  useUnreadCount,
} from "@/lib/api/hooks/notifications"
import { cn } from "@/lib/utils"

const bellAnimationStyles = `
@keyframes bell-ring {
  0% { transform: rotate(0deg); }
  10% { transform: rotate(14deg); }
  20% { transform: rotate(-12deg); }
  30% { transform: rotate(10deg); }
  40% { transform: rotate(-8deg); }
  50% { transform: rotate(6deg); }
  60% { transform: rotate(-4deg); }
  70% { transform: rotate(2deg); }
  80% { transform: rotate(-1deg); }
  90% { transform: rotate(0.5deg); }
  100% { transform: rotate(0deg); }
}
@keyframes badge-pulse {
  0%, 100% { transform: scale(1); opacity: 1; }
  50% { transform: scale(1.2); opacity: 0.85; }
}
.bell-ring {
  animation: bell-ring 0.8s ease-in-out;
  transform-origin: top center;
}
.bell-has-unread {
  animation: bell-ring 1s ease-in-out infinite;
  animation-delay: 3s;
  animation-iteration-count: 1;
  transform-origin: top center;
}
.badge-pulse-new {
  animation: badge-pulse 1.5s ease-in-out 3;
}
` as const

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

function NotificationRow({
  notification,
  onClose,
}: {
  notification: NotificationItem
  onClose: () => void
}) {
  const navigate = useNavigate()
  const markRead = useMarkRead()
  const deleteNotification = useDeleteNotification()

  const Icon = getCategoryIcon(notification.category)
  const colorClass = getCategoryColor(notification.category)

  const handleClick = () => {
    if (!notification.isRead) {
      markRead.mutate(notification.id)
    }
    if (notification.actionUrl) {
      onClose()
      navigate({ to: notification.actionUrl as "/" })
    }
  }

  const handleDelete = (e: React.MouseEvent) => {
    e.stopPropagation()
    deleteNotification.mutate(notification.id)
  }

  const relativeTime = timeAgo(notification.createdAt)

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={handleClick}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          handleClick()
        }
      }}
      className={cn(
        "group flex items-start gap-3 rounded-md px-3 py-2.5 text-left transition-colors hover:bg-accent",
        !notification.isRead && "bg-accent/40",
        notification.actionUrl && "cursor-pointer",
      )}
    >
      <div className={cn("mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-muted", colorClass)}>
        <Icon className="h-4 w-4" />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <p className={cn("truncate text-sm font-medium", !notification.isRead && "text-foreground", notification.isRead && "text-muted-foreground")}>
            {notification.title}
          </p>
          {!notification.isRead && <span className="h-2 w-2 shrink-0 rounded-full bg-primary" />}
        </div>
        <p className="line-clamp-2 text-xs text-muted-foreground">{notification.message}</p>
        <p className="mt-0.5 text-[0.65rem] text-muted-foreground/70">{relativeTime}</p>
      </div>
      <button
        type="button"
        onClick={handleDelete}
        className="mt-0.5 shrink-0 rounded p-1 opacity-0 transition-opacity hover:bg-destructive/10 hover:text-destructive group-hover:opacity-100"
        title="Delete notification"
      >
        <X className="h-3 w-3" />
      </button>
    </div>
  )
}

export function NotificationBell() {
  const [open, setOpen] = useState(false)
  const { data: unreadData } = useUnreadCount()
  const { data: notificationsData, isLoading } = useNotifications(1, 10)
  const markAllRead = useMarkAllRead()
  const navigate = useNavigate()

  const unreadCount = unreadData?.count ?? 0
  const notifications = notificationsData?.items ?? []

  // Track previous unread count to trigger pulse animation on new arrivals
  const prevUnreadRef = useRef(unreadCount)
  const [pulseKey, setPulseKey] = useState(0)

  useEffect(() => {
    if (unreadCount > prevUnreadRef.current) {
      setPulseKey((k) => k + 1)
    }
    prevUnreadRef.current = unreadCount
  }, [unreadCount])

  return (
    <DropdownMenu open={open} onOpenChange={setOpen}>
      {/* Inject animation keyframes */}
      <style dangerouslySetInnerHTML={{ __html: bellAnimationStyles }} />

      <DropdownMenuTrigger asChild>
        <button
          type="button"
          className="relative flex h-9 w-9 items-center justify-center rounded-full text-muted-foreground transition-colors hover:bg-accent hover:text-accent-foreground focus:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          aria-label={`Notifications${unreadCount > 0 ? ` (${unreadCount} unread)` : ""}`}
        >
          <Bell className={cn("h-5 w-5", unreadCount > 0 && "bell-has-unread")} />
          {unreadCount > 0 && (
            <span
              key={pulseKey}
              className={cn(
                "absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-destructive px-1 text-[0.6rem] font-bold leading-none text-destructive-foreground",
                pulseKey > 0 && "badge-pulse-new",
              )}
            >
              {unreadCount > 99 ? "99+" : unreadCount}
            </span>
          )}
        </button>
      </DropdownMenuTrigger>

      <DropdownMenuContent align="end" className="w-[380px] p-0" sideOffset={8}>
        <div className="flex items-center justify-between border-b px-4 py-3">
          <DropdownMenuLabel className="p-0 text-base font-semibold">Notifications</DropdownMenuLabel>
          {unreadCount > 0 && (
            <Button
              variant="ghost"
              size="sm"
              className="h-7 gap-1.5 text-xs text-muted-foreground"
              onClick={() => markAllRead.mutate()}
              disabled={markAllRead.isPending}
            >
              <CheckCheck className="h-3.5 w-3.5" />
              Mark all read
            </Button>
          )}
        </div>

        <div className="max-h-[400px] overflow-y-auto">
          {isLoading ? (
            <div className="flex items-center justify-center py-8">
              <div className="h-5 w-5 animate-spin rounded-full border-2 border-muted-foreground border-t-transparent" />
            </div>
          ) : notifications.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-8 text-center">
              <Bell className="mb-2 h-8 w-8 text-muted-foreground/40" />
              <p className="text-sm font-medium text-muted-foreground">No notifications</p>
              <p className="text-xs text-muted-foreground/70">You're all caught up</p>
            </div>
          ) : (
            <DropdownMenuGroup className="p-1">
              {notifications.map((notification) => (
                <NotificationRow key={notification.id} notification={notification} onClose={() => setOpen(false)} />
              ))}
            </DropdownMenuGroup>
          )}
        </div>

        {notifications.length > 0 && (
          <>
            <DropdownMenuSeparator className="m-0" />
            <div className="p-2">
              <Button
                variant="ghost"
                size="sm"
                className="w-full text-xs text-muted-foreground"
                onClick={() => {
                  setOpen(false)
                  navigate({ to: "/notifications" as "/" })
                }}
              >
                View all notifications
              </Button>
            </div>
          </>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
