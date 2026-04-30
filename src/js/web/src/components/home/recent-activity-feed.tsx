import { Link } from "@tanstack/react-router"
import { ArrowRight, Bell, ChevronRight, Laptop, Phone, TicketCheck, Users } from "lucide-react"
import type { LucideIcon } from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { EmptyState } from "@/components/ui/empty-state"
import { useNotifications } from "@/lib/api/hooks/notifications"
import type { NotificationItem } from "@/lib/api/hooks/notifications"
import { formatRelativeTimeShort } from "@/lib/date-utils"

interface ActivityItem {
  id: string
  icon: LucideIcon
  iconColor: string
  title: string
  description: string
  timestamp: string
  link?: string
}

const categoryIcons: Record<string, { icon: LucideIcon; color: string }> = {
  team: { icon: Users, color: "text-blue-600 bg-blue-500/10 dark:text-blue-400" },
  device: { icon: Laptop, color: "text-emerald-600 bg-emerald-500/10 dark:text-emerald-400" },
  support: { icon: TicketCheck, color: "text-amber-600 bg-amber-500/10 dark:text-amber-400" },
  voice: { icon: Phone, color: "text-violet-600 bg-violet-500/10 dark:text-violet-400" },
}

const defaultIcon = { icon: Bell, color: "text-gray-600 bg-gray-500/10 dark:text-gray-400" }

const placeholderActivities: ActivityItem[] = [
  {
    id: "1",
    icon: Users,
    iconColor: "text-blue-600 bg-blue-500/10 dark:text-blue-400",
    title: "Joined a team",
    description: "You were added to a team workspace",
    timestamp: "2m ago",
  },
  {
    id: "2",
    icon: Laptop,
    iconColor: "text-emerald-600 bg-emerald-500/10 dark:text-emerald-400",
    title: "Device registered",
    description: "A new device was provisioned to your account",
    timestamp: "1h ago",
  },
  {
    id: "3",
    icon: TicketCheck,
    iconColor: "text-amber-600 bg-amber-500/10 dark:text-amber-400",
    title: "Ticket updated",
    description: "A support ticket you created received a reply",
    timestamp: "Yesterday",
  },
  {
    id: "4",
    icon: Phone,
    iconColor: "text-violet-600 bg-violet-500/10 dark:text-violet-400",
    title: "Extension assigned",
    description: "A voice extension was assigned to your profile",
    timestamp: "3d ago",
  },
]

function mapNotificationToActivity(notification: NotificationItem): ActivityItem {
  const mapping = categoryIcons[notification.category] ?? defaultIcon
  return {
    id: notification.id,
    icon: mapping.icon,
    iconColor: mapping.color,
    title: notification.title,
    description: notification.message,
    timestamp: formatRelativeTimeShort(notification.createdAt),
    link: notification.actionUrl ?? undefined,
  }
}

export function RecentActivityFeed() {
  const { data, isLoading, isError } = useNotifications(1, 5)

  const activities: ActivityItem[] =
    data?.items && data.items.length > 0
      ? data.items.map(mapNotificationToActivity)
      : isLoading || isError
        ? placeholderActivities
        : []

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <div className="space-y-1">
          <CardTitle className="text-lg">Recent Activity</CardTitle>
          <CardDescription>Your latest actions and updates</CardDescription>
        </div>
        <Link to="/notifications" className="flex items-center gap-1 text-xs font-medium text-muted-foreground transition-colors hover:text-foreground">
          View all <ArrowRight className="h-3 w-3" />
        </Link>
      </CardHeader>
      <CardContent className="p-0">
        {activities.length === 0 ? (
          <div className="px-6 pb-6">
            <EmptyState
              icon={Bell}
              title="No recent activity"
              description="Your recent actions and notifications will appear here"
              className="border-0 py-10"
            />
          </div>
        ) : (
          <div className="max-h-[320px] overflow-y-auto px-6 pb-6">
            {activities.map((activity, index) => {
              const content = (
                <div
                  key={activity.id}
                  className={`group flex items-start gap-3 rounded-lg px-3 py-2.5 transition-colors hover:bg-muted/50 ${
                    index < activities.length - 1 ? "border-b border-border/40" : ""
                  }`}
                >
                  <div className={`mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${activity.iconColor}`}>
                    <activity.icon className="h-4 w-4" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium">{activity.title}</p>
                    <p className="text-xs text-muted-foreground">{activity.description}</p>
                  </div>
                  <span className="shrink-0 text-xs text-muted-foreground">{activity.timestamp}</span>
                  <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground/40 opacity-0 transition-all group-hover:opacity-100" />
                </div>
              )

              if (activity.link) {
                return (
                  <Link key={activity.id} to={activity.link}>
                    {content}
                  </Link>
                )
              }
              return content
            })}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
