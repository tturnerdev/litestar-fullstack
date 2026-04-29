import { Link } from "@tanstack/react-router"
import { ArrowRight, Laptop, Phone, TicketCheck, Users } from "lucide-react"
import type { LucideIcon } from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"

interface ActivityItem {
  id: string
  icon: LucideIcon
  iconColor: string
  title: string
  description: string
  timestamp: string
  link?: string
}

const placeholderActivities: ActivityItem[] = [
  {
    id: "1",
    icon: Users,
    iconColor: "text-blue-600 bg-blue-500/10 dark:text-blue-400",
    title: "Joined a team",
    description: "You were added to a team workspace",
    timestamp: "Recently",
  },
  {
    id: "2",
    icon: Laptop,
    iconColor: "text-emerald-600 bg-emerald-500/10 dark:text-emerald-400",
    title: "Device registered",
    description: "A new device was provisioned to your account",
    timestamp: "Recently",
  },
  {
    id: "3",
    icon: TicketCheck,
    iconColor: "text-amber-600 bg-amber-500/10 dark:text-amber-400",
    title: "Ticket updated",
    description: "A support ticket you created received a reply",
    timestamp: "Recently",
  },
  {
    id: "4",
    icon: Phone,
    iconColor: "text-violet-600 bg-violet-500/10 dark:text-violet-400",
    title: "Extension assigned",
    description: "A voice extension was assigned to your profile",
    timestamp: "Recently",
  },
]

export function RecentActivityFeed() {
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
      <CardContent className="space-y-1">
        {placeholderActivities.map((activity) => (
          <div key={activity.id} className="flex items-start gap-3 rounded-lg px-3 py-2.5 transition-colors hover:bg-muted/50">
            <div className={`mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${activity.iconColor}`}>
              <activity.icon className="h-4 w-4" />
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-sm font-medium">{activity.title}</p>
              <p className="text-xs text-muted-foreground">{activity.description}</p>
            </div>
            <span className="shrink-0 text-xs text-muted-foreground">{activity.timestamp}</span>
          </div>
        ))}
      </CardContent>
    </Card>
  )
}
