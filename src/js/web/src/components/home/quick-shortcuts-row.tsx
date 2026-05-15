import { Link } from "@tanstack/react-router"
import { BarChart3, Calendar, FileUp, Laptop, type LucideIcon, PhoneForwarded, TicketPlus, Users } from "lucide-react"
import { Card, CardContent } from "@/components/ui/card"
import { usePermissions } from "@/hooks/use-permissions"
import type { FeatureArea } from "@/lib/generated/api"

interface QuickShortcut {
  key: string
  label: string
  description: string
  to: string
  icon: LucideIcon
  iconBg: string
  iconText: string
  editArea?: FeatureArea
}

const shortcuts: QuickShortcut[] = [
  {
    key: "create-ticket",
    label: "New Support Ticket",
    description: "Get help from your team",
    to: "/support/new",
    icon: TicketPlus,
    iconBg: "bg-amber-500/10 group-hover:bg-amber-500",
    iconText: "text-amber-600 dark:text-amber-400 group-hover:text-white dark:group-hover:text-white",
    editArea: "SUPPORT_TICKETS",
  },
  {
    key: "add-device",
    label: "Create New Device",
    description: "Register a phone or endpoint",
    to: "/devices/new",
    icon: Laptop,
    iconBg: "bg-blue-500/10 group-hover:bg-blue-500",
    iconText: "text-blue-600 dark:text-blue-400 group-hover:text-white dark:group-hover:text-white",
    editArea: "DEVICES",
  },
  {
    key: "new-extension",
    label: "New Extension",
    description: "Add a voice extension",
    to: "/voice/extensions/new",
    icon: PhoneForwarded,
    iconBg: "bg-green-500/10 group-hover:bg-green-500",
    iconText: "text-green-600 dark:text-green-400 group-hover:text-white dark:group-hover:text-white",
    editArea: "VOICE_EXTENSIONS",
  },
  {
    key: "create-team",
    label: "Create Team",
    description: "Start collaborating",
    to: "/teams/new",
    icon: Users,
    iconBg: "bg-cyan-500/10 group-hover:bg-cyan-500",
    iconText: "text-cyan-600 dark:text-cyan-400 group-hover:text-white dark:group-hover:text-white",
    editArea: "TEAMS",
  },
  {
    key: "create-schedule",
    label: "Create Schedule",
    description: "Set business hours & rules",
    to: "/schedules/new",
    icon: Calendar,
    iconBg: "bg-teal-500/10 group-hover:bg-teal-500",
    iconText: "text-teal-600 dark:text-teal-400 group-hover:text-white dark:group-hover:text-white",
    editArea: "SCHEDULES",
  },
  {
    key: "send-fax",
    label: "Send Fax",
    description: "Send a fax message",
    to: "/fax/send",
    icon: FileUp,
    iconBg: "bg-orange-500/10 group-hover:bg-orange-500",
    iconText: "text-orange-600 dark:text-orange-400 group-hover:text-white dark:group-hover:text-white",
    editArea: "FAX_MESSAGES",
  },
  {
    key: "view-analytics",
    label: "View Call Analytics",
    description: "Call volume & trends",
    to: "/analytics",
    icon: BarChart3,
    iconBg: "bg-violet-500/10 group-hover:bg-violet-500",
    iconText: "text-violet-600 dark:text-violet-400 group-hover:text-white dark:group-hover:text-white",
  },
]

export function QuickShortcutsRow() {
  const { canEdit } = usePermissions()
  const visible = shortcuts.filter((s) => !s.editArea || canEdit(s.editArea))

  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4">
      {visible.map((shortcut, index) => (
        <Link key={shortcut.key} to={shortcut.to}>
          <Card
            className="animate-in fade-in slide-in-from-bottom-1 group h-full cursor-pointer fill-mode-both transition-all duration-200 hover:scale-[1.02] hover:shadow-md"
            style={{ animationDelay: `${index * 40}ms` }}
          >
            <CardContent className="flex items-center gap-3 px-3 py-3">
              <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg transition-colors ${shortcut.iconBg} ${shortcut.iconText}`}>
                <shortcut.icon className="h-4.5 w-4.5" />
              </div>
              <div className="min-w-0 flex-1">
                <span className="block truncate text-sm font-medium text-foreground">{shortcut.label}</span>
                <span className="block truncate text-xs text-muted-foreground">{shortcut.description}</span>
              </div>
            </CardContent>
          </Card>
        </Link>
      ))}
    </div>
  )
}
