import { Link } from "@tanstack/react-router"
import { BarChart3, Laptop, type LucideIcon, TicketPlus, Users } from "lucide-react"
import { Card, CardContent } from "@/components/ui/card"

interface QuickShortcut {
  key: string
  label: string
  to: string
  icon: LucideIcon
  iconBg: string
  iconText: string
}

const shortcuts: QuickShortcut[] = [
  {
    key: "create-ticket",
    label: "Create new ticket",
    to: "/support/new",
    icon: TicketPlus,
    iconBg: "bg-amber-500/10 group-hover:bg-amber-500",
    iconText: "text-amber-600 dark:text-amber-400 group-hover:text-white dark:group-hover:text-white",
  },
  {
    key: "add-device",
    label: "Add device",
    to: "/devices/new",
    icon: Laptop,
    iconBg: "bg-blue-500/10 group-hover:bg-blue-500",
    iconText: "text-blue-600 dark:text-blue-400 group-hover:text-white dark:group-hover:text-white",
  },
  {
    key: "create-team",
    label: "Create team",
    to: "/teams/new",
    icon: Users,
    iconBg: "bg-cyan-500/10 group-hover:bg-cyan-500",
    iconText: "text-cyan-600 dark:text-cyan-400 group-hover:text-white dark:group-hover:text-white",
  },
  {
    key: "view-analytics",
    label: "View analytics",
    to: "/analytics",
    icon: BarChart3,
    iconBg: "bg-violet-500/10 group-hover:bg-violet-500",
    iconText: "text-violet-600 dark:text-violet-400 group-hover:text-white dark:group-hover:text-white",
  },
]

export function QuickShortcutsRow() {
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
      {shortcuts.map((shortcut) => (
        <Link key={shortcut.key} to={shortcut.to}>
          <Card className="group cursor-pointer transition-all duration-200 hover:scale-[1.02] hover:shadow-md">
            <CardContent className="flex flex-col items-center gap-2.5 px-3 py-4">
              <div className={`flex h-10 w-10 items-center justify-center rounded-lg transition-colors ${shortcut.iconBg} ${shortcut.iconText}`}>
                <shortcut.icon className="h-5 w-5" />
              </div>
              <span className="text-center text-xs font-medium text-muted-foreground group-hover:text-foreground">{shortcut.label}</span>
            </CardContent>
          </Card>
        </Link>
      ))}
    </div>
  )
}
