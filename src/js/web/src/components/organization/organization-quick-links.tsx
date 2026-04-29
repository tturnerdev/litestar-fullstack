import { Link } from "@tanstack/react-router"
import { ChevronRight, ScrollText, ShieldCheck, Users, UsersRound } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { useAuthStore } from "@/lib/auth"

interface QuickLinkItem {
  title: string
  description: string
  to: string
  icon: React.ElementType
  color: string
  bgColor: string
  requiresSuperuser?: boolean
}

const quickLinks: QuickLinkItem[] = [
  {
    title: "Manage Users",
    description: "View and manage user accounts",
    to: "/admin/users",
    icon: Users,
    color: "text-blue-600 dark:text-blue-400",
    bgColor: "bg-blue-500/10 group-hover:bg-blue-500",
    requiresSuperuser: true,
  },
  {
    title: "Manage Teams",
    description: "Organize and manage teams",
    to: "/admin/teams",
    icon: UsersRound,
    color: "text-emerald-600 dark:text-emerald-400",
    bgColor: "bg-emerald-500/10 group-hover:bg-emerald-500",
    requiresSuperuser: true,
  },
  {
    title: "View Audit Logs",
    description: "Track system events and actions",
    to: "/admin/audit",
    icon: ScrollText,
    color: "text-orange-600 dark:text-orange-400",
    bgColor: "bg-orange-500/10 group-hover:bg-orange-500",
    requiresSuperuser: true,
  },
  {
    title: "Admin Console",
    description: "System dashboard and statistics",
    to: "/admin",
    icon: ShieldCheck,
    color: "text-purple-600 dark:text-purple-400",
    bgColor: "bg-purple-500/10 group-hover:bg-purple-500",
    requiresSuperuser: true,
  },
]

export function OrganizationQuickLinks() {
  const user = useAuthStore((state) => state.user)
  const isSuperuser = user?.isSuperuser ?? false

  const visibleLinks = quickLinks.filter(
    (link) => !link.requiresSuperuser || isSuperuser,
  )

  if (visibleLinks.length === 0) {
    return null
  }

  return (
    <div className="space-y-3">
      <h2 className="text-lg font-semibold">Quick Links</h2>
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {visibleLinks.map((link) => (
          <Link key={link.to} to={link.to}>
            <Card hover className="h-full">
              <CardContent className="flex items-center gap-4 py-5">
                <div className={`group flex h-10 w-10 shrink-0 items-center justify-center rounded-lg transition-colors ${link.bgColor}`}>
                  <link.icon className={`h-5 w-5 ${link.color} transition-colors group-hover:text-white`} />
                </div>
                <div className="min-w-0 flex-1">
                  <CardTitle className="text-sm">{link.title}</CardTitle>
                  <p className="mt-0.5 text-xs text-muted-foreground">{link.description}</p>
                </div>
                <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground/50" />
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>
    </div>
  )
}
