import { useQuery } from "@tanstack/react-query"
import {
  BarChart3,
  Bell,
  Building2,
  Cable,
  Clock,
  GitBranch,
  Home,
  LifeBuoy,
  ListTodo,
  MapPin,
  Monitor,
  Phone,
  Printer,
  Search,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Tags,
  Users,
  Voicemail,
  Webhook,
} from "lucide-react"
import type * as React from "react"
import { useEffect, useMemo } from "react"
import { NavMain, type NavMainItem } from "@/components/nav-main"
import { NavProjects } from "@/components/nav-projects"
import { NavUser } from "@/components/nav-user"
import { TeamSwitcher } from "@/components/team-switcher"
import { ThemeToggle } from "@/components/theme-toggle"
import { Sidebar, SidebarContent, SidebarFooter, SidebarHeader, SidebarRail, SidebarSeparator } from "@/components/ui/sidebar"
import { usePermissions } from "@/hooks/use-permissions"
import { useUnreadCount } from "@/lib/api/hooks/notifications"
import { useAuthStore } from "@/lib/auth"
import { adminListUsers, type FeatureArea, listTeams, type Team } from "@/lib/generated/api"

const BADGE_STALE_TIME = 60_000

function useNavBadges(isAuthenticated: boolean, isSuperuser: boolean) {
  const teamsCount = useQuery({
    queryKey: ["nav-badge", "teams"],
    queryFn: async () => {
      const response = await listTeams({ query: { pageSize: 1 } })
      return response.data?.total ?? 0
    },
    enabled: isAuthenticated,
    staleTime: BADGE_STALE_TIME,
  })

  const usersCount = useQuery({
    queryKey: ["nav-badge", "admin-users"],
    queryFn: async () => {
      const response = await adminListUsers({ query: { pageSize: 1 } })
      return response.data?.total ?? 0
    },
    enabled: isAuthenticated && isSuperuser,
    staleTime: BADGE_STALE_TIME,
  })

  return {
    teams: teamsCount.data ?? null,
    adminUsers: usersCount.data ?? null,
  }
}

export function AppSidebar({ ...props }: React.ComponentProps<typeof Sidebar>) {
  const { teams, currentTeam, setTeams, setCurrentTeam, user, isAuthenticated } = useAuthStore()
  const badges = useNavBadges(isAuthenticated, user?.isSuperuser ?? false)
  const { data: unreadData } = useUnreadCount()
  const { canView, canEdit } = usePermissions()

  const {
    data: teamsData = [],
    isLoading,
    isError,
  } = useQuery({
    queryKey: ["teams"],
    queryFn: async () => {
      const response = await listTeams()
      const data = response.data
      if (Array.isArray(data)) return data
      return data?.items ?? []
    },
    enabled: isAuthenticated,
  })

  const safeTeamsData = Array.isArray(teamsData) ? teamsData : []
  const teamIds = useMemo(() => safeTeamsData.map((team) => team.id).join("|"), [safeTeamsData])
  const storeIds = useMemo(() => teams.map((team) => team.id).join("|"), [teams])

  useEffect(() => {
    if (isLoading || isError || teamIds === storeIds) {
      return
    }
    setTeams(safeTeamsData)
  }, [isError, isLoading, setTeams, storeIds, teamIds, safeTeamsData])

  const navMain = useMemo(() => {
    const topLevelAreas: Record<string, FeatureArea> = {
      Teams: "TEAMS",
      Locations: "LOCATIONS",
      Devices: "DEVICES",
      Voice: "VOICE",
      Voicemail: "VOICE_VOICEMAIL",
      Fax: "FAX",
      Schedules: "SCHEDULES",
      E911: "E911",
      "Call Routing": "CALL_ROUTING",
      Support: "SUPPORT",
    }

    const subItemAreas: Record<string, FeatureArea> = {
      "Phone Numbers": "VOICE_PHONE_NUMBERS",
      Extensions: "VOICE_EXTENSIONS",
      "Voicemail Boxes": "VOICE_VOICEMAIL_BOXES",
      "Fax Numbers": "FAX_NUMBERS",
      Messages: "FAX_MESSAGES",
      "Email Routes": "FAX_EMAIL_ROUTES",
      "Time Conditions": "CALL_ROUTING_TIME_CONDITIONS",
      "IVR Menus": "CALL_ROUTING_IVR_MENUS",
      "Call Queues": "CALL_ROUTING_QUEUES",
      "Ring Groups": "CALL_ROUTING_RING_GROUPS",
      Tickets: "SUPPORT_TICKETS",
    }

    const subItemEditAreas: Record<string, FeatureArea> = {
      "Send Fax": "FAX_MESSAGES",
    }

    const items: NavMainItem[] = [
      {
        title: "Home",
        to: "/home",
        icon: Home,
      },
      {
        title: "Teams",
        to: "/teams",
        icon: Users,
        badge: badges.teams,
        items: [{ title: "Overview", to: "/teams" }],
      },
      {
        title: "Locations",
        to: "/locations",
        icon: MapPin,
        items: [{ title: "Overview", to: "/locations" }],
      },
      {
        title: "Devices",
        to: "/devices",
        icon: Monitor,
        items: [{ title: "Overview", to: "/devices" }],
      },
      {
        title: "Voice",
        to: "/voice",
        icon: Phone,
        items: [
          { title: "Overview", to: "/voice" },
          { title: "Phone Numbers", to: "/voice/phone-numbers" },
          { title: "Extensions", to: "/voice/extensions" },
        ],
      },
      {
        title: "Voicemail",
        to: "/voicemail",
        icon: Voicemail,
        items: [
          { title: "Overview", to: "/voicemail" },
          { title: "Voicemail Boxes", to: "/voicemail?tab=boxes" },
        ],
      },
      {
        title: "Fax",
        to: "/fax",
        icon: Printer,
        items: [
          { title: "Overview", to: "/fax" },
          { title: "Fax Numbers", to: "/fax/numbers" },
          { title: "Messages", to: "/fax/messages" },
          { title: "Email Routes", to: "/fax/email-routes" },
          { title: "Send Fax", to: "/fax/send" },
        ],
      },
      {
        title: "Schedules",
        to: "/schedules",
        icon: Clock,
        items: [{ title: "Overview", to: "/schedules" }],
      },
      {
        title: "E911",
        to: "/e911",
        icon: ShieldAlert,
        items: [{ title: "Overview", to: "/e911" }],
      },
      {
        title: "Call Routing",
        to: "/call-routing",
        icon: GitBranch,
        items: [
          { title: "Time Conditions", to: "/call-routing?tab=time-conditions" },
          { title: "IVR Menus", to: "/call-routing?tab=ivr-menus" },
          { title: "Call Queues", to: "/call-routing?tab=call-queues" },
          { title: "Ring Groups", to: "/call-routing?tab=ring-groups" },
        ],
      },
      {
        title: "Gateway",
        to: "/gateway",
        icon: Search,
      },
      {
        title: "Analytics",
        to: "/analytics",
        icon: BarChart3,
        items: [
          { title: "Overview", to: "/analytics" },
          { title: "Call Records", to: "/analytics?tab=records" },
        ],
      },
      {
        title: "Support",
        to: "/support",
        icon: LifeBuoy,
        items: [{ title: "Tickets", to: "/support" }],
      },
      {
        title: "Tasks",
        to: "/tasks",
        icon: ListTodo,
      },
      {
        title: "Tags",
        to: "/tags",
        icon: Tags,
        items: [{ title: "Overview", to: "/tags" }],
      },
    ]

    if (user?.isSuperuser) {
      items.push({
        title: "Connections",
        to: "/connections",
        icon: Cable,
        items: [{ title: "Overview", to: "/connections" }],
      })
    }

    return items
      .filter((item) => {
        const area = topLevelAreas[item.title]
        return !area || canView(area)
      })
      .map((item) => {
        if (!item.items) return item
        const filtered = item.items.filter((sub) => {
          const editArea = subItemEditAreas[sub.title]
          if (editArea) return canEdit(editArea)
          const viewArea = subItemAreas[sub.title]
          return !viewArea || canView(viewArea)
        })
        return filtered.length === item.items.length ? item : { ...item, items: filtered }
      })
      .filter((item) => {
        if (!item.items) return true
        return item.items.length > 0
      })
  }, [user?.isSuperuser, badges.teams, canView, canEdit])

  const unreadCount = unreadData?.count || null
  const navSecondary = useMemo<NavMainItem[]>(
    () => [
      {
        title: "Notifications",
        to: "/notifications",
        icon: Bell,
        badge: unreadCount,
        badgeVariant: "default",
      },
      ...(user?.isSuperuser
        ? [
            {
              title: "Webhooks",
              to: "/webhooks",
              icon: Webhook,
            },
          ]
        : []),
      {
        title: "Settings",
        to: "/settings",
        icon: Settings,
      },
    ],
    [unreadCount, user?.isSuperuser],
  )

  const navAdmin = useMemo<NavMainItem[]>(() => {
    if (!user?.isSuperuser) return []
    return [
      {
        title: "Organization",
        to: "/organization",
        icon: Building2,
      },
      {
        title: "Admin",
        to: "/admin",
        icon: ShieldCheck,
        badge: badges.adminUsers,
      },
    ]
  }, [user?.isSuperuser, badges.adminUsers])

  const teamLinks = useMemo(
    () =>
      teams.map((team: Team) => ({
        name: team.name,
        to: "/teams/$teamId",
        params: { teamId: team.id },
        icon: Users,
      })),
    [teams],
  )
  const teamOptions = safeTeamsData.length > 0 ? safeTeamsData : teams

  return (
    <Sidebar collapsible="icon" {...props}>
      <SidebarHeader>
        <TeamSwitcher teams={teamOptions} currentTeam={currentTeam} onTeamSelect={setCurrentTeam} />
      </SidebarHeader>
      <SidebarContent>
        <NavMain items={navMain} />
        {teamLinks.length > 0 && <NavProjects label="Teams" projects={teamLinks} />}
        <SidebarSeparator className="mx-3" />
        <NavMain items={navSecondary} label="General" />
        {navAdmin.length > 0 && <NavMain items={navAdmin} label="System" />}
      </SidebarContent>
      <SidebarFooter>
        <div className="flex items-center gap-2">
          <div className="flex-1 min-w-0">
            <NavUser />
          </div>
          <div className="shrink-0 group-data-[collapsible=icon]:hidden">
            <ThemeToggle />
          </div>
        </div>
      </SidebarFooter>
      <SidebarRail />
    </Sidebar>
  )
}
