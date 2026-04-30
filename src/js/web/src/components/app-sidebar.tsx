import { useQuery } from "@tanstack/react-query"
import { Bell, Building2, Cable, Home, LifeBuoy, MapPin, Monitor, Phone, Printer, Search, Settings, ShieldCheck, Tags, Users } from "lucide-react"
import type * as React from "react"
import { useEffect, useMemo } from "react"
import { NavMain, type NavMainItem } from "@/components/nav-main"
import { NavProjects } from "@/components/nav-projects"
import { NavUser } from "@/components/nav-user"
import { TeamSwitcher } from "@/components/team-switcher"
import { ThemeToggle } from "@/components/theme-toggle"
import { Sidebar, SidebarContent, SidebarFooter, SidebarHeader, SidebarRail, SidebarSeparator } from "@/components/ui/sidebar"
import { useAuthStore } from "@/lib/auth"
import { adminListUsers, listTeams, type Team } from "@/lib/generated/api"

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
        items: [
          { title: "All teams", to: "/teams" },
          { title: "Create new", to: "/teams/new" },
        ],
      },
      {
        title: "Locations",
        to: "/locations",
        icon: MapPin,
        items: [
          { title: "All locations", to: "/locations" },
          { title: "New location", to: "/locations/new" },
        ],
      },
      {
        title: "Devices",
        to: "/devices",
        icon: Monitor,
        items: [
          { title: "All devices", to: "/devices" },
          { title: "Add device", to: "/devices/new" },
        ],
      },
      {
        title: "Voice",
        to: "/voice",
        icon: Phone,
        items: [
          { title: "Phone Numbers", to: "/voice/phone-numbers" },
          { title: "Extensions", to: "/voice/extensions" },
        ],
      },
      {
        title: "Fax",
        to: "/fax",
        icon: Printer,
        items: [
          { title: "Fax Numbers", to: "/fax/numbers" },
          { title: "Messages", to: "/fax/messages" },
          { title: "Send Fax", to: "/fax/send" },
        ],
      },
      {
        title: "Gateway",
        to: "/gateway",
        icon: Search,
      },
      {
        title: "Support",
        to: "/support",
        icon: LifeBuoy,
        items: [
          { title: "Tickets", to: "/support" },
          { title: "New Ticket", to: "/support/new" },
        ],
      },
      {
        title: "Tags",
        to: "/tags",
        icon: Tags,
        items: [
          { title: "All tags", to: "/tags" },
          { title: "Create new", to: "/tags/new" },
        ],
      },
    ]

    if (user?.isSuperuser) {
      items.push({
        title: "Connections",
        to: "/connections",
        icon: Cable,
        items: [
          { title: "All connections", to: "/connections" },
          { title: "New connection", to: "/connections/new" },
        ],
      })
    }

    return items
  }, [user?.isSuperuser, badges.teams])

  const navSecondary = useMemo<NavMainItem[]>(
    () => [
      {
        title: "Notifications",
        to: "/notifications",
        icon: Bell,
      },
      {
        title: "Settings",
        to: "/settings",
        icon: Settings,
      },
    ],
    [],
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
