import { Link } from "@tanstack/react-router"
import { Check, ChevronsUpDown, Plus, Search, Settings } from "lucide-react"
import * as React from "react"

import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuShortcut,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Input } from "@/components/ui/input"
import { SidebarMenu, SidebarMenuButton, SidebarMenuItem, useSidebar } from "@/components/ui/sidebar"
import type { Team } from "@/lib/generated/api"

const teamColors = [
  "bg-blue-500/15 text-blue-600 dark:text-blue-400",
  "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400",
  "bg-violet-500/15 text-violet-600 dark:text-violet-400",
  "bg-amber-500/15 text-amber-600 dark:text-amber-400",
  "bg-rose-500/15 text-rose-600 dark:text-rose-400",
  "bg-cyan-500/15 text-cyan-600 dark:text-cyan-400",
]

function getTeamColor(identifier: string): string {
  const index = identifier.split("").reduce((acc, char) => acc + char.charCodeAt(0), 0) % teamColors.length
  return teamColors[index]
}

function getTeamInitials(name: string): string {
  return name
    .split(" ")
    .map((part) => part[0])
    .join("")
    .slice(0, 2)
}

export function TeamSwitcher({ teams, currentTeam, onTeamSelect }: { teams: Team[]; currentTeam: Team | null; onTeamSelect: (team: Team) => void }) {
  const { isMobile } = useSidebar()
  const [search, setSearch] = React.useState("")

  const activeTeam = React.useMemo(() => {
    if (currentTeam) {
      return teams.find((team) => team.id === currentTeam.id) ?? teams[0]
    }
    return teams[0]
  }, [currentTeam, teams])

  const filteredTeams = React.useMemo(() => {
    if (!search.trim()) return teams
    const q = search.toLowerCase()
    return teams.filter((team) => team.name.toLowerCase().includes(q))
  }, [teams, search])

  const showSearch = teams.length > 5

  if (!activeTeam) {
    return null
  }

  const activeInitials = getTeamInitials(activeTeam.name)
  const activeColor = getTeamColor(activeTeam.id ?? activeTeam.name)
  const subtitle = teams.length > 1 ? `${teams.length} teams` : activeTeam.slug

  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <DropdownMenu
          onOpenChange={(open) => {
            if (!open) setSearch("")
          }}
        >
          <DropdownMenuTrigger asChild>
            <SidebarMenuButton size="lg" className="data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground">
              <div className={`flex aspect-square size-8 shrink-0 items-center justify-center rounded-lg ${activeColor}`}>
                <span className="text-xs font-semibold">{activeInitials}</span>
              </div>
              <div className="grid flex-1 text-left text-sm leading-tight group-data-[collapsible=icon]:hidden">
                <span className="truncate font-medium" title={activeTeam.name}>
                  {activeTeam.name}
                </span>
                <span className="truncate text-xs text-muted-foreground" title={subtitle}>
                  {subtitle}
                </span>
              </div>
              <ChevronsUpDown className="ml-auto group-data-[collapsible=icon]:hidden" />
            </SidebarMenuButton>
          </DropdownMenuTrigger>
          <DropdownMenuContent className="w-(--radix-dropdown-menu-trigger-width) min-w-56 rounded-lg" align="start" side={isMobile ? "bottom" : "right"} sideOffset={4}>
            <DropdownMenuLabel className="text-muted-foreground text-xs">Teams</DropdownMenuLabel>
            {showSearch && (
              <>
                <div className="px-2 py-1.5">
                  <div className="relative">
                    <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
                    <Input
                      placeholder="Search teams..."
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                      className="h-8 pl-8 text-xs"
                      onKeyDown={(e) => e.stopPropagation()}
                    />
                  </div>
                </div>
                <DropdownMenuSeparator />
              </>
            )}
            {filteredTeams.length === 0 && <div className="px-2 py-4 text-center text-xs text-muted-foreground">No teams found</div>}
            {filteredTeams.map((team, index) => {
              const isActive = team.id === activeTeam.id
              const color = getTeamColor(team.id ?? team.name)
              const initials = getTeamInitials(team.name)
              return (
                <DropdownMenuItem key={team.id} onClick={() => onTeamSelect(team)} className="gap-2 p-2">
                  <div className={`flex size-6 items-center justify-center rounded-md ${color}`}>
                    <span className="text-[10px] font-semibold">{initials}</span>
                  </div>
                  <span className="flex-1 truncate" title={team.name}>
                    {team.name}
                  </span>
                  {isActive && <Check className="ml-auto size-4 text-primary" />}
                  {!search && <DropdownMenuShortcut>⌘{index + 1}</DropdownMenuShortcut>}
                </DropdownMenuItem>
              )
            })}
            <DropdownMenuSeparator />
            <DropdownMenuItem asChild className="p-2">
              <Link to="/teams/new" className="flex items-center gap-2">
                <div className="flex size-6 items-center justify-center rounded-md border bg-transparent">
                  <Plus className="size-4" />
                </div>
                <span className="font-medium text-muted-foreground">Add team</span>
              </Link>
            </DropdownMenuItem>
            <DropdownMenuItem asChild className="p-2">
              <Link to="/teams" className="flex items-center gap-2">
                <div className="flex size-6 items-center justify-center rounded-md border bg-transparent">
                  <Settings className="size-4" />
                </div>
                <span className="font-medium text-muted-foreground">Manage teams</span>
              </Link>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </SidebarMenuItem>
    </SidebarMenu>
  )
}
