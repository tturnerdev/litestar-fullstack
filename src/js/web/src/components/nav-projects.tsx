import { Link, useLocation } from "@tanstack/react-router"
import { ChevronDown, type LucideIcon } from "lucide-react"
import { useState } from "react"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { Badge } from "@/components/ui/badge"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { SidebarGroup, SidebarGroupLabel, SidebarMenu, SidebarMenuButton, SidebarMenuItem } from "@/components/ui/sidebar"

const teamColors = [
  "bg-blue-500/15 text-blue-600 dark:text-blue-400",
  "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400",
  "bg-violet-500/15 text-violet-600 dark:text-violet-400",
  "bg-amber-500/15 text-amber-600 dark:text-amber-400",
  "bg-rose-500/15 text-rose-600 dark:text-rose-400",
  "bg-cyan-500/15 text-cyan-600 dark:text-cyan-400",
]

function getTeamColor(name: string): string {
  const index = name.split("").reduce((acc, char) => acc + char.charCodeAt(0), 0) % teamColors.length
  return teamColors[index]
}

function getTeamInitials(name: string): string {
  return name
    .split(" ")
    .map((part) => part[0])
    .join("")
    .slice(0, 2)
    .toUpperCase()
}

const VISIBLE_LIMIT = 5

export function NavProjects({
  projects,
  label = "Teams",
}: {
  projects: {
    name: string
    to: string
    params?: Record<string, string>
    icon?: LucideIcon
    memberCount?: number
  }[]
  label?: string
}) {
  const [expanded, setExpanded] = useState(false)
  const location = useLocation()
  const hasOverflow = projects.length > VISIBLE_LIMIT
  const visibleItems = hasOverflow && !expanded ? projects.slice(0, VISIBLE_LIMIT) : projects
  const hiddenCount = projects.length - VISIBLE_LIMIT

  const isActive = (item: { to: string; params?: Record<string, string> }) => {
    // Build the resolved path for comparison
    let resolvedPath = item.to
    if (item.params) {
      for (const [key, value] of Object.entries(item.params)) {
        resolvedPath = resolvedPath.replace(`$${key}`, value)
      }
    }
    return location.pathname.startsWith(resolvedPath)
  }

  const renderItem = (item: (typeof projects)[number]) => {
    const color = getTeamColor(item.name)
    const initials = getTeamInitials(item.name)
    const active = isActive(item)

    return (
      <SidebarMenuItem key={item.name}>
        <SidebarMenuButton
          asChild
          isActive={active}
          className="transition-colors duration-150 hover:bg-sidebar-accent"
        >
          <Link to={item.to} params={item.params}>
            <Avatar className="size-5 shrink-0">
              <AvatarFallback className={`text-[9px] font-semibold ${color}`}>
                {initials}
              </AvatarFallback>
            </Avatar>
            <span className="flex-1 truncate">{item.name}</span>
            {item.memberCount != null && (
              <Badge variant="secondary" className="ml-auto h-4 min-w-[1.25rem] justify-center px-1 py-0 text-[10px] leading-none">
                {item.memberCount}
              </Badge>
            )}
          </Link>
        </SidebarMenuButton>
      </SidebarMenuItem>
    )
  }

  return (
    <SidebarGroup className="group-data-[collapsible=icon]:hidden">
      <SidebarGroupLabel>{label}</SidebarGroupLabel>
      <SidebarMenu>
        {visibleItems.map(renderItem)}
        {hasOverflow && !expanded && (
          <Collapsible open={expanded} onOpenChange={setExpanded}>
            <SidebarMenuItem>
              <CollapsibleTrigger asChild>
                <SidebarMenuButton className="text-muted-foreground">
                  <ChevronDown className="size-4 transition-transform duration-200" />
                  <span className="text-xs">Show {hiddenCount} more</span>
                </SidebarMenuButton>
              </CollapsibleTrigger>
            </SidebarMenuItem>
            <CollapsibleContent />
          </Collapsible>
        )}
        {hasOverflow && expanded && (
          <>
            {projects.slice(VISIBLE_LIMIT).map(renderItem)}
            <Collapsible open={expanded} onOpenChange={setExpanded}>
              <SidebarMenuItem>
                <CollapsibleTrigger asChild>
                  <SidebarMenuButton className="text-muted-foreground">
                    <ChevronDown className="size-4 rotate-180 transition-transform duration-200" />
                    <span className="text-xs">Show less</span>
                  </SidebarMenuButton>
                </CollapsibleTrigger>
              </SidebarMenuItem>
              <CollapsibleContent />
            </Collapsible>
          </>
        )}
      </SidebarMenu>
    </SidebarGroup>
  )
}
