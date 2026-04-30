"use client"

import { useNavigate } from "@tanstack/react-router"
import { Bell, ChevronsUpDown, LogOut, Settings, User } from "lucide-react"
import { useMemo } from "react"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { Badge } from "@/components/ui/badge"
import { DropdownMenu, DropdownMenuContent, DropdownMenuGroup, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { SidebarMenu, SidebarMenuButton, SidebarMenuItem, useSidebar } from "@/components/ui/sidebar"
import { useAuthStore } from "@/lib/auth"

function useIsMac() {
  return useMemo(() => typeof navigator !== "undefined" && /Mac|iPod|iPhone|iPad/.test(navigator.userAgent), [])
}

export function NavUser() {
  const navigate = useNavigate()
  const { logout, user } = useAuthStore()
  const { isMobile } = useSidebar()
  const isMac = useIsMac()

  const onLogout = async () => {
    await logout()
    navigate({ to: "/" })
  }

  if (!user) {
    return null
  }

  const displayName = user.name || user.username || "Account"
  const initials = displayName
    .split(" ")
    .map((part) => part[0])
    .join("")
    .slice(0, 2)

  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <SidebarMenuButton size="lg" className="data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground">
              <div className="relative">
                <Avatar className="h-8 w-8 shrink-0 rounded-lg">
                  <AvatarImage src={user.avatarUrl ?? undefined} alt={displayName} />
                  <AvatarFallback className="rounded-lg">{initials}</AvatarFallback>
                </Avatar>
                <span className="absolute -bottom-0.5 -right-0.5 block h-2 w-2 rounded-full bg-green-500 ring-2 ring-sidebar" />
              </div>
              <div className="grid flex-1 text-left text-sm leading-tight group-data-[collapsible=icon]:hidden">
                <span className="truncate font-medium">{displayName}</span>
                <span className="truncate text-xs">{user.email}</span>
              </div>
              <ChevronsUpDown className="ml-auto size-4 group-data-[collapsible=icon]:hidden" />
            </SidebarMenuButton>
          </DropdownMenuTrigger>
          <DropdownMenuContent className="w-(--radix-dropdown-menu-trigger-width) min-w-56 rounded-lg" side={isMobile ? "bottom" : "right"} align="end" sideOffset={4}>
            <DropdownMenuLabel className="p-0 font-normal">
              <div className="flex items-center gap-2 px-1 py-1.5 text-left text-sm">
                <div className="relative">
                  <Avatar className="h-8 w-8 rounded-lg">
                    <AvatarImage src={user.avatarUrl ?? undefined} alt={displayName} />
                    <AvatarFallback className="rounded-lg">{initials}</AvatarFallback>
                  </Avatar>
                  <span className="absolute -bottom-0.5 -right-0.5 block h-2 w-2 rounded-full bg-green-500 ring-2 ring-white dark:ring-zinc-900" />
                </div>
                <div className="grid flex-1 text-left text-sm leading-tight">
                  <div className="flex items-center gap-1.5">
                    <span className="truncate font-medium">{displayName}</span>
                    <Badge variant={user.isSuperuser ? "destructive" : "secondary"} className="text-[10px] px-1.5 py-0">
                      {user.isSuperuser ? "Admin" : "Member"}
                    </Badge>
                  </div>
                  <span className="truncate text-xs">{user.email}</span>
                </div>
              </div>
              <p className="px-1 pb-1 text-[11px] text-muted-foreground">{isMac ? "⌘K" : "Ctrl+K"} to search</p>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuGroup>
              <DropdownMenuItem className="cursor-pointer" onClick={() => navigate({ to: "/profile" })}>
                <User />
                Profile
              </DropdownMenuItem>
              <DropdownMenuItem className="cursor-pointer" onClick={() => navigate({ to: "/settings" })}>
                <Settings />
                Settings
              </DropdownMenuItem>
              <DropdownMenuItem className="cursor-pointer" onClick={() => navigate({ to: "/notifications" })}>
                <Bell />
                Notifications
              </DropdownMenuItem>
            </DropdownMenuGroup>
            <DropdownMenuSeparator />
            <DropdownMenuItem className="cursor-default focus:bg-transparent">
              MFA
              <Badge variant={user.isTwoFactorEnabled ? "default" : "secondary"} className="ml-auto">
                {user.isTwoFactorEnabled ? "Enabled" : "Disabled"}
              </Badge>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem className="cursor-pointer" onClick={onLogout}>
              <LogOut />
              Log out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </SidebarMenuItem>
    </SidebarMenu>
  )
}
