"use client"

import { Link } from "@tanstack/react-router"
import { ChevronRight, type LucideIcon } from "lucide-react"

import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { SidebarGroup, SidebarGroupLabel, SidebarMenu, SidebarMenuBadge, SidebarMenuButton, SidebarMenuItem, SidebarMenuSub, SidebarMenuSubButton, SidebarMenuSubItem } from "@/components/ui/sidebar"

export interface NavMainItem {
  title: string
  to: string
  icon?: LucideIcon
  isActive?: boolean
  badge?: number | string | null
  items?: {
    title: string
    to: string
  }[]
}

function formatBadge(value: number | string | null | undefined): string | null {
  if (value == null) return null
  if (typeof value === "string") return value
  if (value <= 0) return null
  if (value > 99) return "99+"
  return String(value)
}

export function NavMain({ items, label = "Platform" }: { items: NavMainItem[]; label?: string }) {
  return (
    <SidebarGroup>
      <SidebarGroupLabel>{label}</SidebarGroupLabel>
      <SidebarMenu role="navigation" aria-label="Main navigation">
        {items.map((item) => {
          const badgeText = formatBadge(item.badge)

          if (!item.items || item.items.length === 0) {
            return (
              <SidebarMenuItem key={item.title}>
                <SidebarMenuButton asChild tooltip={item.title}>
                  <Link to={item.to}>
                    <span className="relative shrink-0">
                      {item.icon && <item.icon />}
                      {badgeText != null && (
                        <span className="absolute -top-1 -right-1 hidden size-2 rounded-full bg-primary group-data-[collapsible=icon]:block" />
                      )}
                    </span>
                    <span className="group-data-[collapsible=icon]:hidden">{item.title}</span>
                  </Link>
                </SidebarMenuButton>
                {badgeText != null && (
                  <SidebarMenuBadge className="bg-muted text-muted-foreground rounded-full px-1.5 text-[10px] font-semibold leading-tight">
                    {badgeText}
                  </SidebarMenuBadge>
                )}
              </SidebarMenuItem>
            )
          }

          return (
            <Collapsible key={item.title} asChild defaultOpen={item.isActive} className="group/collapsible">
              <SidebarMenuItem>
                <CollapsibleTrigger asChild>
                  <SidebarMenuButton asChild tooltip={item.title}>
                    <Link to={item.to}>
                      <span className="relative shrink-0">
                        {item.icon && <item.icon />}
                        {badgeText != null && (
                          <span className="absolute -top-1 -right-1 hidden size-2 rounded-full bg-primary group-data-[collapsible=icon]:block" />
                        )}
                      </span>
                      <span className="group-data-[collapsible=icon]:hidden">{item.title}</span>
                      <ChevronRight className="ml-auto transition-transform duration-200 group-data-[state=open]/collapsible:rotate-90 group-data-[collapsible=icon]:hidden" />
                    </Link>
                  </SidebarMenuButton>
                </CollapsibleTrigger>
                {badgeText != null && (
                  <SidebarMenuBadge className="bg-muted text-muted-foreground rounded-full px-1.5 text-[10px] font-semibold leading-tight">
                    {badgeText}
                  </SidebarMenuBadge>
                )}
                <CollapsibleContent>
                  <SidebarMenuSub>
                    {item.items?.map((subItem) => (
                      <SidebarMenuSubItem key={subItem.title}>
                        <SidebarMenuSubButton asChild>
                          <Link to={subItem.to}>
                            <span>{subItem.title}</span>
                          </Link>
                        </SidebarMenuSubButton>
                      </SidebarMenuSubItem>
                    ))}
                  </SidebarMenuSub>
                </CollapsibleContent>
              </SidebarMenuItem>
            </Collapsible>
          )
        })}
      </SidebarMenu>
    </SidebarGroup>
  )
}
