"use client"

import { Link } from "@tanstack/react-router"
import { ChevronRight, type LucideIcon } from "lucide-react"
import { useCallback, useState } from "react"

import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import {
  SidebarGroup,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarMenuSub,
  SidebarMenuSubButton,
  SidebarMenuSubItem,
} from "@/components/ui/sidebar"
import { cn } from "@/lib/utils"

const NAV_STORAGE_KEY = "nav-sections-expanded"

function readExpandedState(): Record<string, boolean> {
  try {
    const stored = localStorage.getItem(NAV_STORAGE_KEY)
    if (stored) {
      return JSON.parse(stored) as Record<string, boolean>
    }
  } catch {
    // Ignore malformed or inaccessible localStorage
  }
  return {}
}

function writeExpandedState(state: Record<string, boolean>): void {
  try {
    localStorage.setItem(NAV_STORAGE_KEY, JSON.stringify(state))
  } catch {
    // Ignore quota or access errors
  }
}

export interface NavMainItem {
  title: string
  to: string
  icon?: LucideIcon
  isActive?: boolean
  badge?: number | string | null
  badgeVariant?: "default" | "muted"
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
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>(() => {
    const stored = readExpandedState()
    const initial: Record<string, boolean> = {}
    for (const item of items) {
      if (item.items && item.items.length > 0) {
        initial[item.title] = stored[item.title] ?? true
      }
    }
    return initial
  })

  const handleToggle = useCallback((title: string, open: boolean) => {
    setExpandedSections((prev) => {
      const next = { ...prev, [title]: open }
      writeExpandedState(next)
      return next
    })
  }, [])

  return (
    <SidebarGroup>
      <SidebarGroupLabel>{label}</SidebarGroupLabel>
      <SidebarMenu role="navigation" aria-label="Main navigation">
        {items.map((item) => {
          const badgeText = formatBadge(item.badge)

          if (!item.items || item.items.length === 0) {
            const variant = item.badgeVariant ?? "muted"
            return (
              <SidebarMenuItem key={item.title}>
                <SidebarMenuButton asChild tooltip={item.title}>
                  <Link to={item.to}>
                    <span className="relative shrink-0">
                      {item.icon && <item.icon />}
                      {badgeText != null && <span className="absolute -top-1 -right-1 hidden size-2 rounded-full bg-primary group-data-[collapsible=icon]:block" />}
                    </span>
                    <span className="group-data-[collapsible=icon]:hidden">{item.title}</span>
                  </Link>
                </SidebarMenuButton>
                {badgeText != null && (
                  <SidebarMenuBadge
                    className={cn(
                      "rounded-full px-1.5 text-[10px] font-semibold leading-tight",
                      variant === "default" ? "bg-primary text-primary-foreground" : "bg-muted text-muted-foreground",
                    )}
                  >
                    {badgeText}
                  </SidebarMenuBadge>
                )}
              </SidebarMenuItem>
            )
          }

          const collapsibleVariant = item.badgeVariant ?? "muted"
          return (
            <Collapsible key={item.title} asChild open={expandedSections[item.title] ?? true} onOpenChange={(open) => handleToggle(item.title, open)} className="group/collapsible">
              <SidebarMenuItem>
                <CollapsibleTrigger asChild>
                  <SidebarMenuButton asChild tooltip={item.title}>
                    <Link to={item.to}>
                      <span className="relative shrink-0">
                        {item.icon && <item.icon />}
                        {badgeText != null && <span className="absolute -top-1 -right-1 hidden size-2 rounded-full bg-primary group-data-[collapsible=icon]:block" />}
                      </span>
                      <span className="group-data-[collapsible=icon]:hidden">{item.title}</span>
                      <ChevronRight className="ml-auto transition-transform duration-200 group-data-[state=open]/collapsible:rotate-90 group-data-[collapsible=icon]:hidden" />
                    </Link>
                  </SidebarMenuButton>
                </CollapsibleTrigger>
                {badgeText != null && (
                  <SidebarMenuBadge
                    className={cn(
                      "rounded-full px-1.5 text-[10px] font-semibold leading-tight",
                      collapsibleVariant === "default" ? "bg-primary text-primary-foreground" : "bg-muted text-muted-foreground",
                    )}
                  >
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
