import { Link, Outlet, useNavigate, useRouterState } from "@tanstack/react-router"
import { useCallback, useMemo, useState } from "react"
import { toast } from "sonner"
import { AppSidebar } from "@/components/app-sidebar"
import { HelpMenu } from "@/components/help/help-menu"
import { KeyboardShortcutsDialog } from "@/components/keyboard-shortcuts-dialog"
import { NotificationBell } from "@/components/notifications/notification-bell"
import { GlobalSearch } from "@/components/search/global-search"
import { Separator } from "@/components/ui/separator"
import { SidebarInset, SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar"
import type { KeyboardShortcut, SequenceShortcut } from "@/hooks/use-keyboard-shortcuts"
import { useKeyboardShortcuts } from "@/hooks/use-keyboard-shortcuts"
import { useAuthStore } from "@/lib/auth"

const NEW_ITEM_ROUTES: Record<string, string> = {
  "/teams": "/teams/new",
  "/devices": "/devices/new",
  "/support": "/support/new",
}

function getNewItemRoute(pathname: string): string | null {
  for (const [prefix, target] of Object.entries(NEW_ITEM_ROUTES)) {
    if (pathname === prefix || pathname.startsWith(`${prefix}/`)) {
      return target
    }
  }
  return null
}

export function AppLayout() {
  const currentTeam = useAuthStore((state) => state.currentTeam)
  const user = useAuthStore((state) => state.user)
  const navigate = useNavigate()
  const pathname = useRouterState({
    select: (state) => state.location.pathname,
  })
  const [shortcutsOpen, setShortcutsOpen] = useState(false)

  const goTo = useCallback((path: string) => navigate({ to: path }), [navigate])

  const shortcuts = useMemo<KeyboardShortcut[]>(() => {
    const newRoute = getNewItemRoute(pathname)
    const items: KeyboardShortcut[] = [
      { key: "N", modifiers: ["ctrl", "shift"], action: () => goTo("/support/new"), description: "New ticket", category: "actions" },
      { key: "?", action: () => setShortcutsOpen(true), description: "Show keyboard shortcuts", category: "help" },
    ]
    if (newRoute) {
      items.push({ key: "n", action: () => goTo(newRoute), description: "Create new item", category: "actions" })
    }
    return items
  }, [goTo, pathname])

  const sequences = useMemo<SequenceShortcut[]>(() => {
    const items: SequenceShortcut[] = [
      { prefix: "g", key: "h", action: () => goTo("/home"), description: "Go to Home", category: "navigation" },
      { prefix: "g", key: "t", action: () => goTo("/teams"), description: "Go to Teams", category: "navigation" },
      { prefix: "g", key: "d", action: () => goTo("/devices"), description: "Go to Devices", category: "navigation" },
      { prefix: "g", key: "v", action: () => goTo("/voice"), description: "Go to Voice", category: "navigation" },
      { prefix: "g", key: "f", action: () => goTo("/fax"), description: "Go to Fax", category: "navigation" },
      { prefix: "g", key: "s", action: () => goTo("/support"), description: "Go to Support", category: "navigation" },
      { prefix: "g", key: "l", action: () => goTo("/locations"), description: "Go to Locations", category: "navigation" },
      { prefix: "g", key: "r", action: () => goTo("/call-routing"), description: "Go to Call Routing", category: "navigation" },
      { prefix: "g", key: "e", action: () => goTo("/schedules"), description: "Go to Schedules", category: "navigation" },
      { prefix: "g", key: "y", action: () => goTo("/analytics"), description: "Go to Analytics", category: "navigation" },
      { prefix: "g", key: "n", action: () => goTo("/notifications"), description: "Go to Notifications", category: "navigation" },
      { prefix: "g", key: "o", action: () => goTo("/organization"), description: "Go to Organization", category: "navigation" },
      { prefix: "g", key: "w", action: () => goTo("/webhooks"), description: "Go to Webhooks", category: "navigation" },
      { prefix: "g", key: "p", action: () => goTo("/profile"), description: "Go to Profile", category: "navigation" },
    ]
    if (user?.isSuperuser) {
      items.push(
        { prefix: "g", key: "a", action: () => goTo("/admin"), description: "Go to Admin", category: "navigation" },
        { prefix: "g", key: "c", action: () => goTo("/connections"), description: "Go to Connections", category: "navigation" },
      )
    }
    return items
  }, [goTo, user?.isSuperuser])

  useKeyboardShortcuts({
    shortcuts,
    sequences,
    onSequenceStart: (prefix) => {
      if (prefix === "g") toast("Go to…", { id: "keyboard-go-to", description: "Press a key to navigate (h=home, t=teams, d=devices, v=voice, f=fax, s=support, ...)", duration: 1500 })
    },
    onSequenceEnd: () => toast.dismiss("keyboard-go-to"),
  })

  const isMac = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.userAgent)
  const modKey = isMac ? "⌘" : "Ctrl"
  const shortcutGroups = useMemo(() => {
    const navigation = [
      { keys: ["g", "h"], description: "Go to Home" },
      { keys: ["g", "t"], description: "Go to Teams" },
      { keys: ["g", "d"], description: "Go to Devices" },
      { keys: ["g", "v"], description: "Go to Voice" },
      { keys: ["g", "f"], description: "Go to Fax" },
      { keys: ["g", "s"], description: "Go to Support" },
      { keys: ["g", "l"], description: "Go to Locations" },
      { keys: ["g", "r"], description: "Go to Call Routing" },
      { keys: ["g", "e"], description: "Go to Schedules" },
      { keys: ["g", "y"], description: "Go to Analytics" },
      { keys: ["g", "n"], description: "Go to Notifications" },
      { keys: ["g", "o"], description: "Go to Organization" },
      { keys: ["g", "w"], description: "Go to Webhooks" },
      { keys: ["g", "p"], description: "Go to Profile" },
    ]
    if (user?.isSuperuser) {
      navigation.push(
        { keys: ["g", "a"], description: "Go to Admin" },
        { keys: ["g", "c"], description: "Go to Connections" },
      )
    }
    return [
      { category: "Navigation", shortcuts: navigation },
      { category: "Actions", shortcuts: [{ keys: [`${modKey}+K`], description: "Open search" }, { keys: [`${modKey}+Shift+N`], description: "New ticket" }, { keys: ["n"], description: "Create new item (context-dependent)" }] },
      { category: "Help", shortcuts: [{ keys: ["?"], description: "Show keyboard shortcuts" }] },
    ]
  }, [modKey, user?.isSuperuser])

  const header = useMemo(() => {
    if (pathname === "/home") {
      return { eyebrow: "Overview", title: "Home" }
    }
    if (pathname === "/teams") {
      return { eyebrow: "Workspace", title: "Teams" }
    }
    if (pathname === "/teams/new") {
      return { eyebrow: "Workspace", title: "Create team" }
    }
    if (pathname.startsWith("/teams/")) {
      return { eyebrow: "Workspace", title: currentTeam?.name ?? "Team" }
    }
    if (pathname === "/devices") {
      return { eyebrow: "Workspace", title: "Devices" }
    }
    if (pathname === "/devices/new") {
      return { eyebrow: "Workspace", title: "Add device" }
    }
    if (pathname.startsWith("/devices/")) {
      return { eyebrow: "Workspace", title: "Device" }
    }
    if (pathname.startsWith("/voice/extensions/")) {
      return { eyebrow: "Voice", title: "Extension Settings" }
    }
    if (pathname === "/voice/extensions") {
      return { eyebrow: "Voice", title: "Extensions" }
    }
    if (pathname === "/voice/phone-numbers") {
      return { eyebrow: "Voice", title: "Phone Numbers" }
    }
    if (pathname.startsWith("/voice")) {
      return { eyebrow: "Voice", title: "Voice Settings" }
    }
    if (pathname === "/fax") {
      return { eyebrow: "Communications", title: "Fax" }
    }
    if (pathname === "/fax/numbers") {
      return { eyebrow: "Communications", title: "Fax Numbers" }
    }
    if (pathname.startsWith("/fax/numbers/")) {
      return { eyebrow: "Communications", title: "Fax Number Details" }
    }
    if (pathname === "/fax/messages") {
      return { eyebrow: "Communications", title: "Fax Messages" }
    }
    if (pathname.startsWith("/fax/messages/")) {
      return { eyebrow: "Communications", title: "Message Details" }
    }
    if (pathname === "/fax/send") {
      return { eyebrow: "Communications", title: "Send Fax" }
    }
    if (pathname === "/support") {
      return { eyebrow: "Helpdesk", title: "Tickets" }
    }
    if (pathname === "/support/new") {
      return { eyebrow: "Helpdesk", title: "New Ticket" }
    }
    if (pathname.startsWith("/support/")) {
      return { eyebrow: "Helpdesk", title: "Ticket Detail" }
    }
    if (pathname.startsWith("/locations")) {
      return { eyebrow: "Infrastructure", title: "Locations" }
    }
    if (pathname.startsWith("/connections")) {
      return { eyebrow: "Infrastructure", title: "Connections" }
    }
    if (pathname.startsWith("/admin")) {
      return { eyebrow: "Operations", title: "Admin" }
    }
    if (pathname.startsWith("/notifications")) {
      return { eyebrow: "General", title: "Notifications" }
    }
    if (pathname.startsWith("/settings")) {
      return { eyebrow: "General", title: "Settings" }
    }
    if (pathname.startsWith("/profile")) {
      return { eyebrow: "Account", title: "Profile" }
    }
    return { eyebrow: "Workspace", title: "Dashboard" }
  }, [currentTeam?.name, pathname])

  return (
    <div className="flex min-h-screen flex-col">
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:rounded-md focus:bg-primary focus:px-4 focus:py-2 focus:text-sm focus:font-medium focus:text-primary-foreground focus:shadow-lg focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2"
      >
        Skip to main content
      </a>
      <div className="flex flex-1">
        <SidebarProvider>
          <AppSidebar />
          <SidebarInset>
            <header className="flex h-16 shrink-0 items-center gap-2 border-b border-border/60 bg-background/80 backdrop-blur">
              <div className="flex w-full items-center justify-between gap-4 px-4">
                <div className="flex items-center gap-2">
                  <SidebarTrigger className="-ml-1" aria-label="Toggle sidebar" />
                  <Separator orientation="vertical" className="mr-2 h-4" />
                  <div>
                    <p className="text-[0.65rem] font-semibold uppercase tracking-[0.24em] text-muted-foreground">{header.eyebrow}</p>
                    <p className="font-heading text-lg font-semibold text-foreground">{header.title}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {currentTeam && pathname !== "/teams/new" && !pathname.startsWith(`/teams/${currentTeam.id}`) && (
                    <Link
                      to="/teams/$teamId"
                      params={{ teamId: currentTeam.id }}
                      className="hidden items-center gap-2 rounded-full border border-border/60 bg-card/80 px-3 py-1 text-xs font-medium text-muted-foreground transition-colors hover:bg-accent hover:text-accent-foreground md:flex"
                    >
                      Active team
                      <span className="text-foreground">{currentTeam.name}</span>
                    </Link>
                  )}
                  <GlobalSearch />
                  <NotificationBell />
                  <HelpMenu />
                </div>
              </div>
            </header>
            <main id="main-content" tabIndex={-1} className="outline-none">
              <Outlet />
            </main>
          </SidebarInset>
        </SidebarProvider>
      </div>
      <KeyboardShortcutsDialog open={shortcutsOpen} onOpenChange={setShortcutsOpen} groups={shortcutGroups} />
    </div>
  )
}
