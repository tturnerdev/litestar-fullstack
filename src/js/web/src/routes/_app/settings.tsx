import { createFileRoute } from "@tanstack/react-router"
import { AnimatePresence, motion } from "framer-motion"
import {
  Accessibility,
  Bell,
  Calendar,
  Check,
  Globe,
  Hash,
  Keyboard,
  Laptop,
  Layout,
  LogOut,
  Monitor,
  Moon,
  PanelLeftClose,
  Palette,
  RotateCcw,
  Shield,
  Smartphone,
  Sun,
  Type,
} from "lucide-react"
import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { toast } from "sonner"
import { NotificationPreferences } from "@/components/settings/notification-preferences"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { Switch } from "@/components/ui/switch"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { cn } from "@/lib/utils"
import { useNotificationPreferencesStore } from "@/lib/notification-preferences-store"
import { useSettingsStore } from "@/lib/settings-store"
import { useTheme } from "@/lib/theme-context"

export const Route = createFileRoute("/_app/settings")({
  component: SettingsPage,
})

const NAV_ITEMS = [
  { id: "appearance", label: "Appearance", icon: Palette },
  { id: "notifications", label: "Notifications", icon: Bell },
  { id: "display", label: "Display", icon: Layout },
  { id: "accessibility", label: "Accessibility", icon: Accessibility },
  { id: "sessions", label: "Sessions", icon: Shield },
  { id: "shortcuts", label: "Shortcuts", icon: Keyboard },
] as const

type SectionId = (typeof NAV_ITEMS)[number]["id"]

function SettingsPage() {
  useDocumentTitle("Settings")
  const [activeSection, setActiveSection] = useState<SectionId>("appearance")
  const sectionRefs = useRef<Record<string, HTMLDivElement | null>>({})
  const { resetToDefaults } = useSettingsStore()
  const { resetToDefaults: resetNotificationPreferences } = useNotificationPreferencesStore()

  const scrollToSection = useCallback((id: SectionId) => {
    setActiveSection(id)
    const el = sectionRefs.current[id]
    if (el) {
      el.scrollIntoView({ behavior: "smooth", block: "start" })
    }
  }, [])

  const handleReset = useCallback(() => {
    resetToDefaults()
    resetNotificationPreferences()
    toast.success("Settings reset to defaults", {
      description: "All display preferences have been restored.",
    })
  }, [resetToDefaults, resetNotificationPreferences])

  return (
    <PageContainer className="flex-1" maxWidth="xl">
      <PageHeader
        eyebrow="Preferences"
        title="Settings"
        description="Customize the look and behavior of the application."
        actions={
          <Button variant="outline" size="sm" onClick={handleReset}>
            <RotateCcw className="h-4 w-4" />
            Reset to defaults
          </Button>
        }
      />

      <div className="flex gap-8">
        {/* Sidebar navigation */}
        <nav className="hidden w-48 shrink-0 md:block">
          <div className="sticky top-24 space-y-1">
            {NAV_ITEMS.map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                type="button"
                onClick={() => scrollToSection(id)}
                className={cn(
                  "flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                  activeSection === id
                    ? "bg-primary/10 text-primary"
                    : "text-muted-foreground hover:bg-muted hover:text-foreground",
                )}
              >
                <Icon className="h-4 w-4" />
                {label}
              </button>
            ))}
            <Separator className="my-3" />
            <button
              type="button"
              onClick={handleReset}
              className="flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-sm font-medium text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
            >
              <RotateCcw className="h-4 w-4" />
              Reset all
            </button>
          </div>
        </nav>

        {/* Main content */}
        <div className="min-w-0 flex-1 space-y-8 pb-16">
          <PageSection delay={0.1}>
            <div ref={(el) => { sectionRefs.current.appearance = el }} className="scroll-mt-24">
              <AppearanceSection onNavigate={() => setActiveSection("appearance")} />
            </div>
          </PageSection>

          <PageSection delay={0.15}>
            <div ref={(el) => { sectionRefs.current.notifications = el }} className="scroll-mt-24">
              <NotificationPreferences />
            </div>
          </PageSection>

          <PageSection delay={0.2}>
            <div ref={(el) => { sectionRefs.current.display = el }} className="scroll-mt-24">
              <DisplaySection />
            </div>
          </PageSection>

          <PageSection delay={0.25}>
            <div ref={(el) => { sectionRefs.current.accessibility = el }} className="scroll-mt-24">
              <AccessibilitySection />
            </div>
          </PageSection>

          <PageSection delay={0.3}>
            <div ref={(el) => { sectionRefs.current.sessions = el }} className="scroll-mt-24">
              <ActiveSessionsSection />
            </div>
          </PageSection>

          <PageSection delay={0.35}>
            <div ref={(el) => { sectionRefs.current.shortcuts = el }} className="scroll-mt-24">
              <KeyboardShortcutsSection />
            </div>
          </PageSection>
        </div>
      </div>
    </PageContainer>
  )
}

/* -----------------------------------------------------------------------
 * Theme preview mini cards
 * ----------------------------------------------------------------------- */

function ThemePreviewCard({
  mode,
  isActive,
  icon: Icon,
  label,
}: {
  mode: "light" | "dark" | "system"
  isActive: boolean
  icon: React.ComponentType<{ className?: string }>
  label: string
}) {
  const previewBg = mode === "dark" ? "bg-zinc-900" : mode === "light" ? "bg-white" : "bg-gradient-to-br from-white to-zinc-900"
  const previewFg = mode === "dark" ? "bg-zinc-700" : mode === "light" ? "bg-zinc-200" : "bg-zinc-400"
  const previewAccent = mode === "dark" ? "bg-blue-500" : mode === "light" ? "bg-blue-600" : "bg-blue-500"

  return (
    <Label
      htmlFor={`theme-${mode}`}
      className={cn(
        "group flex cursor-pointer flex-col gap-3 rounded-xl border-2 p-4 transition-all duration-200",
        isActive
          ? "border-primary bg-primary/5 shadow-sm shadow-primary/10"
          : "border-border/40 hover:border-border hover:bg-accent/50",
      )}
    >
      <RadioGroupItem value={mode} id={`theme-${mode}`} className="sr-only" />
      {/* Mini preview */}
      <div
        className={cn(
          "relative flex h-20 w-full overflow-hidden rounded-lg border border-border/60",
          previewBg,
        )}
      >
        {/* Sidebar preview */}
        <div className={cn("h-full w-6 border-r border-border/30", mode === "dark" ? "bg-zinc-800" : "bg-zinc-100")}>
          <div className={cn("mx-1 mt-2 h-1 w-4 rounded-full", previewAccent)} />
          <div className={cn("mx-1 mt-1.5 h-1 w-4 rounded-full", previewFg)} />
          <div className={cn("mx-1 mt-1.5 h-1 w-4 rounded-full", previewFg)} />
        </div>
        {/* Content preview */}
        <div className="flex-1 p-2">
          <div className={cn("mb-1.5 h-1.5 w-12 rounded-full", previewFg)} />
          <div className={cn("mb-1 h-1 w-full rounded-full", previewFg, "opacity-60")} />
          <div className={cn("mb-1 h-1 w-3/4 rounded-full", previewFg, "opacity-60")} />
          <div className={cn("mt-2 h-3 w-8 rounded", previewAccent, "opacity-80")} />
        </div>
        {/* Active indicator */}
        <AnimatePresence>
          {isActive && (
            <motion.div
              initial={{ scale: 0, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0, opacity: 0 }}
              className="absolute right-1.5 top-1.5 flex h-5 w-5 items-center justify-center rounded-full bg-primary text-primary-foreground"
            >
              <Check className="h-3 w-3" />
            </motion.div>
          )}
        </AnimatePresence>
      </div>
      <div className="flex items-center gap-2">
        <Icon className={cn("h-4 w-4", isActive ? "text-primary" : "text-muted-foreground")} />
        <span className={cn("text-sm font-medium", isActive ? "text-primary" : "text-foreground")}>{label}</span>
      </div>
    </Label>
  )
}

/* -----------------------------------------------------------------------
 * Appearance section
 * ----------------------------------------------------------------------- */

function AppearanceSection({ onNavigate }: { onNavigate: () => void }) {
  const { mode, setMode } = useTheme()
  const { compactMode, setCompactMode } = useSettingsStore()

  const handleThemeChange = useCallback(
    (v: string) => {
      setMode(v as "light" | "dark" | "system")
      onNavigate()
      const labels: Record<string, string> = { light: "Light", dark: "Dark", system: "System" }
      toast.success(`Theme set to ${labels[v]}`)
    },
    [setMode, onNavigate],
  )

  const handleCompactChange = useCallback(
    (checked: boolean) => {
      setCompactMode(checked)
      toast.success(checked ? "Compact mode enabled" : "Compact mode disabled")
    },
    [setCompactMode],
  )

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary/10">
            <Palette className="h-4 w-4 text-primary" />
          </div>
          Appearance
        </CardTitle>
        <CardDescription>Control how the application looks on your device.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="space-y-3">
          <Label className="text-sm font-medium">Theme</Label>
          <RadioGroup
            value={mode}
            onValueChange={handleThemeChange}
            className="grid grid-cols-3 gap-3"
          >
            <ThemePreviewCard mode="light" isActive={mode === "light"} icon={Sun} label="Light" />
            <ThemePreviewCard mode="dark" isActive={mode === "dark"} icon={Moon} label="Dark" />
            <ThemePreviewCard mode="system" isActive={mode === "system"} icon={Monitor} label="System" />
          </RadioGroup>
        </div>

        <Separator />

        <div className="flex items-center justify-between rounded-lg border border-border/60 p-4">
          <div className="space-y-0.5">
            <Label htmlFor="compact-mode" className="text-sm font-medium">
              Compact mode
            </Label>
            <p className="text-sm text-muted-foreground">Reduce padding and spacing throughout the interface.</p>
          </div>
          <Switch id="compact-mode" checked={compactMode} onCheckedChange={handleCompactChange} />
        </div>
      </CardContent>
    </Card>
  )
}

/* -----------------------------------------------------------------------
 * Display section
 * ----------------------------------------------------------------------- */

function DisplaySection() {
  const { defaultPageSize, setDefaultPageSize, dateFormat, setDateFormat, sidebarCollapsed, setSidebarCollapsed } = useSettingsStore()

  const handlePageSizeChange = useCallback(
    (v: string) => {
      setDefaultPageSize(Number(v) as 10 | 25 | 50 | 100)
      toast.success(`Default page size set to ${v}`)
    },
    [setDefaultPageSize],
  )

  const handleDateFormatChange = useCallback(
    (v: string) => {
      setDateFormat(v as "relative" | "absolute")
      toast.success(`Date format set to ${v}`)
    },
    [setDateFormat],
  )

  const handleSidebarChange = useCallback(
    (checked: boolean) => {
      setSidebarCollapsed(checked)
      toast.success(checked ? "Sidebar will start collapsed" : "Sidebar will start expanded")
    },
    [setSidebarCollapsed],
  )

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-500/10">
            <Layout className="h-4 w-4 text-blue-500" />
          </div>
          Display Preferences
        </CardTitle>
        <CardDescription>Configure how data is displayed across the application.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-2">
        <div className="flex items-center justify-between rounded-lg border border-border/60 p-4">
          <div className="space-y-0.5">
            <Label className="flex items-center gap-1.5 text-sm font-medium">
              <Hash className="h-3.5 w-3.5 text-muted-foreground" />
              Default page size
            </Label>
            <p className="text-sm text-muted-foreground">Number of rows displayed per page in tables.</p>
          </div>
          <Select value={String(defaultPageSize)} onValueChange={handlePageSizeChange}>
            <SelectTrigger className="w-24">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="10">10</SelectItem>
              <SelectItem value="25">25</SelectItem>
              <SelectItem value="50">50</SelectItem>
              <SelectItem value="100">100</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <div className="flex items-center justify-between rounded-lg border border-border/60 p-4">
          <div className="space-y-0.5">
            <Label className="flex items-center gap-1.5 text-sm font-medium">
              <Calendar className="h-3.5 w-3.5 text-muted-foreground" />
              Date format
            </Label>
            <p className="text-sm text-muted-foreground">
              {dateFormat === "relative" ? 'Show dates like "2h ago" or "yesterday".' : 'Show dates like "Apr 28, 2026".'}
            </p>
          </div>
          <Select value={dateFormat} onValueChange={handleDateFormatChange}>
            <SelectTrigger className="w-32">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="relative">Relative</SelectItem>
              <SelectItem value="absolute">Absolute</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <div className="flex items-center justify-between rounded-lg border border-border/60 p-4">
          <div className="space-y-0.5">
            <Label htmlFor="sidebar-collapsed" className="flex items-center gap-1.5 text-sm font-medium">
              <PanelLeftClose className="h-3.5 w-3.5 text-muted-foreground" />
              Sidebar collapsed by default
            </Label>
            <p className="text-sm text-muted-foreground">Start with the sidebar in its collapsed state.</p>
          </div>
          <Switch id="sidebar-collapsed" checked={sidebarCollapsed} onCheckedChange={handleSidebarChange} />
        </div>
      </CardContent>
    </Card>
  )
}

/* -----------------------------------------------------------------------
 * Accessibility section
 * ----------------------------------------------------------------------- */

function AccessibilitySection() {
  const {
    reducedMotion, setReducedMotion,
    highContrast, setHighContrast,
    fontSize, setFontSize,
  } = useSettingsStore()

  useEffect(() => {
    document.documentElement.classList.toggle("motion-reduce", reducedMotion)
  }, [reducedMotion])

  useEffect(() => {
    document.documentElement.classList.toggle("high-contrast", highContrast)
  }, [highContrast])

  useEffect(() => {
    document.documentElement.style.fontSize =
      fontSize === "large" ? "112.5%" : fontSize === "x-large" ? "125%" : ""
  }, [fontSize])

  const handleReducedMotionChange = useCallback(
    (checked: boolean) => {
      setReducedMotion(checked)
      toast.success(checked ? "Reduced motion enabled" : "Reduced motion disabled")
    },
    [setReducedMotion],
  )

  const handleHighContrastChange = useCallback(
    (checked: boolean) => {
      setHighContrast(checked)
      toast.success(checked ? "High contrast enabled" : "High contrast disabled")
    },
    [setHighContrast],
  )

  const handleFontSizeChange = useCallback(
    (v: string) => {
      setFontSize(v as "default" | "large" | "x-large")
      const labels: Record<string, string> = { default: "Default", large: "Large", "x-large": "Extra Large" }
      toast.success(`Font size set to ${labels[v]}`)
    },
    [setFontSize],
  )

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-violet-500/10">
            <Accessibility className="h-4 w-4 text-violet-500" />
          </div>
          Accessibility
        </CardTitle>
        <CardDescription>Adjust settings to make the interface more comfortable and easier to use.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-2">
        <div className="flex items-center justify-between rounded-lg border border-border/60 p-4">
          <div className="space-y-0.5">
            <Label htmlFor="reduced-motion" className="text-sm font-medium">
              Reduced motion
            </Label>
            <p className="text-sm text-muted-foreground">Minimize animations and transitions throughout the interface.</p>
          </div>
          <Switch id="reduced-motion" checked={reducedMotion} onCheckedChange={handleReducedMotionChange} />
        </div>

        <div className="flex items-center justify-between rounded-lg border border-border/60 p-4">
          <div className="space-y-0.5">
            <Label htmlFor="high-contrast" className="text-sm font-medium">
              High contrast
            </Label>
            <p className="text-sm text-muted-foreground">Increase contrast between foreground and background elements.</p>
          </div>
          <Switch id="high-contrast" checked={highContrast} onCheckedChange={handleHighContrastChange} />
        </div>

        <div className="flex items-center justify-between rounded-lg border border-border/60 p-4">
          <div className="space-y-0.5">
            <Label className="flex items-center gap-1.5 text-sm font-medium">
              <Type className="h-3.5 w-3.5 text-muted-foreground" />
              Font size
            </Label>
            <p className="text-sm text-muted-foreground">
              {fontSize === "large"
                ? "Text is 12% larger than default."
                : fontSize === "x-large"
                  ? "Text is 25% larger than default."
                  : "Standard text size across the interface."}
            </p>
          </div>
          <Select value={fontSize} onValueChange={handleFontSizeChange}>
            <SelectTrigger className="w-32">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="default">Default</SelectItem>
              <SelectItem value="large">Large</SelectItem>
              <SelectItem value="x-large">Extra Large</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </CardContent>
    </Card>
  )
}

/* -----------------------------------------------------------------------
 * Active sessions section
 * ----------------------------------------------------------------------- */

interface SessionInfo {
  id: string
  device: string
  icon: React.ComponentType<{ className?: string }>
  browser: string
  ip: string
  location: string
  lastActive: string
  isCurrent: boolean
}

function parseUserAgent(ua: string): { device: string; browser: string; icon: React.ComponentType<{ className?: string }> } {
  let browser = "Unknown browser"
  if (ua.includes("Firefox")) browser = "Firefox"
  else if (ua.includes("Edg/")) browser = "Microsoft Edge"
  else if (ua.includes("Chrome") && !ua.includes("Edg/")) browser = "Google Chrome"
  else if (ua.includes("Safari") && !ua.includes("Chrome")) browser = "Safari"

  let device = "Unknown device"
  let icon: React.ComponentType<{ className?: string }> = Monitor
  if (/Android|iPhone|iPad|iPod|Mobile/i.test(ua)) {
    icon = Smartphone
    if (ua.includes("iPhone")) device = "iPhone"
    else if (ua.includes("iPad")) device = "iPad"
    else if (ua.includes("Android")) device = "Android device"
    else device = "Mobile device"
  } else {
    icon = Laptop
    if (ua.includes("Windows")) device = "Windows PC"
    else if (ua.includes("Macintosh")) device = "macOS"
    else if (ua.includes("Linux")) device = "Linux"
    else device = "Desktop"
  }

  return { device, browser, icon }
}

function ActiveSessionsSection() {
  const currentSession = useMemo<SessionInfo>(() => {
    const ua = typeof navigator !== "undefined" ? navigator.userAgent : ""
    const { device, browser, icon } = parseUserAgent(ua)
    return {
      id: "current",
      device,
      icon,
      browser,
      ip: "Current network",
      location: "This device",
      lastActive: "Active now",
      isCurrent: true,
    }
  }, [])

  const handleSignOut = useCallback((_sessionId: string) => {
    toast.info("Coming soon", {
      description: "Remote session management will be available in a future update.",
    })
  }, [])

  const handleSignOutAll = useCallback(() => {
    toast.info("Coming soon", {
      description: "The ability to sign out all other sessions will be available in a future update.",
    })
  }, [])

  const sessions: SessionInfo[] = [currentSession]

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-500/10">
            <Shield className="h-4 w-4 text-emerald-500" />
          </div>
          Active Sessions
        </CardTitle>
        <CardDescription>
          Devices and browsers where you are currently signed in.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-2">
          {sessions.map((session) => {
            const Icon = session.icon
            return (
              <div
                key={session.id}
                className={cn(
                  "flex items-center justify-between rounded-lg border p-4",
                  session.isCurrent
                    ? "border-emerald-500/30 bg-emerald-500/5"
                    : "border-border/60",
                )}
              >
                <div className="flex items-center gap-3">
                  <div
                    className={cn(
                      "flex h-10 w-10 items-center justify-center rounded-lg",
                      session.isCurrent ? "bg-emerald-500/10" : "bg-muted",
                    )}
                  >
                    <Icon
                      className={cn(
                        "h-5 w-5",
                        session.isCurrent ? "text-emerald-500" : "text-muted-foreground",
                      )}
                    />
                  </div>
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium">{session.browser}</span>
                      <span className="text-sm text-muted-foreground">on {session.device}</span>
                      {session.isCurrent && (
                        <Badge variant="default" className="bg-emerald-600 text-[0.625rem] px-1.5 py-0">
                          Current
                        </Badge>
                      )}
                    </div>
                    <div className="flex items-center gap-3 text-xs text-muted-foreground">
                      <span className="flex items-center gap-1">
                        <Globe className="h-3 w-3" />
                        {session.ip}
                      </span>
                      <span>{session.lastActive}</span>
                    </div>
                  </div>
                </div>
                {!session.isCurrent && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleSignOut(session.id)}
                    className="text-destructive hover:bg-destructive/10 hover:text-destructive"
                  >
                    <LogOut className="mr-1.5 h-3.5 w-3.5" />
                    Sign out
                  </Button>
                )}
              </div>
            )
          })}
        </div>

        <Separator />

        <div className="flex items-center justify-between">
          <p className="text-xs text-muted-foreground">
            Session management is limited to the current session. Full session history and remote sign-out coming soon.
          </p>
          <Button
            variant="outline"
            size="sm"
            onClick={handleSignOutAll}
            className="shrink-0 text-destructive hover:bg-destructive/10 hover:text-destructive"
          >
            <LogOut className="mr-1.5 h-3.5 w-3.5" />
            Sign out all other sessions
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}

/* -----------------------------------------------------------------------
 * Keyboard shortcuts section
 * ----------------------------------------------------------------------- */

function Kbd({ children }: { children: React.ReactNode }) {
  return (
    <kbd className="inline-flex h-5 min-w-5 items-center justify-center rounded border border-border bg-muted px-1.5 font-mono text-[0.6875rem] font-medium text-muted-foreground">
      {children}
    </kbd>
  )
}

const SHORTCUTS = [
  {
    category: "Navigation",
    items: [
      { keys: ["G", "H"], description: "Go to Home" },
      { keys: ["G", "T"], description: "Go to Teams" },
      { keys: ["G", "D"], description: "Go to Devices" },
      { keys: ["G", "V"], description: "Go to Voice" },
      { keys: ["G", "F"], description: "Go to Fax" },
      { keys: ["G", "S"], description: "Go to Support" },
      { keys: ["G", "L"], description: "Go to Locations" },
      { keys: ["G", "R"], description: "Go to Call Routing" },
      { keys: ["G", "E"], description: "Go to Schedules" },
      { keys: ["G", "Y"], description: "Go to Analytics" },
      { keys: ["G", "N"], description: "Go to Notifications" },
      { keys: ["G", "O"], description: "Go to Organization" },
      { keys: ["G", "P"], description: "Go to Profile" },
      { keys: ["G", "A"], description: "Go to Admin" },
      { keys: ["G", "C"], description: "Go to Connections" },
    ],
  },
  {
    category: "Actions",
    items: [
      { keys: ["Ctrl", "K"], description: "Open global search" },
      { keys: ["Ctrl", "Shift", "N"], description: "New ticket" },
      { keys: ["N"], description: "Create new item (context-dependent)" },
      { keys: ["?"], description: "Show all shortcuts" },
      { keys: ["Esc"], description: "Close dialog / cancel" },
    ],
  },
]

function KeyboardShortcutsSection() {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-amber-500/10">
            <Keyboard className="h-4 w-4 text-amber-500" />
          </div>
          Keyboard Shortcuts
        </CardTitle>
        <CardDescription>Navigate and perform actions quickly without leaving the keyboard.</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-6">
          {SHORTCUTS.map((group) => (
            <div key={group.category}>
              <h4 className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                {group.category}
              </h4>
              <div className="space-y-1">
                {group.items.map((shortcut) => (
                  <div
                    key={shortcut.description}
                    className="flex items-center justify-between rounded-lg px-3 py-2.5 transition-colors hover:bg-muted/50"
                  >
                    <span className="text-sm text-foreground">{shortcut.description}</span>
                    <div className="flex items-center gap-1">
                      {shortcut.keys.map((key, i) => (
                        <span key={`${shortcut.description}-${key}-${i}`} className="flex items-center gap-1">
                          {i > 0 && <span className="text-xs text-muted-foreground">+</span>}
                          <Kbd>{key}</Kbd>
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
        <Separator className="my-4" />
        <Tooltip>
          <TooltipTrigger asChild>
            <p className="text-xs text-muted-foreground">
              Press <Kbd>?</Kbd> anywhere to view the full list of keyboard shortcuts.
            </p>
          </TooltipTrigger>
          <TooltipContent>Opens the keyboard shortcuts dialog</TooltipContent>
        </Tooltip>
      </CardContent>
    </Card>
  )
}
