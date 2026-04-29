import { createFileRoute } from "@tanstack/react-router"
import { Calendar, Hash, Layout, Monitor, Moon, PanelLeftClose, Sun } from "lucide-react"
import { NotificationPreferences } from "@/components/settings/notification-preferences"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { useSettingsStore } from "@/lib/settings-store"
import { useTheme } from "@/lib/theme-context"

export const Route = createFileRoute("/_app/settings")({
  component: SettingsPage,
})

function SettingsPage() {
  return (
    <PageContainer className="flex-1 space-y-8" maxWidth="xl">
      <PageHeader eyebrow="Preferences" title="Settings" description="Customize the look and behavior of the application." />

      <PageSection delay={0.1}>
        <div className="space-y-6">
          <AppearanceSection />
          <NotificationPreferences />
          <DisplaySection />
        </div>
      </PageSection>
    </PageContainer>
  )
}

function AppearanceSection() {
  const { mode, setMode } = useTheme()
  const { compactMode, setCompactMode } = useSettingsStore()

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Sun className="h-5 w-5 text-muted-foreground" />
          Appearance
        </CardTitle>
        <CardDescription>Control how the application looks on your device.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="space-y-3">
          <Label className="text-sm font-medium">Theme</Label>
          <RadioGroup value={mode} onValueChange={(v) => setMode(v as "light" | "dark" | "system")} className="grid grid-cols-3 gap-3">
            <Label
              htmlFor="theme-light"
              className="flex cursor-pointer flex-col items-center gap-2 rounded-lg border border-border/60 p-4 transition-colors hover:bg-accent has-[button[data-state=checked]]:border-primary has-[button[data-state=checked]]:bg-primary/5"
            >
              <RadioGroupItem value="light" id="theme-light" className="sr-only" />
              <Sun className="h-6 w-6" />
              <span className="text-sm font-medium">Light</span>
            </Label>
            <Label
              htmlFor="theme-dark"
              className="flex cursor-pointer flex-col items-center gap-2 rounded-lg border border-border/60 p-4 transition-colors hover:bg-accent has-[button[data-state=checked]]:border-primary has-[button[data-state=checked]]:bg-primary/5"
            >
              <RadioGroupItem value="dark" id="theme-dark" className="sr-only" />
              <Moon className="h-6 w-6" />
              <span className="text-sm font-medium">Dark</span>
            </Label>
            <Label
              htmlFor="theme-system"
              className="flex cursor-pointer flex-col items-center gap-2 rounded-lg border border-border/60 p-4 transition-colors hover:bg-accent has-[button[data-state=checked]]:border-primary has-[button[data-state=checked]]:bg-primary/5"
            >
              <RadioGroupItem value="system" id="theme-system" className="sr-only" />
              <Monitor className="h-6 w-6" />
              <span className="text-sm font-medium">System</span>
            </Label>
          </RadioGroup>
        </div>

        <div className="flex items-center justify-between">
          <div className="space-y-0.5">
            <Label htmlFor="compact-mode" className="text-sm font-medium">
              Compact mode
            </Label>
            <p className="text-sm text-muted-foreground">Reduce padding and spacing throughout the interface.</p>
          </div>
          <Switch id="compact-mode" checked={compactMode} onCheckedChange={setCompactMode} />
        </div>
      </CardContent>
    </Card>
  )
}

function DisplaySection() {
  const { defaultPageSize, setDefaultPageSize, dateFormat, setDateFormat, sidebarCollapsed, setSidebarCollapsed } = useSettingsStore()

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Layout className="h-5 w-5 text-muted-foreground" />
          Display Preferences
        </CardTitle>
        <CardDescription>Configure how data is displayed across the application.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="flex items-center justify-between">
          <div className="space-y-0.5">
            <Label className="flex items-center gap-1.5 text-sm font-medium">
              <Hash className="h-3.5 w-3.5" />
              Default page size
            </Label>
            <p className="text-sm text-muted-foreground">Number of rows displayed per page in tables.</p>
          </div>
          <Select value={String(defaultPageSize)} onValueChange={(v) => setDefaultPageSize(Number(v) as 10 | 25 | 50 | 100)}>
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

        <div className="flex items-center justify-between">
          <div className="space-y-0.5">
            <Label className="flex items-center gap-1.5 text-sm font-medium">
              <Calendar className="h-3.5 w-3.5" />
              Date format
            </Label>
            <p className="text-sm text-muted-foreground">
              {dateFormat === "relative" ? 'Show dates like "2h ago" or "yesterday".' : "Show dates like \"Apr 28, 2026\"."}
            </p>
          </div>
          <Select value={dateFormat} onValueChange={(v) => setDateFormat(v as "relative" | "absolute")}>
            <SelectTrigger className="w-32">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="relative">Relative</SelectItem>
              <SelectItem value="absolute">Absolute</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <div className="flex items-center justify-between">
          <div className="space-y-0.5">
            <Label htmlFor="sidebar-collapsed" className="flex items-center gap-1.5 text-sm font-medium">
              <PanelLeftClose className="h-3.5 w-3.5" />
              Sidebar collapsed by default
            </Label>
            <p className="text-sm text-muted-foreground">Start with the sidebar in its collapsed state.</p>
          </div>
          <Switch id="sidebar-collapsed" checked={sidebarCollapsed} onCheckedChange={setSidebarCollapsed} />
        </div>
      </CardContent>
    </Card>
  )
}
