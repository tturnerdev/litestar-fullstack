import { useQueryClient } from "@tanstack/react-query"
import { createFileRoute, Link, useNavigate, useSearch } from "@tanstack/react-router"
import {
  AlertCircle,
  ArrowRight,
  Bell,
  Calendar,
  CheckCircle2,
  ChevronRight,
  Circle,
  Download,
  FileJson,
  FileSpreadsheet,
  Home,
  KeyRound,
  KeySquare,
  Link2,
  Loader2,
  Mail,
  Monitor,
  Palette,
  Phone,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  User as UserIcon,
  Users,
} from "lucide-react"
import { useCallback, useEffect, useMemo, useState } from "react"
import { toast } from "sonner"
import { z } from "zod"
import { ActiveSessions } from "@/components/profile/active-sessions"
import { ConnectedAccounts } from "@/components/profile/connected-accounts"
import { MfaSection } from "@/components/profile/mfa-section"
import { PasswordChangeCard } from "@/components/profile/password-change-card"
import { PersonalInfoForm } from "@/components/profile/personal-info-form"
import { ProfileHero } from "@/components/profile/profile-hero"
import { RecentSecurityActivity } from "@/components/profile/recent-security-activity"
import { Badge } from "@/components/ui/badge"
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { EmptyState } from "@/components/ui/empty-state"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { Separator } from "@/components/ui/separator"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { useMfaStatus } from "@/lib/api/hooks/auth"
import { useProfile } from "@/lib/api/hooks/profile"
import { useAuthStore } from "@/lib/auth"
import { formatDateLong } from "@/lib/date-utils"
import { profileOAuthAccountsQueryKey } from "@/lib/generated/api/@tanstack/react-query.gen"
import type { User } from "@/lib/generated/api/types.gen"
import { useNotificationPreferencesStore } from "@/lib/notification-preferences-store"
import { useSettingsStore } from "@/lib/settings-store"
import { useTheme } from "@/lib/theme-context"

const profileSearchSchema = z
  .object({
    provider: z.string().optional(),
    action: z.string().optional(),
    linked: z.coerce.string().optional(),
    oauth_failed: z.string().optional(),
    message: z.string().optional(),
  })
  .passthrough()

export const Route = createFileRoute("/_app/profile/")({
  validateSearch: (search) => profileSearchSchema.parse(search),
  component: ProfilePage,
})

function SectionHeading({ icon: Icon, title, description }: { icon: React.ComponentType<{ className?: string }>; title: string; description?: string }) {
  return (
    <div className="space-y-1">
      <h3 className="flex items-center gap-2 text-lg font-semibold tracking-tight">
        <Icon className="h-5 w-5 text-muted-foreground" />
        {title}
      </h3>
      {description && <p className="text-sm text-muted-foreground">{description}</p>}
    </div>
  )
}

function InfoRow({ icon: Icon, label, children }: { icon: React.ComponentType<{ className?: string }>; label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start gap-3 py-2.5">
      <Icon className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
      <div className="min-w-0 flex-1">
        <p className="text-xs font-medium text-muted-foreground">{label}</p>
        <div className="mt-0.5 text-sm">{children}</div>
      </div>
    </div>
  )
}

function AccountInfoCard({ user }: { user: User }) {
  const roleNames = user.roles?.map((r) => r.roleName) ?? []
  const teamNames = user.teams?.map((t) => t.teamName) ?? []
  const earliestRole = user.roles?.reduce<string | null>((earliest, r) => {
    if (!earliest) return r.assignedAt
    return r.assignedAt < earliest ? r.assignedAt : earliest
  }, null)

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <UserIcon className="h-4 w-4 text-muted-foreground" />
          Account information
        </CardTitle>
        <CardDescription>Your account details and membership.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-0 divide-y">
        <InfoRow icon={Mail} label="Email">
          {user.email}
        </InfoRow>
        {user.username && (
          <InfoRow icon={UserIcon} label="Username">
            @{user.username}
          </InfoRow>
        )}
        {user.phone && (
          <InfoRow icon={Phone} label="Phone">
            {user.phone}
          </InfoRow>
        )}
        <InfoRow icon={KeyRound} label="Role">
          {roleNames.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {roleNames.map((role) => (
                <Badge key={role} variant="outline" className="capitalize">
                  {role}
                </Badge>
              ))}
            </div>
          ) : (
            <span className="text-muted-foreground">No roles assigned</span>
          )}
        </InfoRow>
        {teamNames.length > 0 && (
          <InfoRow icon={Users} label="Teams">
            <div className="flex flex-wrap gap-1.5">
              {teamNames.map((name) => (
                <Badge key={name} variant="secondary">
                  {name}
                </Badge>
              ))}
            </div>
          </InfoRow>
        )}
        <InfoRow icon={CheckCircle2} label="Account status">
          <Badge variant={user.isActive ? "default" : "destructive"} className="gap-1">
            {user.isActive ? "Active" : "Inactive"}
          </Badge>
        </InfoRow>
        {earliestRole && (
          <InfoRow icon={Calendar} label="Member since">
            {formatDateLong(earliestRole)}
          </InfoRow>
        )}
      </CardContent>
    </Card>
  )
}

function MfaSummaryCard() {
  const { data, isLoading } = useMfaStatus()

  if (isLoading) {
    return <SkeletonCard />
  }

  const enabled = data?.enabled ?? false

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Shield className="h-4 w-4 text-muted-foreground" />
          Security status
        </CardTitle>
        <CardDescription>Multi-factor authentication overview.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {enabled ? (
          <div className="flex items-start gap-4 rounded-lg border border-green-200 bg-green-50 p-4 dark:border-green-900 dark:bg-green-950/30">
            <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-full bg-green-100 dark:bg-green-900/50">
              <ShieldCheck className="h-6 w-6 text-green-600 dark:text-green-400" />
            </div>
            <div className="min-w-0 flex-1">
              <p className="font-medium text-green-800 dark:text-green-300">Two-factor authentication is enabled</p>
              <p className="mt-1 text-sm text-green-600 dark:text-green-400">
                Your account is protected with an authenticator app.
                {data?.confirmedAt && <span className="block mt-1 text-xs">Enabled on {formatDateLong(data.confirmedAt)}.</span>}
              </p>
            </div>
          </div>
        ) : (
          <div className="flex items-start gap-4 rounded-lg border border-amber-200 bg-amber-50 p-4 dark:border-amber-900 dark:bg-amber-950/30">
            <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-full bg-amber-100 dark:bg-amber-900/50">
              <ShieldAlert className="h-6 w-6 text-amber-600 dark:text-amber-400" />
            </div>
            <div className="min-w-0 flex-1">
              <p className="font-medium text-amber-800 dark:text-amber-300">Two-factor authentication is not enabled</p>
              <p className="mt-1 text-sm text-amber-600 dark:text-amber-400">We strongly recommend enabling MFA to add an extra layer of security to your account.</p>
            </div>
          </div>
        )}

        {enabled && data?.backupCodesRemaining != null && (
          <div className="rounded-md border bg-muted/30 px-4 py-3">
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">Backup codes remaining</span>
              <span className={`font-medium tabular-nums ${data.backupCodesRemaining > 5 ? "text-green-600" : data.backupCodesRemaining > 2 ? "text-amber-600" : "text-red-600"}`}>
                {data.backupCodesRemaining} of 10
              </span>
            </div>
          </div>
        )}

        {!enabled && <p className="text-xs text-muted-foreground">Scroll to the Security section below to set up MFA.</p>}
      </CardContent>
    </Card>
  )
}

function QuickLinksCard() {
  const links = [
    {
      icon: Palette,
      title: "Appearance",
      description: "Theme, compact mode, and visual preferences",
      href: "/settings" as const,
    },
    {
      icon: Bell,
      title: "Notifications",
      description: "Email and in-app notification preferences",
      href: "/settings" as const,
    },
    {
      icon: Monitor,
      title: "Display",
      description: "Page size, date format, and sidebar settings",
      href: "/settings" as const,
    },
  ]

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <ArrowRight className="h-4 w-4 text-muted-foreground" />
          Quick links
        </CardTitle>
        <CardDescription>Jump to related settings and preferences.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-1">
        {links.map((link) => {
          const LinkIcon = link.icon
          return (
            <Link key={link.title} to={link.href} className="group flex items-center gap-3 rounded-lg px-3 py-2.5 transition-colors hover:bg-accent">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-muted group-hover:bg-background">
                <LinkIcon className="h-4 w-4 text-muted-foreground" />
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium">{link.title}</p>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <p className="truncate text-xs text-muted-foreground">{link.description}</p>
                  </TooltipTrigger>
                  <TooltipContent side="bottom" className="max-w-sm">
                    <p>{link.description}</p>
                  </TooltipContent>
                </Tooltip>
              </div>
              <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground/50 transition-transform group-hover:translate-x-0.5" />
            </Link>
          )
        })}
      </CardContent>
    </Card>
  )
}

interface CompletionStep {
  label: string
  completed: boolean
  sectionId?: string
}

function ProfileCompletenessCard({ user }: { user: User }) {
  const completionSteps: CompletionStep[] = useMemo(() => {
    return [
      { label: "Set display name", completed: !!user.name && user.name.trim() !== "", sectionId: "personal-info" },
      { label: "Add email address", completed: !!user.email },
      { label: "Verify email", completed: user.isVerified === true },
      { label: "Set up MFA", completed: user.isTwoFactorEnabled === true, sectionId: "security" },
      { label: "Join a team", completed: (user.teams?.length ?? 0) > 0 },
      { label: "Upload avatar", completed: !!user.avatarUrl },
    ]
  }, [user.name, user.email, user.isVerified, user.isTwoFactorEnabled, user.teams, user.avatarUrl])

  const completedCount = completionSteps.filter((s) => s.completed).length
  const totalSteps = completionSteps.length
  const percentage = Math.round((completedCount / totalSteps) * 100)

  if (percentage === 100) {
    return (
      <Card className="border-green-200 bg-green-50/50 dark:border-green-900 dark:bg-green-950/20">
        <CardContent className="flex items-center gap-3 py-4">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-green-100 dark:bg-green-900/50">
            <Sparkles className="h-5 w-5 text-green-600 dark:text-green-400" />
          </div>
          <div>
            <p className="text-sm font-medium text-green-800 dark:text-green-300">Profile complete</p>
            <p className="text-xs text-green-600 dark:text-green-400">Great job! Your profile is fully set up.</p>
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base">Profile completeness</CardTitle>
        <CardDescription>
          {percentage}% complete &mdash; {totalSteps - completedCount} {totalSteps - completedCount === 1 ? "step" : "steps"} remaining
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Progress bar */}
        <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
          <div className="h-full rounded-full bg-primary transition-all duration-500" style={{ width: `${percentage}%` }} />
        </div>

        {/* Steps checklist */}
        <ul className="grid gap-1.5 sm:grid-cols-2">
          {completionSteps.map((step) => (
            <li key={step.label}>
              {!step.completed && step.sectionId ? (
                <button
                  type="button"
                  onClick={() => {
                    document.getElementById(step.sectionId as string)?.scrollIntoView({ behavior: "smooth", block: "start" })
                  }}
                  className="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm transition-colors hover:bg-accent"
                >
                  <Circle className="h-4 w-4 shrink-0 text-muted-foreground/50" />
                  <span className="text-muted-foreground">{step.label}</span>
                </button>
              ) : (
                <div className="flex items-center gap-2 px-2 py-1.5 text-sm">
                  {step.completed ? (
                    <CheckCircle2 className="h-4 w-4 shrink-0 text-green-600 dark:text-green-400" />
                  ) : (
                    <Circle className="h-4 w-4 shrink-0 text-muted-foreground/50" />
                  )}
                  <span className={step.completed ? "text-foreground" : "text-muted-foreground"}>{step.label}</span>
                </div>
              )}
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  )
}

function ApiKeysCard() {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <KeySquare className="h-4 w-4 text-muted-foreground" />
          API Keys
        </CardTitle>
        <CardDescription>Programmatic access to the admin portal API.</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="rounded-lg border border-dashed bg-muted/30 p-6">
          <div className="flex items-start gap-4">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-muted">
              <KeySquare className="h-5 w-5 text-muted-foreground" />
            </div>
            <div className="space-y-1.5">
              <div className="flex items-center gap-2">
                <p className="text-sm font-medium">Coming soon</p>
                <Badge variant="secondary" className="text-xs">
                  Planned
                </Badge>
              </div>
              <p className="text-sm text-muted-foreground">
                API key management will let you generate and revoke personal access tokens for authenticating with the admin portal API. Use them to integrate with external tools,
                scripts, and CI/CD pipelines without relying on your browser session.
              </p>
              <ul className="mt-3 space-y-1 text-xs text-muted-foreground">
                <li className="flex items-center gap-1.5">
                  <Circle className="h-1.5 w-1.5 fill-current" /> Scoped permissions per key
                </li>
                <li className="flex items-center gap-1.5">
                  <Circle className="h-1.5 w-1.5 fill-current" /> Configurable expiration dates
                </li>
                <li className="flex items-center gap-1.5">
                  <Circle className="h-1.5 w-1.5 fill-current" /> Usage audit logging
                </li>
              </ul>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

function downloadFile(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType })
  const url = URL.createObjectURL(blob)
  const a = document.createElement("a")
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

function flattenForCsv(obj: Record<string, unknown>, prefix = ""): Record<string, string> {
  const result: Record<string, string> = {}
  for (const [key, value] of Object.entries(obj)) {
    const fullKey = prefix ? `${prefix}.${key}` : key
    if (value !== null && typeof value === "object" && !Array.isArray(value)) {
      Object.assign(result, flattenForCsv(value as Record<string, unknown>, fullKey))
    } else if (Array.isArray(value)) {
      result[fullKey] = value.map((v) => (typeof v === "object" ? JSON.stringify(v) : String(v))).join("; ")
    } else {
      result[fullKey] = value == null ? "" : String(value)
    }
  }
  return result
}

function objectToCsv(data: Record<string, unknown>): string {
  const flat = flattenForCsv(data)
  const keys = Object.keys(flat)
  const escapeCsv = (val: string) => {
    if (val.includes(",") || val.includes('"') || val.includes("\n")) {
      return `"${val.replace(/"/g, '""')}"`
    }
    return val
  }
  const header = keys.map(escapeCsv).join(",")
  const row = keys.map((k) => escapeCsv(flat[k])).join(",")
  return `${header}\n${row}\n`
}

type ExportFormat = "json" | "csv"

interface ExportSection {
  id: string
  label: string
  description: string
}

const EXPORT_SECTIONS: ExportSection[] = [
  { id: "profile", label: "Profile information", description: "Name, email, phone, username" },
  { id: "teams", label: "Team memberships", description: "Teams you belong to and your roles" },
  { id: "preferences", label: "Preferences", description: "Theme, display, and accessibility settings" },
  { id: "notifications", label: "Notification preferences", description: "Notification category settings" },
  { id: "security", label: "Security overview", description: "MFA status and connected OAuth accounts" },
]

function DataExportCard({ user }: { user: User }) {
  const { mode } = useTheme()
  const { compactMode, dateFormat, reducedMotion, highContrast, fontSize } = useSettingsStore()
  const { systemAlerts, taskUpdates, teamActivity, supportTickets, deviceAlerts, security: securityPref } = useNotificationPreferencesStore()
  const { data: mfaData } = useMfaStatus()

  const [format, setFormat] = useState<ExportFormat>("json")
  const [selectedSections, setSelectedSections] = useState<Set<string>>(() => new Set(EXPORT_SECTIONS.map((s) => s.id)))
  const [isExporting, setIsExporting] = useState(false)
  const [exportProgress, setExportProgress] = useState(0)

  const allSelected = selectedSections.size === EXPORT_SECTIONS.length
  const noneSelected = selectedSections.size === 0

  const toggleSection = useCallback((id: string) => {
    setSelectedSections((prev) => {
      const next = new Set(prev)
      if (next.has(id)) {
        next.delete(id)
      } else {
        next.add(id)
      }
      return next
    })
  }, [])

  const toggleAll = useCallback(() => {
    if (allSelected) {
      setSelectedSections(new Set())
    } else {
      setSelectedSections(new Set(EXPORT_SECTIONS.map((s) => s.id)))
    }
  }, [allSelected])

  const buildExportData = useCallback(() => {
    const data: Record<string, unknown> = {
      exportedAt: new Date().toISOString(),
      exportFormat: format,
    }

    if (selectedSections.has("profile")) {
      data.profile = {
        name: user.name ?? null,
        email: user.email,
        phone: user.phone ?? null,
        username: user.username ?? null,
        isActive: user.isActive ?? false,
        isVerified: user.isVerified ?? false,
      }
    }

    if (selectedSections.has("teams")) {
      data.teamMemberships = (user.teams ?? []).map((t) => ({
        teamName: t.teamName,
        teamId: t.teamId,
        role: t.role ?? "member",
        isOwner: t.isOwner ?? false,
      }))
    }

    if (selectedSections.has("preferences")) {
      data.preferences = {
        theme: mode,
        compactMode,
        dateFormat,
        reducedMotion,
        highContrast,
        fontSize,
      }
    }

    if (selectedSections.has("notifications")) {
      data.notificationPreferences = {
        systemAlerts,
        taskUpdates,
        teamActivity,
        supportTickets,
        deviceAlerts,
        security: securityPref,
      }
    }

    if (selectedSections.has("security")) {
      data.securityOverview = {
        mfaEnabled: user.isTwoFactorEnabled ?? false,
        mfaConfirmedAt: mfaData?.confirmedAt ?? null,
        backupCodesRemaining: mfaData?.backupCodesRemaining ?? null,
        connectedOAuthProviders: (user.oauthAccounts ?? []).map((a) => a.oauthName),
        roles: (user.roles ?? []).map((r) => ({
          roleName: r.roleName,
          assignedAt: r.assignedAt,
        })),
      }
    }

    return data
  }, [
    format,
    selectedSections,
    user,
    mode,
    compactMode,
    dateFormat,
    reducedMotion,
    highContrast,
    fontSize,
    systemAlerts,
    taskUpdates,
    teamActivity,
    supportTickets,
    deviceAlerts,
    securityPref,
    mfaData,
  ])

  const handleExport = useCallback(async () => {
    if (noneSelected) {
      toast.error("Select at least one data category to export.")
      return
    }

    setIsExporting(true)
    setExportProgress(0)

    // Simulate progress steps for data assembly
    const progressSteps = [10, 30, 55, 75, 90, 100]
    for (const step of progressSteps) {
      await new Promise((resolve) => setTimeout(resolve, 120))
      setExportProgress(step)
    }

    const data = buildExportData()
    const date = new Date().toISOString().slice(0, 10)

    if (format === "json") {
      downloadFile(JSON.stringify(data, null, 2), `profile-export-${date}.json`, "application/json")
    } else {
      downloadFile(objectToCsv(data), `profile-export-${date}.csv`, "text/csv")
    }

    // Brief pause to show 100% complete
    await new Promise((resolve) => setTimeout(resolve, 300))
    setIsExporting(false)
    setExportProgress(0)
    toast.success("Your data export has been downloaded.")
  }, [format, noneSelected, buildExportData])

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Download className="h-4 w-4 text-muted-foreground" />
          Export your data
        </CardTitle>
        <CardDescription>Download a copy of your personal data. Choose which categories to include and your preferred file format.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Format selection */}
        <div className="space-y-3">
          <p className="text-sm font-medium">Export format</p>
          <RadioGroup value={format} onValueChange={(v) => setFormat(v as ExportFormat)} className="flex gap-4">
            <div className="flex items-center gap-2">
              <RadioGroupItem value="json" id="format-json" />
              <Label htmlFor="format-json" className="flex cursor-pointer items-center gap-1.5 text-sm font-normal">
                <FileJson className="h-4 w-4 text-muted-foreground" />
                JSON
              </Label>
            </div>
            <div className="flex items-center gap-2">
              <RadioGroupItem value="csv" id="format-csv" />
              <Label htmlFor="format-csv" className="flex cursor-pointer items-center gap-1.5 text-sm font-normal">
                <FileSpreadsheet className="h-4 w-4 text-muted-foreground" />
                CSV
              </Label>
            </div>
          </RadioGroup>
        </div>

        <Separator />

        {/* Data categories */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-sm font-medium">Data to include</p>
            <button type="button" onClick={toggleAll} className="text-xs font-medium text-primary hover:underline">
              {allSelected ? "Deselect all" : "Select all"}
            </button>
          </div>
          <div className="space-y-2">
            {EXPORT_SECTIONS.map((section) => (
              <label
                key={section.id}
                htmlFor={`export-${section.id}`}
                className="flex cursor-pointer items-start gap-3 rounded-lg border px-3 py-2.5 transition-colors hover:bg-accent/50"
              >
                <Checkbox
                  id={`export-${section.id}`}
                  checked={selectedSections.has(section.id)}
                  onChange={() => toggleSection(section.id)}
                  className="mt-0.5"
                  disabled={isExporting}
                />
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium leading-tight">{section.label}</p>
                  <p className="mt-0.5 text-xs text-muted-foreground">{section.description}</p>
                </div>
              </label>
            ))}
          </div>
        </div>

        {/* Export progress */}
        {isExporting && (
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs text-muted-foreground">
              <span className="flex items-center gap-1.5">
                <Loader2 className="h-3 w-3 animate-spin" />
                Preparing export...
              </span>
              <span className="tabular-nums">{exportProgress}%</span>
            </div>
            <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
              <div className="h-full rounded-full bg-primary transition-all duration-200 ease-out" style={{ width: `${exportProgress}%` }} />
            </div>
          </div>
        )}

        {/* Export button */}
        <Button variant="outline" size="sm" onClick={handleExport} disabled={isExporting || noneSelected}>
          {isExporting ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              Exporting...
            </>
          ) : (
            <>
              <Download className="mr-2 h-4 w-4" />
              Export {selectedSections.size} {selectedSections.size === 1 ? "category" : "categories"} as {format.toUpperCase()}
            </>
          )}
        </Button>
      </CardContent>
    </Card>
  )
}

function ProfilePage() {
  useDocumentTitle("Profile")
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const searchParams = useSearch({ from: "/_app/profile/" })
  const authUser = useAuthStore((s) => s.user)
  const { data: profile, isLoading, isError } = useProfile()

  const user = profile ?? authUser

  useEffect(() => {
    if (searchParams.linked === "true" && searchParams.provider) {
      queryClient.invalidateQueries({ queryKey: profileOAuthAccountsQueryKey() })
      const providerName = searchParams.provider.charAt(0).toUpperCase() + searchParams.provider.slice(1)
      toast.success(`Successfully linked ${providerName} account`)
      void navigate({ to: "/profile", replace: true })
      return
    }
    if (searchParams.oauth_failed) {
      toast.error(searchParams.message || "Failed to link account")
      void navigate({ to: "/profile", replace: true })
    }
  }, [searchParams, queryClient, navigate])

  if (isLoading && !user) {
    return (
      <PageContainer className="flex-1 space-y-8" maxWidth="4xl">
        <PageHeader eyebrow="Account" title="Profile" description="Manage your personal information, security, and connected accounts." />
        <PageSection>
          <SkeletonCard />
          <SkeletonCard />
        </PageSection>
      </PageContainer>
    )
  }

  if (isError) {
    return (
      <PageContainer className="flex-1 space-y-8" maxWidth="4xl">
        <PageHeader eyebrow="Account" title="Profile" description="Manage your personal information, security, and connected accounts." />
        <PageSection>
          <EmptyState
            icon={AlertCircle}
            title="Unable to load profile"
            description="Something went wrong. Please try refreshing the page."
            action={
              <Button variant="outline" size="sm" onClick={() => window.location.reload()}>
                Refresh page
              </Button>
            }
          />
        </PageSection>
      </PageContainer>
    )
  }

  if (!user) {
    return null
  }

  return (
    <PageContainer className="flex-1 space-y-10" maxWidth="4xl">
      <PageHeader
        eyebrow="Account"
        title="Profile"
        description="Manage your personal information, security, and connected accounts."
        breadcrumbs={
          <Breadcrumb>
            <BreadcrumbList>
              <BreadcrumbItem>
                <BreadcrumbLink asChild>
                  <Link to="/">
                    <Home className="h-3.5 w-3.5" />
                  </Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbPage>Profile</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
      />

      {/* Profile completeness indicator */}
      <PageSection>
        <SectionErrorBoundary name="Profile Completeness">
          <ProfileCompletenessCard user={user} />
        </SectionErrorBoundary>
      </PageSection>

      {/* Hero / avatar section */}
      <PageSection>
        <SectionErrorBoundary name="Profile Hero">
          <ProfileHero user={user} />
        </SectionErrorBoundary>
      </PageSection>

      {/* Account overview cards */}
      <PageSection delay={0.05}>
        <div className="grid gap-6 lg:grid-cols-2">
          <SectionErrorBoundary name="Account Information">
            <AccountInfoCard user={user} />
          </SectionErrorBoundary>
          <SectionErrorBoundary name="Security Status">
            <MfaSummaryCard />
          </SectionErrorBoundary>
        </div>
      </PageSection>

      <Separator />

      {/* Personal information */}
      <PageSection delay={0.1} id="personal-info">
        <SectionHeading icon={UserIcon} title="Personal information" description="Update your name, username, and contact details." />
        <SectionErrorBoundary name="Personal Information">
          <PersonalInfoForm user={user} />
        </SectionErrorBoundary>
      </PageSection>

      <Separator />

      {/* Security section */}
      <PageSection delay={0.2} id="security">
        <SectionHeading icon={Shield} title="Security" description="Manage your password and multi-factor authentication." />
        <div className="grid gap-6 lg:grid-cols-2">
          <SectionErrorBoundary name="Password">
            <PasswordChangeCard />
          </SectionErrorBoundary>
          <SectionErrorBoundary name="Multi-Factor Authentication">
            <MfaSection />
          </SectionErrorBoundary>
        </div>
        <SectionErrorBoundary name="Recent Security Activity">
          <RecentSecurityActivity />
        </SectionErrorBoundary>
      </PageSection>

      <Separator />

      {/* Connected accounts & sessions in a two-column layout */}
      <PageSection delay={0.3}>
        <SectionHeading icon={Link2} title="Connected accounts" description="Manage linked OAuth providers and active sessions." />
        <div className="grid gap-6 lg:grid-cols-2">
          <SectionErrorBoundary name="Connected Accounts">
            <ConnectedAccounts />
          </SectionErrorBoundary>
          <SectionErrorBoundary name="Active Sessions">
            <ActiveSessions />
          </SectionErrorBoundary>
        </div>
      </PageSection>

      <Separator />

      {/* API Keys */}
      <PageSection delay={0.35}>
        <SectionErrorBoundary name="API Keys">
          <ApiKeysCard />
        </SectionErrorBoundary>
      </PageSection>

      <Separator />

      {/* Data export */}
      <PageSection delay={0.4}>
        <SectionErrorBoundary name="Data Export">
          <DataExportCard user={user} />
        </SectionErrorBoundary>
      </PageSection>

      <Separator />

      {/* Quick links to Settings */}
      <PageSection delay={0.5}>
        <SectionErrorBoundary name="Quick Links">
          <QuickLinksCard />
        </SectionErrorBoundary>
      </PageSection>
    </PageContainer>
  )
}
