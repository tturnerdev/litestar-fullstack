import { useQueryClient } from "@tanstack/react-query"
import { Link, createFileRoute, useNavigate, useSearch } from "@tanstack/react-router"
import { AlertCircle, ArrowRight, Bell, Calendar, CheckCircle2, ChevronRight, Circle, KeyRound, Link2, Mail, Monitor, Palette, Phone, Shield, ShieldAlert, ShieldCheck, Sparkles, User as UserIcon, Users } from "lucide-react"
import { useEffect, useMemo } from "react"
import { toast } from "sonner"
import { z } from "zod"
import { ActiveSessions } from "@/components/profile/active-sessions"
import { ConnectedAccounts } from "@/components/profile/connected-accounts"
import { MfaSection } from "@/components/profile/mfa-section"
import { PasswordChangeCard } from "@/components/profile/password-change-card"
import { RecentSecurityActivity } from "@/components/profile/recent-security-activity"
import { PersonalInfoForm } from "@/components/profile/personal-info-form"
import { ProfileHero } from "@/components/profile/profile-hero"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { EmptyState } from "@/components/ui/empty-state"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Separator } from "@/components/ui/separator"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { SkeletonCard } from "@/components/ui/skeleton"
import { useMfaStatus } from "@/lib/api/hooks/auth"
import { useProfile } from "@/lib/api/hooks/profile"
import { profileOAuthAccountsQueryKey } from "@/lib/generated/api/@tanstack/react-query.gen"
import type { User } from "@/lib/generated/api/types.gen"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { useAuthStore } from "@/lib/auth"
import { formatDateLong } from "@/lib/date-utils"

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
              <p className="font-medium text-green-800 dark:text-green-300">
                Two-factor authentication is enabled
              </p>
              <p className="mt-1 text-sm text-green-600 dark:text-green-400">
                Your account is protected with an authenticator app.
                {data?.confirmedAt && (
                  <span className="block mt-1 text-xs">
                    Enabled on {formatDateLong(data.confirmedAt)}.
                  </span>
                )}
              </p>
            </div>
          </div>
        ) : (
          <div className="flex items-start gap-4 rounded-lg border border-amber-200 bg-amber-50 p-4 dark:border-amber-900 dark:bg-amber-950/30">
            <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-full bg-amber-100 dark:bg-amber-900/50">
              <ShieldAlert className="h-6 w-6 text-amber-600 dark:text-amber-400" />
            </div>
            <div className="min-w-0 flex-1">
              <p className="font-medium text-amber-800 dark:text-amber-300">
                Two-factor authentication is not enabled
              </p>
              <p className="mt-1 text-sm text-amber-600 dark:text-amber-400">
                We strongly recommend enabling MFA to add an extra layer of security to your account.
              </p>
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

        {!enabled && (
          <p className="text-xs text-muted-foreground">
            Scroll to the Security section below to set up MFA.
          </p>
        )}
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
        <CardDescription>{percentage}% complete &mdash; {totalSteps - completedCount} {totalSteps - completedCount === 1 ? "step" : "steps"} remaining</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Progress bar */}
        <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
          <div
            className="h-full rounded-full bg-primary transition-all duration-500"
            style={{ width: `${percentage}%` }}
          />
        </div>

        {/* Steps checklist */}
        <ul className="grid gap-1.5 sm:grid-cols-2">
          {completionSteps.map((step) => (
            <li key={step.label}>
              {!step.completed && step.sectionId ? (
                <button
                  type="button"
                  onClick={() => {
                    document.getElementById(step.sectionId!)?.scrollIntoView({ behavior: "smooth", block: "start" })
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
      <PageHeader eyebrow="Account" title="Profile" description="Manage your personal information, security, and connected accounts." />

      {/* Profile completeness indicator */}
      <PageSection>
        <ProfileCompletenessCard user={user} />
      </PageSection>

      {/* Hero / avatar section */}
      <PageSection>
        <ProfileHero user={user} />
      </PageSection>

      {/* Account overview cards */}
      <PageSection delay={0.05}>
        <div className="grid gap-6 lg:grid-cols-2">
          <AccountInfoCard user={user} />
          <MfaSummaryCard />
        </div>
      </PageSection>

      <Separator />

      {/* Personal information */}
      <PageSection delay={0.1} id="personal-info">
        <SectionHeading icon={UserIcon} title="Personal information" description="Update your name, username, and contact details." />
        <PersonalInfoForm user={user} />
      </PageSection>

      <Separator />

      {/* Security section */}
      <PageSection delay={0.2} id="security">
        <SectionHeading icon={Shield} title="Security" description="Manage your password and multi-factor authentication." />
        <div className="grid gap-6 lg:grid-cols-2">
          <PasswordChangeCard />
          <MfaSection />
        </div>
        <RecentSecurityActivity />
      </PageSection>

      <Separator />

      {/* Connected accounts & sessions in a two-column layout */}
      <PageSection delay={0.3}>
        <SectionHeading icon={Link2} title="Connected accounts" description="Manage linked OAuth providers and active sessions." />
        <div className="grid gap-6 lg:grid-cols-2">
          <ConnectedAccounts />
          <ActiveSessions />
        </div>
      </PageSection>

      <Separator />

      {/* Quick links to Settings */}
      <PageSection delay={0.4}>
        <QuickLinksCard />
      </PageSection>
    </PageContainer>
  )
}
