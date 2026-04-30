import { useQueryClient } from "@tanstack/react-query"
import { Link, createFileRoute, useNavigate, useSearch } from "@tanstack/react-router"
import { AlertCircle, ArrowRight, Bell, ChevronRight, Link2, Monitor, Palette, Shield, User as UserIcon } from "lucide-react"
import { useEffect } from "react"
import { toast } from "sonner"
import { z } from "zod"
import { ActiveSessions } from "@/components/profile/active-sessions"
import { ConnectedAccounts } from "@/components/profile/connected-accounts"
import { MfaSection } from "@/components/profile/mfa-section"
import { PasswordChangeCard } from "@/components/profile/password-change-card"
import { PersonalInfoForm } from "@/components/profile/personal-info-form"
import { ProfileHero } from "@/components/profile/profile-hero"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { EmptyState } from "@/components/ui/empty-state"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Separator } from "@/components/ui/separator"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { SkeletonCard } from "@/components/ui/skeleton"
import { useProfile } from "@/lib/api/hooks/profile"
import { profileOAuthAccountsQueryKey } from "@/lib/generated/api/@tanstack/react-query.gen"
import { useAuthStore } from "@/lib/auth"

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

function ProfilePage() {
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

      {/* Hero / avatar section */}
      <PageSection>
        <ProfileHero user={user} />
      </PageSection>

      {/* Personal information */}
      <PageSection delay={0.1}>
        <SectionHeading icon={UserIcon} title="Personal information" description="Update your name, username, and contact details." />
        <PersonalInfoForm user={user} />
      </PageSection>

      <Separator />

      {/* Security section */}
      <PageSection delay={0.2}>
        <SectionHeading icon={Shield} title="Security" description="Manage your password and multi-factor authentication." />
        <div className="grid gap-6 lg:grid-cols-2">
          <PasswordChangeCard />
          <MfaSection />
        </div>
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
