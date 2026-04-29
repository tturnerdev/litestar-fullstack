import { useQueryClient } from "@tanstack/react-query"
import { createFileRoute, useNavigate, useSearch } from "@tanstack/react-router"
import { useEffect } from "react"
import { toast } from "sonner"
import { z } from "zod"
import { ActiveSessions } from "@/components/profile/active-sessions"
import { ConnectedAccounts } from "@/components/profile/connected-accounts"
import { MfaSection } from "@/components/profile/mfa-section"
import { PasswordChangeCard } from "@/components/profile/password-change-card"
import { PersonalInfoForm } from "@/components/profile/personal-info-form"
import { ProfileHero } from "@/components/profile/profile-hero"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
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

function ProfilePage() {
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const searchParams = useSearch({ from: "/_app/profile/" })
  const authUser = useAuthStore((s) => s.user)
  const { data: profile, isLoading } = useProfile()

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

  if (!user) {
    return null
  }

  return (
    <PageContainer className="flex-1 space-y-8" maxWidth="4xl">
      <PageHeader eyebrow="Account" title="Profile" description="Manage your personal information, security, and connected accounts." />

      <PageSection>
        <ProfileHero user={user} />
      </PageSection>

      <PageSection delay={0.1}>
        <PersonalInfoForm user={user} />
      </PageSection>

      <PageSection delay={0.2}>
        <h3 className="text-lg font-semibold tracking-tight">Security</h3>
        <div className="grid gap-6 lg:grid-cols-2">
          <PasswordChangeCard />
          <MfaSection />
        </div>
      </PageSection>

      <PageSection delay={0.3}>
        <h3 className="text-lg font-semibold tracking-tight">Connected accounts</h3>
        <ConnectedAccounts />
      </PageSection>

      <PageSection delay={0.4}>
        <h3 className="text-lg font-semibold tracking-tight">Sessions</h3>
        <ActiveSessions />
      </PageSection>
    </PageContainer>
  )
}
