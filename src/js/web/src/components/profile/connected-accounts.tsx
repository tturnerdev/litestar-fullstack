import { Link2, LogIn } from "lucide-react"
import { useMemo, useState } from "react"
import { toast } from "sonner"
import { Icons } from "@/components/icons"
import { OAuthLinkButton } from "@/components/profile/oauth-link-button"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { SkeletonCard } from "@/components/ui/skeleton"
import { useOAuthConfig } from "@/hooks/use-oauth-config"
import { useOAuthAccounts, useStartOAuthLink, useUnlinkOAuthAccount } from "@/lib/api/hooks/auth"
import { formatRelativeTimeShort } from "@/lib/date-utils"

const providerMeta: Record<string, { label: string; iconBg: string }> = {
  github: {
    label: "GitHub",
    iconBg: "bg-gray-100 dark:bg-gray-800",
  },
  google: {
    label: "Google",
    iconBg: "bg-blue-50 dark:bg-blue-950/40",
  },
}

export function ConnectedAccounts() {
  const { data, isLoading, isError } = useOAuthAccounts()
  const { data: oauthConfig } = useOAuthConfig()
  const startLink = useStartOAuthLink()
  const unlink = useUnlinkOAuthAccount()
  const [unlinkDialogOpen, setUnlinkDialogOpen] = useState(false)

  const accounts = data?.items ?? []
  const linkedProviders = useMemo(() => new Set(accounts.map((account) => account.provider)), [accounts])

  if (isLoading) {
    return <SkeletonCard />
  }

  if (isError) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Connected accounts</CardTitle>
          <CardDescription>We could not load your connected accounts.</CardDescription>
        </CardHeader>
      </Card>
    )
  }

  const handleLink = async (provider: "google" | "github") => {
    try {
      const redirectUrl = `${window.location.origin}/profile`
      const result = await startLink.mutateAsync({ provider, redirectUrl })
      if (result?.authorizationUrl) {
        window.location.href = result.authorizationUrl
        return
      }
      toast.error("Unable to start OAuth flow")
    } catch (error) {
      toast.error("Unable to start OAuth flow", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    }
  }

  const handleUnlink = async (provider: string) => {
    try {
      await unlink.mutateAsync(provider)
      toast.success(`Unlinked ${provider}`)
    } catch (error) {
      toast.error("Unable to unlink account", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    }
  }

  const availableProviders = [
    ...(oauthConfig?.googleEnabled && !linkedProviders.has("google") ? (["google"] as const) : []),
    ...(oauthConfig?.githubEnabled && !linkedProviders.has("github") ? (["github"] as const) : []),
  ]

  const hasEmptyState = accounts.length === 0

  return (
    <Card>
      <CardHeader>
        <CardTitle>Connected accounts</CardTitle>
        <CardDescription>Manage your linked OAuth providers.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {hasEmptyState ? (
          <div className="flex flex-col items-center gap-4 rounded-lg border border-dashed border-border/60 py-8">
            <div className="rounded-full bg-muted p-3">
              <Link2 className="h-6 w-6 text-muted-foreground" />
            </div>
            <div className="text-center">
              <p className="text-sm font-medium">No connected accounts</p>
              <p className="mt-1 text-sm text-muted-foreground">
                Connect your accounts for easier sign-in and a more streamlined experience.
              </p>
            </div>
            {availableProviders.length > 0 && (
              <div className="flex flex-wrap gap-2">
                {availableProviders.map((provider) => (
                  <OAuthLinkButton
                    key={provider}
                    provider={provider}
                    onClick={() => handleLink(provider)}
                    disabled={startLink.isPending}
                  />
                ))}
              </div>
            )}
          </div>
        ) : (
          <>
            <div className="space-y-3">
              {accounts.map((account) => {
                const Icon = account.provider === "google" ? Icons.google : Icons.gitHub
                const meta = providerMeta[account.provider] ?? {
                  label: account.provider,
                  iconBg: "bg-muted",
                }
                return (
                  <div key={account.provider} className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-border/60 bg-muted/30 px-4 py-3">
                    <div className="flex items-center gap-3">
                      <div className={`flex h-8 w-8 items-center justify-center rounded-full ${meta.iconBg}`}>
                        <Icon className="h-4 w-4" />
                      </div>
                      <div>
                        <p className="font-medium">{meta.label}</p>
                        <p className="text-muted-foreground text-sm">{account.email}</p>
                        <div className="flex flex-wrap items-center gap-x-3 gap-y-0.5 text-xs text-muted-foreground">
                          {account.linkedAt && (
                            <span>Connected {formatRelativeTimeShort(account.linkedAt)}</span>
                          )}
                          {account.lastLoginAt && (
                            <span className="flex items-center gap-1">
                              <LogIn className="h-3 w-3" />
                              Last login {formatRelativeTimeShort(account.lastLoginAt)}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                    <AlertDialog open={unlinkDialogOpen} onOpenChange={setUnlinkDialogOpen}>
                      <AlertDialogTrigger asChild>
                        <Button variant="outline" size="sm">
                          Unlink
                        </Button>
                      </AlertDialogTrigger>
                      <AlertDialogContent>
                        <AlertDialogHeader>
                          <AlertDialogTitle>Disconnect {meta.label}?</AlertDialogTitle>
                          <AlertDialogDescription>
                            You won't be able to sign in with this {meta.label} account anymore.
                            You can always reconnect it later.
                          </AlertDialogDescription>
                        </AlertDialogHeader>
                        <AlertDialogFooter>
                          <AlertDialogCancel onClick={() => setUnlinkDialogOpen(false)}>Cancel</AlertDialogCancel>
                          <AlertDialogAction
                            onClick={() => {
                              setUnlinkDialogOpen(false)
                              handleUnlink(account.provider)
                            }}
                          >
                            Disconnect
                          </AlertDialogAction>
                        </AlertDialogFooter>
                      </AlertDialogContent>
                    </AlertDialog>
                  </div>
                )
              })}
            </div>
            {availableProviders.length > 0 && (
              <div className="flex flex-wrap gap-2">
                {availableProviders.map((provider) => (
                  <OAuthLinkButton
                    key={provider}
                    provider={provider}
                    onClick={() => handleLink(provider)}
                    disabled={startLink.isPending}
                  />
                ))}
              </div>
            )}
          </>
        )}
      </CardContent>
    </Card>
  )
}
