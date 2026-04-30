import { BadgeCheck, KeyRound, Link2, Lock, Mail, Phone, Shield, User as UserIcon } from "lucide-react"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent } from "@/components/ui/card"
import { Separator } from "@/components/ui/separator"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import type { User } from "@/lib/generated/api/types.gen"

interface ProfileHeroProps {
  user: User
}

function getInitials(user: User): string {
  if (user.name) {
    const parts = user.name.trim().split(/\s+/)
    if (parts.length >= 2) {
      return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase()
    }
    return parts[0].slice(0, 2).toUpperCase()
  }
  if (user.username) {
    return user.username.slice(0, 2).toUpperCase()
  }
  return user.email.slice(0, 2).toUpperCase()
}

export function ProfileHero({ user }: ProfileHeroProps) {
  const initials = getInitials(user)
  const displayName = user.name || user.username || user.email.split("@")[0]

  const securityIndicators = [
    {
      enabled: !!user.isTwoFactorEnabled,
      icon: Shield,
      label: "MFA",
      enabledText: "Multi-factor authentication enabled",
      disabledText: "MFA not enabled",
    },
    {
      enabled: !!user.hasPassword,
      icon: Lock,
      label: "Password",
      enabledText: "Password authentication set",
      disabledText: "No password set",
    },
    {
      enabled: (user.oauthAccounts?.length ?? 0) > 0,
      icon: Link2,
      label: `${user.oauthAccounts?.length ?? 0} linked`,
      enabledText: `${user.oauthAccounts?.length ?? 0} connected account${(user.oauthAccounts?.length ?? 0) !== 1 ? "s" : ""}`,
      disabledText: "No connected accounts",
    },
  ]

  const roleNames = user.roles?.map((r) => r.roleName) ?? []

  return (
    <Card className="overflow-hidden">
      <div className="h-24 bg-gradient-to-r from-primary/20 via-primary/10 to-transparent" />
      <CardContent className="relative -mt-12 pb-6">
        <div className="flex flex-col items-center gap-5 sm:flex-row sm:items-end">
          <div className="rounded-full bg-background p-1 shadow-md ring-2 ring-background">
            <Avatar className="h-24 w-24 text-3xl">
              {user.avatarUrl ? (
                <AvatarImage src={user.avatarUrl} alt={displayName} />
              ) : null}
              <AvatarFallback className="bg-primary/10 text-primary text-3xl font-semibold">
                {initials}
              </AvatarFallback>
            </Avatar>
          </div>

          <div className="flex-1 space-y-1.5 text-center sm:pb-1 sm:text-left">
            <div className="flex flex-col items-center gap-2 sm:flex-row">
              <h2 className="text-2xl font-semibold tracking-tight">{displayName}</h2>
              {user.isVerified && (
                <Badge variant="secondary" className="gap-1">
                  <BadgeCheck className="h-3 w-3" />
                  Verified
                </Badge>
              )}
              {roleNames.length > 0 && roleNames.map((role) => (
                <Badge key={role} variant="outline" className="gap-1 capitalize">
                  <KeyRound className="h-3 w-3" />
                  {role}
                </Badge>
              ))}
            </div>

            <div className="flex flex-wrap items-center justify-center gap-x-4 gap-y-1 text-sm text-muted-foreground sm:justify-start">
              <span className="inline-flex items-center gap-1.5">
                <Mail className="h-3.5 w-3.5" />
                {user.email}
              </span>
              {user.username && (
                <span className="inline-flex items-center gap-1.5">
                  <UserIcon className="h-3.5 w-3.5" />
                  @{user.username}
                </span>
              )}
              {user.phone && (
                <span className="inline-flex items-center gap-1.5">
                  <Phone className="h-3.5 w-3.5" />
                  {user.phone}
                </span>
              )}
            </div>
          </div>
        </div>

        <Separator className="my-4" />

        <div className="flex flex-wrap items-center justify-center gap-4 sm:justify-start">
          {securityIndicators.map((indicator) => {
            const Icon = indicator.icon
            return (
              <Tooltip key={indicator.label}>
                <TooltipTrigger asChild>
                  <div className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium transition-colors ${indicator.enabled ? "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-400" : "border-border bg-muted/50 text-muted-foreground"}`}>
                    <Icon className="h-3 w-3" />
                    {indicator.label}
                  </div>
                </TooltipTrigger>
                <TooltipContent>
                  <p>{indicator.enabled ? indicator.enabledText : indicator.disabledText}</p>
                </TooltipContent>
              </Tooltip>
            )
          })}
        </div>
      </CardContent>
    </Card>
  )
}
