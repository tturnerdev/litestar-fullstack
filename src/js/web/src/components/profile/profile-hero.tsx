import { BadgeCheck, Mail, Phone, User as UserIcon } from "lucide-react"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent } from "@/components/ui/card"
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

  return (
    <Card>
      <CardContent className="pt-6">
        <div className="flex flex-col items-center gap-6 sm:flex-row sm:items-start">
          <Avatar className="h-20 w-20 text-2xl">
            {user.avatarUrl ? (
              <AvatarImage src={user.avatarUrl} alt={displayName} />
            ) : null}
            <AvatarFallback className="bg-primary/10 text-primary text-2xl font-semibold">
              {initials}
            </AvatarFallback>
          </Avatar>

          <div className="flex-1 space-y-2 text-center sm:text-left">
            <div className="flex flex-col items-center gap-2 sm:flex-row">
              <h2 className="text-2xl font-semibold tracking-tight">{displayName}</h2>
              {user.isVerified && (
                <Badge variant="secondary" className="gap-1">
                  <BadgeCheck className="h-3 w-3" />
                  Verified
                </Badge>
              )}
            </div>

            <div className="flex flex-col gap-1 text-sm text-muted-foreground">
              <div className="flex items-center justify-center gap-2 sm:justify-start">
                <Mail className="h-3.5 w-3.5" />
                <span>{user.email}</span>
              </div>
              {user.username && (
                <div className="flex items-center justify-center gap-2 sm:justify-start">
                  <UserIcon className="h-3.5 w-3.5" />
                  <span>@{user.username}</span>
                </div>
              )}
              {user.phone && (
                <div className="flex items-center justify-center gap-2 sm:justify-start">
                  <Phone className="h-3.5 w-3.5" />
                  <span>{user.phone}</span>
                </div>
              )}
            </div>

            <div className="flex flex-wrap items-center justify-center gap-2 pt-1 sm:justify-start">
              {user.isTwoFactorEnabled && (
                <Badge variant="outline" className="text-xs">
                  MFA enabled
                </Badge>
              )}
              {user.hasPassword && (
                <Badge variant="outline" className="text-xs">
                  Password set
                </Badge>
              )}
              {(user.oauthAccounts?.length ?? 0) > 0 && (
                <Badge variant="outline" className="text-xs">
                  {user.oauthAccounts!.length} linked account{user.oauthAccounts!.length !== 1 ? "s" : ""}
                </Badge>
              )}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
