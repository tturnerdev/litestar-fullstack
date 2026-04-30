import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { Skeleton } from "@/components/ui/skeleton"
import { useAdminUsers } from "@/lib/api/hooks/admin"

function getInitials(name: string | null | undefined, email: string): string {
  if (name) {
    const parts = name.trim().split(/\s+/)
    if (parts.length >= 2) {
      return `${parts[0][0]}${parts[1][0]}`.toUpperCase()
    }
    return name.slice(0, 2).toUpperCase()
  }
  return email.slice(0, 2).toUpperCase()
}

export function TopUsersCard() {
  const { data, isLoading, isError } = useAdminUsers({ page: 1, pageSize: 100 })

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-semibold">Most active users</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {Array.from({ length: 5 }).map((_, i) => (
            // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
            <div key={`top-user-skeleton-${i}`} className="flex items-center gap-3">
              <Skeleton className="size-8 rounded-full" />
              <div className="flex-1 space-y-1">
                <Skeleton className="h-3 w-24" />
                <Skeleton className="h-3 w-32" />
              </div>
              <Skeleton className="h-3 w-12" />
            </div>
          ))}
        </CardContent>
      </Card>
    )
  }

  if (isError || !data) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-semibold">Most active users</CardTitle>
        </CardHeader>
        <CardContent className="text-muted-foreground text-sm">Unable to load user activity.</CardContent>
      </Card>
    )
  }

  const sorted = [...data.items]
    .sort((a, b) => (b.loginCount ?? 0) - (a.loginCount ?? 0))
    .slice(0, 5)

  const maxCount = sorted[0]?.loginCount ?? 1

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-semibold">Most active users</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {sorted.length === 0 && (
          <p className="text-muted-foreground text-sm">No user activity yet.</p>
        )}
        {sorted.map((user) => {
          const count = user.loginCount ?? 0
          const pct = maxCount > 0 ? (count / maxCount) * 100 : 0
          return (
            <div key={user.id} className="flex items-center gap-3">
              <Avatar className="size-8 text-xs">
                <AvatarFallback>{getInitials(user.name, user.email)}</AvatarFallback>
              </Avatar>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium truncate">{user.name ?? user.email}</p>
                {user.name && (
                  <p className="text-xs text-muted-foreground truncate">{user.email}</p>
                )}
                <div className="mt-1 h-1.5 w-full rounded-full bg-muted">
                  <div
                    className="h-1.5 rounded-full bg-primary transition-all duration-500"
                    style={{ width: `${pct}%` }}
                  />
                </div>
              </div>
              <span className="text-xs font-medium tabular-nums text-muted-foreground whitespace-nowrap">
                {count} {count === 1 ? "login" : "logins"}
              </span>
            </div>
          )
        })}
      </CardContent>
    </Card>
  )
}
