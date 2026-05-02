import { Link } from "@tanstack/react-router"
import { AlertCircle, TrendingUp } from "lucide-react"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { EmptyState } from "@/components/ui/empty-state"
import { Skeleton } from "@/components/ui/skeleton"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useAdminUsers } from "@/lib/api/hooks/admin"

const RANK_COLORS = ["bg-amber-400 text-amber-950", "bg-gray-300 text-gray-700", "bg-amber-600 text-amber-50"] as const

function getRankStyle(index: number): string {
  if (index < 3) return RANK_COLORS[index]
  return "bg-muted text-muted-foreground"
}

function getBarColor(index: number): string {
  if (index === 0) return "bg-primary"
  if (index === 1) return "bg-primary/80"
  if (index === 2) return "bg-primary/60"
  return "bg-primary/40"
}

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
  const { data, isLoading, isError, refetch } = useAdminUsers({ page: 1, pageSize: 100 })

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-semibold">Most active users</CardTitle>
          <CardDescription>By login count</CardDescription>
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
      <EmptyState
        icon={AlertCircle}
        title="Unable to load user activity"
        description="Something went wrong. Please try again."
        action={
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            Try again
          </Button>
        }
      />
    )
  }

  const sorted = [...data.items].sort((a, b) => (b.loginCount ?? 0) - (a.loginCount ?? 0)).slice(0, 5)

  const maxCount = sorted[0]?.loginCount ?? 1

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-semibold">Most active users</CardTitle>
        <CardDescription>By login count</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {sorted.length === 0 && <p className="text-muted-foreground text-sm">No user activity yet.</p>}
        {sorted.map((user, index) => {
          const count = user.loginCount ?? 0
          const pct = maxCount > 0 ? (count / maxCount) * 100 : 0
          return (
            <Link
              key={user.id}
              to="/admin/users/$userId"
              params={{ userId: user.id }}
              className="flex items-center gap-3 hover:bg-muted/50 rounded-lg px-2 py-1.5 -mx-2 transition-colors"
            >
              <span className={`flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-[10px] font-bold ${getRankStyle(index)}`}>{index + 1}</span>
              <Avatar className="size-8 text-xs">
                <AvatarFallback>{getInitials(user.name, user.email)}</AvatarFallback>
              </Avatar>
              <div className="flex-1 min-w-0">
                <Tooltip>
                  <TooltipTrigger asChild>
                    <p className="text-sm font-medium truncate">{user.name ?? user.email}</p>
                  </TooltipTrigger>
                  <TooltipContent>{user.name ?? user.email}</TooltipContent>
                </Tooltip>
                {user.name && (
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <p className="text-xs text-muted-foreground truncate">{user.email}</p>
                    </TooltipTrigger>
                    <TooltipContent>{user.email}</TooltipContent>
                  </Tooltip>
                )}
                <div className="mt-1 h-1.5 w-full rounded-full bg-muted">
                  <div className={`h-1.5 rounded-full ${getBarColor(index)} transition-all duration-500`} style={{ width: `${pct}%` }} />
                </div>
              </div>
              <span className="flex items-center gap-1 text-xs font-medium tabular-nums text-muted-foreground whitespace-nowrap">
                {count} {count === 1 ? "login" : "logins"}
                {count > 10 && <TrendingUp className="h-3 w-3 text-emerald-500" />}
              </span>
            </Link>
          )
        })}
      </CardContent>
    </Card>
  )
}
