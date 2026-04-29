import type { LucideIcon } from "lucide-react"
import { Card, CardContent } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { cn } from "@/lib/utils"

interface StatCardProps {
  label: string
  value: number | undefined
  icon: LucideIcon
  iconClassName?: string
  isLoading?: boolean
}

export function StatCard({ label, value, icon: Icon, iconClassName, isLoading }: StatCardProps) {
  return (
    <Card className="relative overflow-hidden">
      <CardContent className="flex items-center gap-4 p-5">
        <div className={cn("flex h-11 w-11 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary", iconClassName)}>
          <Icon className="h-5 w-5" />
        </div>
        <div className="min-w-0 flex-1">
          {isLoading ? (
            <>
              <Skeleton className="mb-1 h-7 w-12" />
              <Skeleton className="h-4 w-20" />
            </>
          ) : (
            <>
              <p className="text-2xl font-semibold tracking-tight">{value ?? 0}</p>
              <p className="truncate text-sm text-muted-foreground">{label}</p>
            </>
          )}
        </div>
      </CardContent>
    </Card>
  )
}
