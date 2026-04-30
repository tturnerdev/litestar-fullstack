import { Link } from "@tanstack/react-router"
import { motion } from "framer-motion"
import { Minus, TrendingDown, TrendingUp, type LucideIcon } from "lucide-react"
import { Card, CardContent } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { cn } from "@/lib/utils"

interface TrendInfo {
  value: number
  direction: "up" | "down" | "neutral"
}

interface StatCardProps {
  label: string
  value: number | undefined
  icon: LucideIcon
  iconClassName?: string
  isLoading?: boolean
  trend?: TrendInfo
  href?: string
  index?: number
}

function TrendIndicator({ trend }: { trend: TrendInfo }) {
  const { value, direction } = trend
  const formatted = direction === "neutral" ? `${Math.abs(value)}%` : `${value > 0 ? "+" : ""}${value}%`

  if (direction === "up") {
    return (
      <span className="inline-flex items-center gap-0.5 text-xs font-medium text-emerald-600 dark:text-emerald-400">
        <TrendingUp className="h-3 w-3" />
        {formatted}
      </span>
    )
  }

  if (direction === "down") {
    return (
      <span className="inline-flex items-center gap-0.5 text-xs font-medium text-red-600 dark:text-red-400">
        <TrendingDown className="h-3 w-3" />
        {formatted}
      </span>
    )
  }

  return (
    <span className="inline-flex items-center gap-0.5 text-xs font-medium text-muted-foreground">
      <Minus className="h-3 w-3" />
      {formatted}
    </span>
  )
}

export function StatCard({ label, value, icon: Icon, iconClassName, isLoading, trend, href, index = 0 }: StatCardProps) {
  const cardContent = (
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
            <div className="flex items-baseline gap-2">
              <p className="text-2xl font-semibold tracking-tight">{value ?? 0}</p>
              {trend && <TrendIndicator trend={trend} />}
            </div>
            <p className="truncate text-sm text-muted-foreground">{label}</p>
          </>
        )}
      </div>
    </CardContent>
  )

  const card = href ? (
    <Link to={href}>
      <Card className="relative overflow-hidden transition-all duration-200 hover:scale-[1.02] hover:shadow-md cursor-pointer">
        {cardContent}
      </Card>
    </Link>
  ) : (
    <Card className="relative overflow-hidden transition-all duration-200 hover:scale-[1.02] hover:shadow-md">
      {cardContent}
    </Card>
  )

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, delay: index * 0.06, ease: "easeOut" }}
    >
      {card}
    </motion.div>
  )
}
