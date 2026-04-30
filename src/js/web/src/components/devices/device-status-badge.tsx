import { cn } from "@/lib/utils"

const statusConfig: Record<string, { label: string; dotClass: string; textClass: string }> = {
  online: {
    label: "Online",
    dotClass: "bg-emerald-500",
    textClass: "text-emerald-600 dark:text-emerald-400",
  },
  offline: {
    label: "Offline",
    dotClass: "bg-muted-foreground/50",
    textClass: "text-muted-foreground",
  },
  ringing: {
    label: "Ringing",
    dotClass: "bg-blue-500 animate-pulse",
    textClass: "text-blue-600 dark:text-blue-400",
  },
  in_use: {
    label: "In Use",
    dotClass: "bg-yellow-500",
    textClass: "text-yellow-600 dark:text-yellow-400",
  },
  provisioning: {
    label: "Provisioning",
    dotClass: "bg-violet-500 animate-pulse",
    textClass: "text-violet-600 dark:text-violet-400",
  },
  error: {
    label: "Error",
    dotClass: "bg-red-500",
    textClass: "text-red-600 dark:text-red-400",
  },
}

export function DeviceStatusBadge({ status }: { status: string }) {
  const config = statusConfig[status] ?? {
    label: status,
    dotClass: "bg-muted-foreground/40",
    textClass: "text-muted-foreground",
  }
  return (
    <span className={cn("flex items-center gap-1.5 text-xs", config.textClass)}>
      <span className={cn("inline-block h-2 w-2 rounded-full", config.dotClass)} />
      {config.label}
    </span>
  )
}
