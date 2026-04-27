import { Badge } from "@/components/ui/badge"

const statusConfig: Record<string, { label: string; className: string }> = {
  online: { label: "Online", className: "border-green-500/30 bg-green-500/10 text-green-700 dark:text-green-400" },
  offline: { label: "Offline", className: "border-muted-foreground/30 bg-muted/50 text-muted-foreground" },
  ringing: { label: "Ringing", className: "border-blue-500/30 bg-blue-500/10 text-blue-700 dark:text-blue-400" },
  in_use: { label: "In Use", className: "border-yellow-500/30 bg-yellow-500/10 text-yellow-700 dark:text-yellow-400" },
  error: { label: "Error", className: "border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-400" },
}

export function DeviceStatusBadge({ status }: { status: string }) {
  const config = statusConfig[status] ?? { label: status, className: "" }
  return (
    <Badge variant="outline" className={config.className}>
      {config.label}
    </Badge>
  )
}
