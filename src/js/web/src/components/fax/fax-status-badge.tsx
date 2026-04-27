import { Badge } from "@/components/ui/badge"

const statusConfig: Record<string, { label: string; className: string }> = {
  received: {
    label: "Received",
    className: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/20",
  },
  delivered: {
    label: "Delivered",
    className: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/20",
  },
  sending: {
    label: "Sending",
    className: "bg-amber-500/15 text-amber-600 dark:text-amber-400 border-amber-500/20",
  },
  sent: {
    label: "Sent",
    className: "bg-blue-500/15 text-blue-600 dark:text-blue-400 border-blue-500/20",
  },
  failed: {
    label: "Failed",
    className: "bg-red-500/15 text-red-600 dark:text-red-400 border-red-500/20",
  },
}

export function FaxStatusBadge({ status }: { status: string }) {
  const config = statusConfig[status] ?? { label: status, className: "" }
  return (
    <Badge variant="outline" className={config.className}>
      {config.label}
    </Badge>
  )
}

export function DirectionBadge({ direction }: { direction: "inbound" | "outbound" }) {
  return direction === "inbound" ? (
    <Badge variant="outline" className="bg-blue-500/15 text-blue-600 dark:text-blue-400 border-blue-500/20">
      Inbound
    </Badge>
  ) : (
    <Badge variant="outline" className="bg-violet-500/15 text-violet-600 dark:text-violet-400 border-violet-500/20">
      Outbound
    </Badge>
  )
}
