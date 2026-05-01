import {
  AlertTriangle,
  ArrowRightLeft,
  CheckCircle,
  Info,
  RotateCcw,
  UserCheck,
} from "lucide-react"
import { useMemo } from "react"
import type { TicketMessage } from "@/lib/api/hooks/support"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"

interface TicketMessageSystemProps {
  message: TicketMessage
}

interface SystemMessageStyle {
  icon: React.ReactNode
  tint: string
  bgTint: string
  borderTint: string
}

function getMessageStyle(text: string): SystemMessageStyle {
  const lower = text.toLowerCase()

  if (lower.includes("closed")) {
    return {
      icon: <CheckCircle className="h-3.5 w-3.5" />,
      tint: "text-emerald-500",
      bgTint: "bg-emerald-500/5",
      borderTint: "border-emerald-500/20",
    }
  }
  if (lower.includes("reopen")) {
    return {
      icon: <RotateCcw className="h-3.5 w-3.5" />,
      tint: "text-purple-500",
      bgTint: "bg-purple-500/5",
      borderTint: "border-purple-500/20",
    }
  }
  if (lower.includes("status")) {
    return {
      icon: <ArrowRightLeft className="h-3.5 w-3.5" />,
      tint: "text-blue-500",
      bgTint: "bg-blue-500/5",
      borderTint: "border-blue-500/20",
    }
  }
  if (lower.includes("priority")) {
    return {
      icon: <AlertTriangle className="h-3.5 w-3.5" />,
      tint: "text-amber-500",
      bgTint: "bg-amber-500/5",
      borderTint: "border-amber-500/20",
    }
  }
  if (lower.includes("assigned")) {
    return {
      icon: <UserCheck className="h-3.5 w-3.5" />,
      tint: "text-green-500",
      bgTint: "bg-green-500/5",
      borderTint: "border-green-500/20",
    }
  }

  return {
    icon: <Info className="h-3.5 w-3.5" />,
    tint: "text-muted-foreground",
    bgTint: "bg-muted/30",
    borderTint: "border-border/40",
  }
}

export function TicketMessageSystem({ message }: TicketMessageSystemProps) {
  const style = useMemo(
    () => getMessageStyle(message.bodyMarkdown),
    [message.bodyMarkdown],
  )

  const actorName = message.author?.name

  return (
    <div className="flex items-center justify-center py-3 animate-in fade-in duration-500">
      {/* Left divider line */}
      <div className="h-px flex-1 bg-border/30" />

      <div
        className={`mx-3 flex items-center gap-2 rounded-full border px-4 py-1.5 ${style.bgTint} ${style.borderTint}`}
      >
        <span className={style.tint}>{style.icon}</span>
        <span className="text-xs text-muted-foreground">
          {actorName && (
            <span className="font-medium text-foreground/80">{actorName} </span>
          )}
          {message.bodyMarkdown}
        </span>
        {message.createdAt && (
          <>
            <span className="text-muted-foreground/30">·</span>
            <span
              className="text-xs text-muted-foreground/60"
              title={formatDateTime(message.createdAt, "")}
            >
              {formatRelativeTimeShort(message.createdAt)}
            </span>
          </>
        )}
      </div>

      {/* Right divider line */}
      <div className="h-px flex-1 bg-border/30" />
    </div>
  )
}
