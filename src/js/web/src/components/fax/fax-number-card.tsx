import { Link } from "@tanstack/react-router"
import { AlertTriangle, Clock, Hash, Mail, MessageSquare, Send, Settings } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import type { FaxNumber } from "@/lib/api/hooks/fax"

function formatPhoneNumber(phone: string): string {
  const digits = phone.replace(/\D/g, "")
  // Handle US numbers: strip leading 1 if 11 digits
  const normalized = digits.length === 11 && digits.startsWith("1") ? digits.slice(1) : digits
  if (normalized.length === 10) {
    return `${normalized.slice(0, 3)}-${normalized.slice(3, 6)}-${normalized.slice(6)}`
  }
  return phone
}

function timeAgo(dateStr: string | null): string {
  if (!dateStr) return ""
  const now = Date.now()
  const then = new Date(dateStr).getTime()
  const seconds = Math.floor((now - then) / 1000)
  if (seconds < 60) return "just now"
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  if (days < 30) return `${days}d ago`
  const months = Math.floor(days / 30)
  if (months < 12) return `${months}mo ago`
  const years = Math.floor(months / 12)
  return `${years}y ago`
}

interface FaxNumberCardProps {
  faxNumber: FaxNumber
}

export function FaxNumberCard({ faxNumber }: FaxNumberCardProps) {
  const emailRouteCount = faxNumber.emailRoutes?.length ?? 0
  const messageCount = faxNumber.messageCount ?? 0
  const createdAgo = timeAgo(faxNumber.createdAt)

  return (
    <Card className="transition-transform duration-200 hover:scale-[1.02]">
      <CardHeader className="flex flex-row items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
            <Hash className="h-4 w-4" />
          </div>
          <div className="min-w-0">
            <CardTitle className="text-sm truncate">
              {faxNumber.label ?? formatPhoneNumber(faxNumber.number)}
            </CardTitle>
            {faxNumber.label && (
              <p className="text-xs text-muted-foreground font-mono">
                {formatPhoneNumber(faxNumber.number)}
              </p>
            )}
          </div>
        </div>
        <div className="flex items-center gap-1.5">
          <span
            className={`inline-block h-2.5 w-2.5 rounded-full ${
              faxNumber.isActive
                ? "bg-emerald-500 animate-pulse"
                : "bg-gray-400"
            }`}
          />
          <span className="text-xs font-medium text-muted-foreground">
            {faxNumber.isActive ? "Active" : "Inactive"}
          </span>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex items-center gap-4 text-xs text-muted-foreground">
          <div className="flex items-center gap-1.5">
            {emailRouteCount === 0 ? (
              <>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <span className="flex items-center gap-1.5 text-amber-600 dark:text-amber-400">
                      <AlertTriangle className="h-3.5 w-3.5" />
                      <span>No email routes</span>
                    </span>
                  </TooltipTrigger>
                  <TooltipContent>
                    Incoming faxes will not be forwarded to any email address
                  </TooltipContent>
                </Tooltip>
              </>
            ) : (
              <>
                <Mail className="h-3.5 w-3.5" />
                <span>
                  {emailRouteCount} email route{emailRouteCount !== 1 ? "s" : ""}
                </span>
              </>
            )}
          </div>
          <div className="flex items-center gap-1.5">
            <MessageSquare className="h-3.5 w-3.5" />
            <span>
              {messageCount} message{messageCount !== 1 ? "s" : ""}
            </span>
          </div>
        </div>
        <div className="flex items-center justify-between gap-2">
          <Button asChild variant="outline" size="sm">
            <Link to="/fax/numbers/$faxNumberId" params={{ faxNumberId: faxNumber.id }}>
              <Settings className="mr-2 h-3.5 w-3.5" />
              Manage
            </Link>
          </Button>
          <Button asChild variant="outline" size="sm">
            <Link to="/fax/send">
              <Send className="mr-2 h-3.5 w-3.5" />
              Send Fax
            </Link>
          </Button>
        </div>
      </CardContent>
      {createdAgo && (
        <CardFooter className="pt-0">
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <Clock className="h-3 w-3" />
            <span>Created {createdAgo}</span>
          </div>
        </CardFooter>
      )}
    </Card>
  )
}
