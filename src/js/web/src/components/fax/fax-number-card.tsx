import { Link } from "@tanstack/react-router"
import { AlertTriangle, Clock, Hash, Mail, MessageSquare, Pencil, Send, Settings } from "lucide-react"
import { FaxNumberEditDialog } from "@/components/fax/fax-number-edit-dialog"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import type { FaxNumber } from "@/lib/api/hooks/fax"
import { formatRelativeTimeShort } from "@/lib/date-utils"
import { formatPhoneNumber } from "@/lib/format-utils"

interface FaxNumberCardProps {
  faxNumber: FaxNumber
}

export function FaxNumberCard({ faxNumber }: FaxNumberCardProps) {
  const emailRouteCount = faxNumber.emailRoutes?.length ?? 0
  const messageCount = faxNumber.messageCount ?? 0

  return (
    <Card className="transition-transform duration-200 hover:scale-[1.02]">
      <CardHeader className="flex flex-row items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
            <Hash className="h-4 w-4" />
          </div>
          <div className="min-w-0">
            <Tooltip>
              <TooltipTrigger asChild>
                <CardTitle className="text-sm truncate">{faxNumber.label ?? formatPhoneNumber(faxNumber.number)}</CardTitle>
              </TooltipTrigger>
              <TooltipContent>{faxNumber.label ?? formatPhoneNumber(faxNumber.number)}</TooltipContent>
            </Tooltip>
            {faxNumber.label && <p className="text-xs text-muted-foreground font-mono">{formatPhoneNumber(faxNumber.number)}</p>}
          </div>
        </div>
        <div className="flex items-center gap-1.5">
          <span className={`inline-block h-2.5 w-2.5 rounded-full ${faxNumber.isActive ? "bg-emerald-500 animate-pulse" : "bg-gray-400"}`} />
          <span className="text-xs font-medium text-muted-foreground">{faxNumber.isActive ? "Active" : "Inactive"}</span>
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
                  <TooltipContent>Incoming faxes will not be forwarded to any email address</TooltipContent>
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
          <div className="flex items-center gap-2">
            <FaxNumberEditDialog
              faxNumber={faxNumber}
              trigger={
                <Button variant="ghost" size="sm">
                  <Pencil className="mr-2 h-3.5 w-3.5" /> Edit
                </Button>
              }
            />
            <Button asChild variant="outline" size="sm">
              <Link to="/fax/numbers/$faxNumberId" params={{ faxNumberId: faxNumber.id }}>
                <Settings className="mr-2 h-3.5 w-3.5" />
                Manage
              </Link>
            </Button>
          </div>
          <Button asChild variant="outline" size="sm">
            <Link to="/fax/send">
              <Send className="mr-2 h-3.5 w-3.5" />
              Send Fax
            </Link>
          </Button>
        </div>
      </CardContent>
      {faxNumber.createdAt && (
        <CardFooter className="pt-0">
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <Clock className="h-3 w-3" />
            <span>Created {formatRelativeTimeShort(faxNumber.createdAt)}</span>
          </div>
        </CardFooter>
      )}
    </Card>
  )
}
