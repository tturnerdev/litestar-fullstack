import { Check, Copy, Mail, Send, Trash2 } from "lucide-react"
import { useCallback, useEffect, useRef, useState } from "react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import { TableCell, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useUpdateFaxEmailRoute } from "@/lib/api/hooks/fax"

interface EmailRouteRowProps {
  route: {
    id: string
    emailAddress: string
    isActive: boolean
    notifyOnFailure: boolean
  }
  faxNumberId: string
  onDelete: () => void
  isDeleting: boolean
  onTestRoute: () => void
}

export function EmailRouteRow({ route, faxNumberId, onDelete, isDeleting, onTestRoute }: EmailRouteRowProps) {
  const updateRoute = useUpdateFaxEmailRoute(faxNumberId, route.id)
  const [copied, setCopied] = useState(false)
  const [confirmingDelete, setConfirmingDelete] = useState(false)
  const confirmTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    return () => {
      if (confirmTimer.current) clearTimeout(confirmTimer.current)
    }
  }, [])

  const handleCopy = useCallback(async () => {
    await navigator.clipboard.writeText(route.emailAddress)
    setCopied(true)
    toast.success("Email copied to clipboard")
    setTimeout(() => setCopied(false), 2000)
  }, [route.emailAddress])

  function handleToggleActive() {
    const nextActive = !route.isActive
    updateRoute.mutate(
      { isActive: nextActive },
      {
        onSuccess: () => {
          toast.success(nextActive ? "Route activated" : "Route deactivated")
        },
      },
    )
  }

  function handleDeleteClick() {
    if (!confirmingDelete) {
      setConfirmingDelete(true)
      confirmTimer.current = setTimeout(() => setConfirmingDelete(false), 3000)
      return
    }
    if (confirmTimer.current) clearTimeout(confirmTimer.current)
    setConfirmingDelete(false)
    onDelete()
  }

  return (
    <TableRow className="transition-colors hover:bg-muted/50 animate-in fade-in slide-in-from-bottom-1 duration-300">
      <TableCell>
        <div className="flex items-center gap-2">
          <Mail className={`h-4 w-4 shrink-0 ${route.isActive ? "text-green-500" : "text-muted-foreground"}`} />
          <span className="font-mono text-sm">{route.emailAddress}</span>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button variant="ghost" size="sm" className="h-7 w-7 p-0" onClick={handleCopy} aria-label="Copy email address">
                {copied ? (
                  <Check className="h-3.5 w-3.5 text-green-500" />
                ) : (
                  <Copy className="h-3.5 w-3.5 text-muted-foreground" />
                )}
              </Button>
            </TooltipTrigger>
            <TooltipContent>Copy email address</TooltipContent>
          </Tooltip>
        </div>
      </TableCell>
      <TableCell>
        <div className="flex items-center gap-2">
          <Switch
            checked={route.isActive}
            onCheckedChange={handleToggleActive}
            disabled={updateRoute.isPending}
          />
          <span className="text-sm text-muted-foreground">{route.isActive ? "Active" : "Inactive"}</span>
        </div>
      </TableCell>
      <TableCell>
        <div className="flex items-center gap-2">
          <Switch
            checked={route.notifyOnFailure}
            onCheckedChange={() => updateRoute.mutate({ notifyOnFailure: !route.notifyOnFailure })}
            disabled={updateRoute.isPending}
          />
          <span className="text-sm text-muted-foreground">{route.notifyOnFailure ? "Enabled" : "Disabled"}</span>
        </div>
      </TableCell>
      <TableCell className="text-right">
        <div className="flex items-center justify-end gap-1">
          <Tooltip>
            <TooltipTrigger asChild>
              <Button variant="ghost" size="sm" onClick={onTestRoute} aria-label="Send test email">
                <Send className="h-4 w-4" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>Send test email</TooltipContent>
          </Tooltip>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant={confirmingDelete ? "destructive" : "outline"}
                size="sm"
                onClick={handleDeleteClick}
                disabled={isDeleting}
                className={
                  confirmingDelete
                    ? "animate-in fade-in duration-150"
                    : "text-destructive hover:text-destructive hover:bg-destructive/10"
                }
              >
                {confirmingDelete ? (
                  <span className="text-xs font-medium">Confirm?</span>
                ) : (
                  <Trash2 className="h-4 w-4" />
                )}
              </Button>
            </TooltipTrigger>
            <TooltipContent>{confirmingDelete ? "Click again to confirm" : "Remove this email route"}</TooltipContent>
          </Tooltip>
        </div>
      </TableCell>
    </TableRow>
  )
}
