import { AlertTriangle, Loader2, LogOut, RefreshCw } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { useSessionTimeout } from "@/lib/use-session-timeout"

export function SessionTimeoutWarning() {
  const { showWarning, secondsLeft, isRefreshing, continueSession, logoutNow } = useSessionTimeout()

  const minutes = Math.floor(secondsLeft / 60)
  const seconds = secondsLeft % 60

  let timeDisplay: string
  if (minutes > 0) {
    timeDisplay = `${minutes} minute${minutes !== 1 ? "s" : ""}`
  } else {
    timeDisplay = `${seconds} second${seconds !== 1 ? "s" : ""}`
  }

  return (
    <Dialog open={showWarning}>
      <DialogContent
        className="sm:max-w-md [&>[data-slot=dialog-close]]:hidden"
        onPointerDownOutside={(e) => e.preventDefault()}
        onEscapeKeyDown={(e) => e.preventDefault()}
        onInteractOutside={(e) => e.preventDefault()}
      >
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-amber-500" />
            Session Expiring Soon
          </DialogTitle>
          <DialogDescription>Your session will expire in approximately {timeDisplay}. Would you like to continue working?</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={logoutNow} disabled={isRefreshing}>
            <LogOut className="mr-2 h-4 w-4" />
            Log Out
          </Button>
          <Button onClick={continueSession} disabled={isRefreshing}>
            {isRefreshing ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
            {isRefreshing ? "Refreshing..." : "Continue Session"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
