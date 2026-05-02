import { AlertTriangle, LogOut, RefreshCw } from "lucide-react"
import { useCallback, useEffect, useRef, useState } from "react"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { useAuthStore } from "@/lib/auth"

const WARNING_BEFORE_EXPIRY_MS = 5 * 60 * 1000
const CHECK_INTERVAL_MS = 30 * 1000

function getTokenExpiry(): number | null {
  try {
    const token = localStorage.getItem("access_token")
    if (!token) return null
    const payload = JSON.parse(atob(token.split(".")[1]))
    if (typeof payload.exp === "number") return payload.exp * 1000
    return null
  } catch {
    return null
  }
}

export function SessionTimeoutWarning() {
  const [showWarning, setShowWarning] = useState(false)
  const [minutesLeft, setMinutesLeft] = useState(5)
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  const logout = useAuthStore((s) => s.logout)
  const checkAuth = useAuthStore((s) => s.checkAuth)
  const timerRef = useRef<ReturnType<typeof setInterval>>(null)

  const checkExpiry = useCallback(() => {
    const expiry = getTokenExpiry()
    if (!expiry) return

    const remaining = expiry - Date.now()
    if (remaining <= 0) {
      setShowWarning(false)
      return
    }
    if (remaining <= WARNING_BEFORE_EXPIRY_MS) {
      setMinutesLeft(Math.max(1, Math.ceil(remaining / 60_000)))
      setShowWarning(true)
    } else {
      setShowWarning(false)
    }
  }, [])

  useEffect(() => {
    if (!isAuthenticated) {
      setShowWarning(false)
      return
    }
    checkExpiry()
    timerRef.current = setInterval(checkExpiry, CHECK_INTERVAL_MS)
    return () => {
      if (timerRef.current) clearInterval(timerRef.current)
    }
  }, [isAuthenticated, checkExpiry])

  const handleExtend = useCallback(async () => {
    setShowWarning(false)
    try {
      await checkAuth()
    } catch {
      // refresh failed — auth interceptor handles redirect
    }
  }, [checkAuth])

  const handleLogout = useCallback(async () => {
    setShowWarning(false)
    await logout()
  }, [logout])

  if (!isAuthenticated) return null

  return (
    <AlertDialog open={showWarning} onOpenChange={setShowWarning}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-amber-500" />
            Session Expiring Soon
          </AlertDialogTitle>
          <AlertDialogDescription>
            Your session will expire in approximately {minutesLeft} minute{minutesLeft !== 1 ? "s" : ""}. Would you like to continue working?
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel onClick={handleLogout}>
            <LogOut className="mr-2 h-4 w-4" />
            Log Out
          </AlertDialogCancel>
          <AlertDialogAction onClick={handleExtend}>
            <RefreshCw className="mr-2 h-4 w-4" />
            Continue Session
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
