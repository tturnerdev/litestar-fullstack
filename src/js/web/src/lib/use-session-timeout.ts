import { useCallback, useEffect, useRef, useState } from "react"
import { useAuthStore } from "@/lib/auth"
import { tokenRefresh } from "@/lib/generated/api"
import { getLastActivityMs, recordActivity } from "@/lib/session-activity"

/** How often (ms) we poll token expiry & idle state. */
const CHECK_INTERVAL_MS = 15_000 // 15 seconds

/** Show the warning dialog this many ms before the token actually expires. */
const WARNING_LEAD_MS = 2 * 60 * 1000 // 2 minutes

/**
 * Decode the JWT `exp` claim from the stored access token.
 * Returns epoch-milliseconds, or `null` when no valid token exists.
 */
function getTokenExpiryMs(): number | null {
  try {
    const token = localStorage.getItem("access_token")
    if (!token) return null
    const parts = token.split(".")
    if (parts.length !== 3) return null
    const base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/")
    const payload = JSON.parse(atob(base64))
    if (typeof payload.exp === "number") return payload.exp * 1000
    return null
  } catch {
    return null
  }
}

export interface SessionTimeoutState {
  /** Whether the warning dialog should be shown. */
  showWarning: boolean
  /** Approximate seconds remaining before token expires. */
  secondsLeft: number
  /** Whether a session refresh is currently in progress. */
  isRefreshing: boolean
  /** Refresh the token and dismiss the warning. */
  continueSession: () => Promise<void>
  /** Log the user out immediately. */
  logoutNow: () => Promise<void>
}

/**
 * Hook that monitors the JWT access-token lifetime and user inactivity.
 *
 * Behaviour:
 *   1. Every CHECK_INTERVAL_MS it reads the token `exp` and the last-activity
 *      timestamp exposed by `session-activity.ts`.
 *   2. If the user has been *active* (activity within WARNING_LEAD_MS) and the
 *      token is about to expire, it silently refreshes the token in the
 *      background — no dialog needed.
 *   3. If the user has been *idle* and the token will expire within
 *      WARNING_LEAD_MS, the warning dialog is shown.
 *   4. If the token has already expired (remaining <= 0), the user is logged
 *      out immediately and redirected to /login.
 */
export function useSessionTimeout(): SessionTimeoutState {
  const [showWarning, setShowWarning] = useState(false)
  const [secondsLeft, setSecondsLeft] = useState(0)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  const logout = useAuthStore((s) => s.logout)
  const timerRef = useRef<ReturnType<typeof setInterval>>(null)
  const countdownRef = useRef<ReturnType<typeof setInterval>>(null)
  // Guard against concurrent refresh calls
  const refreshingRef = useRef(false)
  // Guard against concurrent check() invocations
  const checkInProgressRef = useRef(false)

  const performRefresh = useCallback(async (): Promise<boolean> => {
    if (refreshingRef.current) return false
    refreshingRef.current = true
    setIsRefreshing(true)
    try {
      const { data } = await tokenRefresh()
      if (data?.access_token) {
        localStorage.setItem("access_token", data.access_token)
        recordActivity()
        return true
      }
      return false
    } catch {
      return false
    } finally {
      refreshingRef.current = false
      setIsRefreshing(false)
    }
  }, [])

  const performLogout = useCallback(async () => {
    setShowWarning(false)
    try {
      await logout()
    } finally {
      // Ensure redirect even if the logout API call fails
      if (window.location.pathname !== "/login") {
        window.location.href = "/login"
      }
    }
  }, [logout])

  const continueSession = useCallback(async () => {
    const ok = await performRefresh()
    if (ok) {
      setShowWarning(false)
    } else {
      // Refresh failed — force logout
      await performLogout()
    }
  }, [performRefresh, performLogout])

  // ---- 1-second countdown while warning is visible ----
  useEffect(() => {
    if (!showWarning) {
      if (countdownRef.current) {
        clearInterval(countdownRef.current)
        countdownRef.current = null
      }
      return
    }

    countdownRef.current = setInterval(() => {
      setSecondsLeft((prev) => {
        if (prev <= 1) return 0
        return prev - 1
      })
    }, 1_000)

    return () => {
      if (countdownRef.current) clearInterval(countdownRef.current)
    }
  }, [showWarning])

  // ---- Main polling effect ----
  useEffect(() => {
    if (!isAuthenticated) {
      setShowWarning(false)
      return
    }

    const check = async () => {
      if (checkInProgressRef.current) return
      checkInProgressRef.current = true
      try {
        const expiryMs = getTokenExpiryMs()
        if (expiryMs === null) return

        const now = Date.now()
        const remaining = expiryMs - now

        // Token already expired → attempt silent refresh before logging out
        if (remaining <= 0) {
          setShowWarning(false)
          const refreshed = await performRefresh()
          if (!refreshed) {
            await performLogout()
          }
          return
        }

        const idleMs = now - getLastActivityMs()
        const isIdle = idleMs >= WARNING_LEAD_MS

        if (remaining <= WARNING_LEAD_MS) {
          if (isIdle) {
            // User is idle and token is about to expire → show warning
            setSecondsLeft(Math.max(1, Math.ceil(remaining / 1000)))
            setShowWarning(true)
          } else {
            // User was recently active → silently refresh
            setShowWarning(false)
            await performRefresh()
          }
        } else {
          setShowWarning(false)
        }
      } finally {
        checkInProgressRef.current = false
      }
    }

    // Run an immediate check when the tab becomes visible
    const handleVisibilityChange = () => {
      if (document.visibilityState === "visible") {
        check()
      }
    }

    check()
    timerRef.current = setInterval(check, CHECK_INTERVAL_MS)
    document.addEventListener("visibilitychange", handleVisibilityChange)
    return () => {
      if (timerRef.current) clearInterval(timerRef.current)
      document.removeEventListener("visibilitychange", handleVisibilityChange)
    }
  }, [isAuthenticated, performLogout, performRefresh])

  return {
    showWarning,
    secondsLeft,
    isRefreshing,
    continueSession,
    logoutNow: performLogout,
  }
}
