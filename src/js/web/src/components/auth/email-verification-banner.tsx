import { useMutation } from "@tanstack/react-query"
import { AnimatePresence, motion } from "framer-motion"
import { CheckCircle2, Mail, X } from "lucide-react"
import { useCallback, useEffect, useRef, useState } from "react"
import { toast } from "sonner"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { useAuth } from "@/hooks/use-auth"
import { apiEmailVerificationRequestRequestVerification } from "@/lib/generated/api"

const COOLDOWN_SECONDS = 60

interface EmailVerificationBannerProps {
  dismissible?: boolean
  className?: string
}

export function EmailVerificationBanner({ className }: EmailVerificationBannerProps) {
  const { user } = useAuth()
  const [isDismissed, setIsDismissed] = useState(false)
  const [countdown, setCountdown] = useState(0)
  const timerRef = useRef<NodeJS.Timeout | null>(null)

  const startCountdown = useCallback(() => {
    setCountdown(COOLDOWN_SECONDS)
    if (timerRef.current) clearInterval(timerRef.current)
    timerRef.current = setInterval(() => {
      setCountdown((prev) => {
        if (prev <= 1) {
          if (timerRef.current) clearInterval(timerRef.current)
          timerRef.current = null
          return 0
        }
        return prev - 1
      })
    }, 1000)
  }, [])

  useEffect(() => {
    return () => {
      if (timerRef.current) clearInterval(timerRef.current)
    }
  }, [])

  const { mutate: resendVerification, isPending } = useMutation({
    mutationFn: async () => {
      if (!user?.email) {
        throw new Error("User email not available")
      }
      const response = await apiEmailVerificationRequestRequestVerification({
        body: { email: user.email },
      })
      if (response.error) {
        throw new Error((response.error as any).detail || "Failed to send verification email")
      }
      return response.data
    },
    onSuccess: () => {
      startCountdown()
      toast.success("Verification email sent! Please check your inbox.")
    },
    onError: (error: Error) => {
      toast.error(error.message || "Failed to send verification email")
    },
  })

  const shouldHide = !user || user.isVerified || isDismissed
  if (shouldHide) {
    return null
  }

  const canResend = countdown === 0

  return (
    <AnimatePresence>
      <motion.div
        initial={{ y: -20, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        exit={{ y: -20, opacity: 0 }}
        transition={{ type: "spring", stiffness: 300, damping: 24 }}
      >
        <Alert className={className} variant="warning">
          <motion.div
            animate={{ scale: [1, 1.15, 1] }}
            transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
            className="absolute left-4 top-4"
          >
            <Mail className="h-4 w-4 text-warning" />
          </motion.div>
          <AlertTitle className="flex items-center justify-between">
            <span>Email Verification Required</span>
            <Button
              variant="ghost"
              size="icon"
              className="h-5 w-5 shrink-0 rounded-sm p-0 opacity-70 hover:opacity-100"
              onClick={() => setIsDismissed(true)}
              aria-label="Dismiss banner"
            >
              <X className="h-3 w-3" />
            </Button>
          </AlertTitle>
          <AlertDescription className="mt-2">
            <p className="mb-2">
              Please verify your email address to access all features. Check your inbox for a verification link sent to{" "}
              <strong>{user.email}</strong>.
            </p>
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" onClick={() => resendVerification()} disabled={isPending || !canResend}>
                {isPending ? "Sending..." : !canResend ? `Resend in ${countdown}s` : "Resend verification email"}
              </Button>
              {!canResend && !isPending && (
                <span className="text-muted-foreground text-xs">Check your spam folder too</span>
              )}
            </div>
          </AlertDescription>
        </Alert>
      </motion.div>
    </AnimatePresence>
  )
}

export function EmailVerificationSuccess() {
  return (
    <Alert variant="success">
      <CheckCircle2 className="h-4 w-4" />
      <AlertTitle>Email Verified Successfully!</AlertTitle>
      <AlertDescription>Your email has been verified. You now have full access to all features.</AlertDescription>
    </Alert>
  )
}
