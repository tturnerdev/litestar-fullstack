import { useMutation } from "@tanstack/react-query"
import { createFileRoute, useNavigate, useSearch } from "@tanstack/react-router"
import { motion } from "framer-motion"
import { CheckCircle2, Mail, XCircle } from "lucide-react"
import { useEffect, useState } from "react"
import { toast } from "sonner"
import { z } from "zod"
import { AuthHeroPanel } from "@/components/auth/auth-hero-panel"
import { Icons } from "@/components/icons"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { useAuth } from "@/hooks/use-auth"
import { apiEmailVerificationRequestRequestVerification, apiEmailVerificationVerifyVerifyEmail } from "@/lib/generated/api"

export const Route = createFileRoute("/_public/verify-email")({
  validateSearch: (search) =>
    z
      .object({
        token: z.string().optional(),
      })
      .parse(search),
  component: VerifyEmailPage,
})

function VerifyEmailPage() {
  const navigate = useNavigate()
  const searchParams = useSearch({ from: "/_public/verify-email" })
  const { refetch: refetchUser } = useAuth()
  const [status, setStatus] = useState<"verifying" | "success" | "error">("verifying")
  const [errorMessage, setErrorMessage] = useState<string>("")

  const token = searchParams.token

  const { mutate: verifyEmail, isPending: isVerifying } = useMutation({
    mutationFn: async (verificationToken: string) => {
      const response = await apiEmailVerificationVerifyVerifyEmail({
        body: { token: verificationToken },
      })

      if (response.error) {
        throw new Error((response.error as { detail?: string }).detail || "Verification failed")
      }

      return response.data
    },
    onSuccess: async () => {
      setStatus("success")
      toast.success("Email verified successfully!")
      await refetchUser()
      setTimeout(() => {
        navigate({ to: "/home" })
      }, 3000)
    },
    onError: (error: Error) => {
      setStatus("error")
      setErrorMessage(error.message)
      toast.error(error.message)
    },
  })

  useEffect(() => {
    if (token) {
      verifyEmail(token)
    } else {
      setStatus("error")
      setErrorMessage("Verification token is missing")
    }
  }, [token, verifyEmail])

  return (
    <div className="relative flex min-h-screen w-full">
      <AuthHeroPanel showTestimonial={false} description="Verify your email to access all features." />
      <div className="flex flex-1 flex-col items-center justify-center bg-brand-gray-light px-4 py-12 dark:bg-background">
        <motion.div className="w-full max-w-md" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4, ease: [0.25, 0.1, 0.25, 1] }}>
          {/* Header icon based on status */}
          <div className="mb-8 flex flex-col items-center space-y-3">
            {status === "verifying" && (
              <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-primary/10 shadow-sm">
                <Icons.spinner className="h-6 w-6 animate-spin text-primary" />
              </div>
            )}
            {status === "success" && (
              <motion.div
                className="flex h-12 w-12 items-center justify-center rounded-full bg-green-100 dark:bg-green-900/50"
                initial={{ scale: 0.8, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                transition={{ duration: 0.3, type: "spring", stiffness: 300 }}
              >
                <CheckCircle2 className="h-6 w-6 text-green-600 dark:text-green-400" />
              </motion.div>
            )}
            {status === "error" && (
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-destructive/10">
                <XCircle className="h-6 w-6 text-destructive" />
              </div>
            )}

            <h1 className="text-2xl font-semibold tracking-tight">
              {status === "verifying" && "Verifying your email..."}
              {status === "success" && "Email Verified!"}
              {status === "error" && "Verification Failed"}
            </h1>

            {status === "verifying" && <p className="text-center text-sm text-muted-foreground">Please wait while we verify your email address...</p>}
            {status === "success" && <p className="text-center text-sm text-muted-foreground">Your email has been verified. Redirecting...</p>}
          </div>

          {(status === "success" || status === "error") && (
            <Card className="border-border/50 bg-card/80 shadow-lg backdrop-blur-sm dark:bg-card/60">
              <CardContent className="px-6 py-6">
                {status === "success" && (
                  <Button onClick={() => navigate({ to: "/home" })} className="w-full">
                    Go to Home
                  </Button>
                )}

                {status === "error" && (
                  <div className="space-y-4">
                    <Alert variant="destructive">
                      <AlertDescription>{errorMessage}</AlertDescription>
                    </Alert>
                    {errorMessage.includes("expired") ? (
                      <>
                        <p className="text-center text-sm text-muted-foreground">Your verification link has expired. Please request a new one.</p>
                        <Button onClick={() => navigate({ to: "/login" })} className="w-full">
                          Go to Login
                        </Button>
                      </>
                    ) : (
                      <div className="space-y-2">
                        <Button onClick={() => navigate({ to: "/login" })} className="w-full">
                          Back to Login
                        </Button>
                        {token && (
                          <Button onClick={() => verifyEmail(token)} variant="outline" className="w-full" disabled={isVerifying}>
                            {isVerifying ? <Icons.spinner className="mr-2 h-4 w-4 animate-spin" /> : null}
                            Try Again
                          </Button>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </motion.div>
      </div>
    </div>
  )
}

export function ResendVerificationPage() {
  const navigate = useNavigate()
  const { user } = useAuth()
  const [hasSent, setHasSent] = useState(false)

  const { mutate: resendVerification, isPending } = useMutation({
    mutationFn: async () => {
      if (!user?.email) {
        throw new Error("User email not available")
      }
      const response = await apiEmailVerificationRequestRequestVerification({
        body: { email: user.email },
      })
      if (response.error) {
        throw new Error((response.error as { detail?: string }).detail || "Failed to send verification email")
      }
      return response.data
    },
    onSuccess: () => {
      setHasSent(true)
      toast.success("Verification email sent! Please check your inbox.")
    },
    onError: (error: Error) => {
      toast.error(error.message || "Failed to send verification email")
    },
  })

  if (hasSent) {
    return (
      <div className="relative flex min-h-screen w-full">
        <AuthHeroPanel showTestimonial={false} description="Verify your email to access all features." />
        <div className="flex flex-1 flex-col items-center justify-center bg-brand-gray-light px-4 py-12 dark:bg-background">
          <motion.div
            className="w-full max-w-md"
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.4, ease: [0.25, 0.1, 0.25, 1] }}
          >
            <div className="mb-8 flex flex-col items-center space-y-3">
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-blue-100 dark:bg-blue-900/50">
                <Mail className="h-6 w-6 text-blue-600 dark:text-blue-400" />
              </div>
              <h1 className="text-2xl font-semibold tracking-tight">Check your email</h1>
              <p className="text-center text-sm text-muted-foreground">
                We've sent a verification link to <strong>{user?.email}</strong>
              </p>
            </div>
            <Card className="border-border/50 bg-card/80 shadow-lg backdrop-blur-sm dark:bg-card/60">
              <CardContent className="px-6 py-6">
                <Button onClick={() => navigate({ to: "/home" })} className="w-full">
                  Go to Home
                </Button>
              </CardContent>
            </Card>
          </motion.div>
        </div>
      </div>
    )
  }

  return (
    <div className="relative flex min-h-screen w-full">
      <AuthHeroPanel showTestimonial={false} description="Verify your email to access all features." />
      <div className="flex flex-1 flex-col items-center justify-center bg-brand-gray-light px-4 py-12 dark:bg-background">
        <motion.div className="w-full max-w-md" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4, ease: [0.25, 0.1, 0.25, 1] }}>
          <div className="mb-8 flex flex-col items-center space-y-3">
            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-primary/10 shadow-sm">
              <Mail className="h-6 w-6 text-primary" />
            </div>
            <h1 className="text-2xl font-semibold tracking-tight">Verify Your Email</h1>
            <p className="text-center text-sm text-muted-foreground">
              Your email address <strong>{user?.email}</strong> needs to be verified to access all features.
            </p>
          </div>
          <Card className="border-border/50 bg-card/80 shadow-lg backdrop-blur-sm dark:bg-card/60">
            <CardContent className="space-y-3 px-6 py-6">
              <Button onClick={() => resendVerification()} disabled={isPending} className="w-full">
                {isPending ? <Icons.spinner className="mr-2 h-4 w-4 animate-spin" /> : null}
                {isPending ? "Sending..." : "Send Verification Email"}
              </Button>
              <Button onClick={() => navigate({ to: "/home" })} variant="outline" className="w-full">
                Skip for now
              </Button>
            </CardContent>
          </Card>
        </motion.div>
      </div>
    </div>
  )
}
