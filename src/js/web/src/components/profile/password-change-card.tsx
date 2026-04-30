import { useMutation } from "@tanstack/react-query"
import { AnimatePresence, motion } from "framer-motion"
import { CheckCircle2, Loader2, Lock, XCircle } from "lucide-react"
import { useCallback, useEffect, useState } from "react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { PasswordStrength } from "@/components/ui/password-strength"
import ValidatedInput from "@/components/ui/validated-input"
import { validatePassword } from "@/hooks/use-validation"
import { useAuthStore } from "@/lib/auth"
import { accountPasswordUpdate } from "@/lib/generated/api"
import { cn } from "@/lib/utils"

const SUCCESS_DISPLAY_MS = 2500

export function PasswordChangeCard() {
  const { user } = useAuthStore()

  const [currentPassword, setCurrentPassword] = useState("")
  const [newPassword, setNewPassword] = useState("")
  const [confirmPassword, setConfirmPassword] = useState("")
  const [showSuccess, setShowSuccess] = useState(false)

  const resetForm = useCallback(() => {
    setCurrentPassword("")
    setNewPassword("")
    setConfirmPassword("")
  }, [])

  useEffect(() => {
    if (!showSuccess) return
    const timer = setTimeout(() => {
      setShowSuccess(false)
      resetForm()
    }, SUCCESS_DISPLAY_MS)
    return () => clearTimeout(timer)
  }, [showSuccess, resetForm])

  const updatePassword = useMutation({
    mutationFn: async (body: { currentPassword: string; newPassword: string }) => {
      const { data } = await accountPasswordUpdate({
        body,
        throwOnError: true,
      })
      return data
    },
    onSuccess: () => {
      toast.success("Password updated successfully")
      setShowSuccess(true)
    },
    onError: (error: unknown) => {
      const message = error instanceof Error ? error.message : "Failed to update password"
      toast.error("Unable to update password", { description: message })
    },
  })

  const confirmError =
    confirmPassword && newPassword !== confirmPassword
      ? "Passwords do not match"
      : undefined

  const passwordsMatch = confirmPassword.length > 0 && newPassword === confirmPassword

  const passwordValidationError = newPassword ? validatePassword(newPassword) : null
  const canSubmit =
    currentPassword.length > 0 &&
    newPassword.length > 0 &&
    confirmPassword.length > 0 &&
    newPassword === confirmPassword &&
    !passwordValidationError

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!canSubmit) return
    updatePassword.mutate({ currentPassword, newPassword })
  }

  if (!user) return null

  // Users without a password (OAuth-only) see a hint
  if (!user.hasPassword) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Password</CardTitle>
          <CardDescription>
            Your account is linked via an external provider. To set a password, use the
            &ldquo;Forgot password&rdquo; flow from the login page.
          </CardDescription>
        </CardHeader>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Change password</CardTitle>
        <CardDescription>
          Update your password. You will need to enter your current password first.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <AnimatePresence mode="wait">
          {showSuccess ? (
            <motion.div
              key="success"
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.9 }}
              transition={{ type: "spring", stiffness: 300, damping: 24 }}
              className="flex flex-col items-center justify-center py-12 text-center"
            >
              <motion.div
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                transition={{ type: "spring", stiffness: 200, damping: 12, delay: 0.1 }}
              >
                <CheckCircle2 className="h-12 w-12 text-success" />
              </motion.div>
              <motion.p
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.25 }}
                className="mt-4 font-medium text-lg"
              >
                Password updated
              </motion.p>
              <motion.p
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 0.4 }}
                className="mt-1 text-muted-foreground text-sm"
              >
                Your new password is now active.
              </motion.p>
            </motion.div>
          ) : (
            <motion.div
              key="form"
              initial={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.15 }}
            >
              <form onSubmit={handleSubmit} className="space-y-6">
                <div className="max-w-md space-y-4">
                  <ValidatedInput
                    label="Current password"
                    type="password"
                    placeholder="Enter current password"
                    value={currentPassword}
                    autoComplete="current-password"
                    validationRule={{ required: true }}
                    onChange={(value) => setCurrentPassword(value)}
                  />

                  <ValidatedInput
                    label="New password"
                    type="password"
                    placeholder="Enter new password"
                    value={newPassword}
                    autoComplete="new-password"
                    validationRule={{ required: true, custom: validatePassword }}
                    onChange={(value) => setNewPassword(value)}
                  />

                  {newPassword && (
                    <PasswordStrength password={newPassword} showRequirements />
                  )}

                  <ValidatedInput
                    label="Confirm new password"
                    type="password"
                    placeholder="Re-enter new password"
                    value={confirmPassword}
                    autoComplete="new-password"
                    error={confirmError}
                    validationRule={{ required: true }}
                    onChange={(value) => setConfirmPassword(value)}
                  />

                  {/* Confirm password match indicator */}
                  <AnimatePresence>
                    {confirmPassword.length > 0 && (
                      <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: "auto" }}
                        exit={{ opacity: 0, height: 0 }}
                        transition={{ duration: 0.2 }}
                        className={cn(
                          "flex items-center gap-1.5 text-sm",
                          passwordsMatch ? "text-success" : "text-destructive",
                        )}
                      >
                        {passwordsMatch ? (
                          <CheckCircle2 className="h-3.5 w-3.5 shrink-0" />
                        ) : (
                          <XCircle className="h-3.5 w-3.5 shrink-0" />
                        )}
                        <span>{passwordsMatch ? "Passwords match" : "Passwords don't match"}</span>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>

                <div className="flex justify-end">
                  <Button type="submit" disabled={!canSubmit || updatePassword.isPending}>
                    {updatePassword.isPending ? (
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    ) : (
                      <Lock className="mr-2 h-4 w-4" />
                    )}
                    Update password
                  </Button>
                </div>
              </form>
            </motion.div>
          )}
        </AnimatePresence>
      </CardContent>
    </Card>
  )
}
