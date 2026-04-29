import { useMutation } from "@tanstack/react-query"
import { Loader2, Lock } from "lucide-react"
import { useState } from "react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { PasswordStrength } from "@/components/ui/password-strength"
import ValidatedInput from "@/components/ui/validated-input"
import { validatePassword } from "@/hooks/use-validation"
import { useAuthStore } from "@/lib/auth"
import { accountPasswordUpdate } from "@/lib/generated/api"

export function PasswordChangeCard() {
  const { user } = useAuthStore()

  const [currentPassword, setCurrentPassword] = useState("")
  const [newPassword, setNewPassword] = useState("")
  const [confirmPassword, setConfirmPassword] = useState("")

  const resetForm = () => {
    setCurrentPassword("")
    setNewPassword("")
    setConfirmPassword("")
  }

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
      resetForm()
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
      </CardContent>
    </Card>
  )
}
