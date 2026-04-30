import { AlertTriangle, Loader2, ShieldOff } from "lucide-react"
import { useState } from "react"
import { toast } from "sonner"

import { Alert, AlertDescription } from "@/components/ui/alert"
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { useDisableMfa, useInitiateDisableMfaOAuth } from "@/lib/api/hooks/auth"
import { useAuthStore } from "@/lib/auth"

interface MfaDisableDialogProps {
  disabled?: boolean
}

export function MfaDisableDialog({ disabled }: MfaDisableDialogProps) {
  const [open, setOpen] = useState(false)
  const [password, setPassword] = useState("")
  const { user } = useAuthStore()
  const disableMfa = useDisableMfa()
  const initiateOAuth = useInitiateDisableMfaOAuth()

  const hasPassword = user?.hasPassword ?? true
  const oauthProvider = user?.oauthAccounts?.[0]?.oauthName

  const handleClose = () => {
    setOpen(false)
    setPassword("")
  }

  const handlePasswordDisable = async () => {
    if (!password) {
      toast.error("Enter your password to disable MFA")
      return
    }
    try {
      await disableMfa.mutateAsync(password)
      handleClose()
    } catch (error) {
      toast.error("Unable to disable MFA", {
        description: error instanceof Error ? error.message : "Check your password and try again",
      })
    }
  }

  const handleOAuthDisable = async () => {
    if (!oauthProvider) {
      toast.error("No linked OAuth account found")
      return
    }
    try {
      const result = await initiateOAuth.mutateAsync(oauthProvider)
      if (result.authorizationUrl) {
        window.location.href = result.authorizationUrl
      }
    } catch (error) {
      toast.error("Unable to start OAuth verification", {
        description: error instanceof Error ? error.message : "Please try again",
      })
    }
  }

  const formatProviderName = (provider: string) => {
    return provider.charAt(0).toUpperCase() + provider.slice(1)
  }

  return (
    <AlertDialog open={open} onOpenChange={setOpen}>
      <Button variant="outline" disabled={disabled} onClick={() => setOpen(true)}>
        Disable MFA
      </Button>
      <AlertDialogContent onInteractOutside={(e) => e.preventDefault()}>
        <AlertDialogHeader>
          <AlertDialogTitle className="flex items-center gap-2">
            <ShieldOff className="h-5 w-5 text-destructive" />
            Disable multi-factor authentication
          </AlertDialogTitle>
          <AlertDialogDescription>{hasPassword ? "Confirm your password to turn off MFA." : "Re-authenticate with your linked account to turn off MFA."}</AlertDialogDescription>
        </AlertDialogHeader>

        <Alert variant="warning">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>
            Disabling MFA will reduce your account security. Your account will be protected by password only. If your password is compromised, an attacker could access your account.
          </AlertDescription>
        </Alert>

        {hasPassword ? (
          <>
            <Input type="password" placeholder="Password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} />
            <AlertDialogFooter>
              <AlertDialogCancel onClick={handleClose}>Cancel</AlertDialogCancel>
              <Button variant="destructive" onClick={handlePasswordDisable} disabled={disableMfa.isPending}>
                {disableMfa.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
                Disable MFA
              </Button>
            </AlertDialogFooter>
          </>
        ) : (
          <AlertDialogFooter>
            <AlertDialogCancel onClick={handleClose}>Cancel</AlertDialogCancel>
            <Button variant="destructive" onClick={handleOAuthDisable} disabled={initiateOAuth.isPending}>
              {initiateOAuth.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
              Verify with {oauthProvider ? formatProviderName(oauthProvider) : "OAuth"}
            </Button>
          </AlertDialogFooter>
        )}
      </AlertDialogContent>
    </AlertDialog>
  )
}
