import { AlertTriangle, ShieldOff } from "lucide-react"
import { useState } from "react"
import { toast } from "sonner"

import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
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

  const handlePasswordDisable = async () => {
    if (!password) {
      toast.error("Enter your password to disable MFA")
      return
    }
    try {
      await disableMfa.mutateAsync(password)
      setOpen(false)
      setPassword("")
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
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" disabled={disabled}>
          Disable MFA
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ShieldOff className="h-5 w-5 text-destructive" />
            Disable multi-factor authentication
          </DialogTitle>
          <DialogDescription>{hasPassword ? "Confirm your password to turn off MFA." : "Re-authenticate with your linked account to turn off MFA."}</DialogDescription>
        </DialogHeader>

        <Alert variant="warning">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>
            Disabling MFA will reduce your account security. Your account will only be protected by your password.
          </AlertDescription>
        </Alert>

        {hasPassword ? (
          <>
            <Input type="password" placeholder="Password" value={password} onChange={(event) => setPassword(event.target.value)} />
            <DialogFooter>
              <Button variant="destructive" onClick={handlePasswordDisable} disabled={disableMfa.isPending}>
                Disable MFA
              </Button>
            </DialogFooter>
          </>
        ) : (
          <DialogFooter>
            <Button variant="destructive" onClick={handleOAuthDisable} disabled={initiateOAuth.isPending}>
              Verify with {oauthProvider ? formatProviderName(oauthProvider) : "OAuth"}
            </Button>
          </DialogFooter>
        )}
      </DialogContent>
    </Dialog>
  )
}
