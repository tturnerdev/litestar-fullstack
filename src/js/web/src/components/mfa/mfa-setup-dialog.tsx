import { ChevronDown, ShieldCheck } from "lucide-react"
import { useEffect, useMemo, useState } from "react"
import { toast } from "sonner"

import { BackupCodesDisplay } from "@/components/mfa/backup-codes-display"
import { TotpInput } from "@/components/mfa/totp-input"
import { Button } from "@/components/ui/button"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Skeleton } from "@/components/ui/skeleton"
import { cn } from "@/lib/utils"
import { useConfirmMfaSetup, useInitiateMfaSetup } from "@/lib/api/hooks/auth"
import type { MfaSetup } from "@/lib/generated/api"

interface MfaSetupDialogProps {
  disabled?: boolean
}

const STEPS = [
  { label: "Scan QR Code", step: 1 },
  { label: "Verify Code", step: 2 },
  { label: "Backup Codes", step: 3 },
] as const

function StepIndicator({ currentStep }: { currentStep: number }) {
  return (
    <div className="flex items-center justify-center gap-0 px-4 pb-2">
      {STEPS.map(({ label, step }, index) => (
        <div key={step} className="flex items-center">
          <div className="flex flex-col items-center gap-1">
            <div
              className={cn(
                "flex h-7 w-7 items-center justify-center rounded-full text-xs font-semibold transition-colors",
                step <= currentStep ? "bg-primary text-primary-foreground" : "border border-muted-foreground/30 bg-muted text-muted-foreground",
              )}
            >
              {step}
            </div>
            <span
              className={cn(
                "text-[11px] leading-tight whitespace-nowrap",
                step <= currentStep ? "font-medium text-foreground" : "text-muted-foreground",
              )}
            >
              {label}
            </span>
          </div>
          {index < STEPS.length - 1 && (
            <div
              className={cn(
                "mx-2 mb-5 h-px w-10 transition-colors",
                step < currentStep ? "bg-primary" : "bg-muted-foreground/30",
              )}
            />
          )}
        </div>
      ))}
    </div>
  )
}

export function MfaSetupDialog({ disabled }: MfaSetupDialogProps) {
  const [open, setOpen] = useState(false)
  const [setup, setSetup] = useState<MfaSetup | null>(null)
  const [codes, setCodes] = useState<string[] | null>(null)
  const [code, setCode] = useState("")
  const [secretOpen, setSecretOpen] = useState(false)
  const initiate = useInitiateMfaSetup()
  const confirm = useConfirmMfaSetup()

  const isLoading = initiate.isPending || confirm.isPending

  const currentStep = codes ? 3 : code.length > 0 ? 2 : 1

  useEffect(() => {
    if (!open) {
      setSetup(null)
      setCodes(null)
      setCode("")
      setSecretOpen(false)
      return
    }
    if (setup || initiate.isPending) {
      return
    }
    initiate
      .mutateAsync()
      .then((data) => setSetup(data))
      .catch((error) => {
        toast.error("Unable to start MFA setup", {
          description: error instanceof Error ? error.message : "Please try again",
        })
      })
  }, [open, initiate, setup])

  const handleConfirm = async () => {
    if (!code || code.length < 6) {
      toast.error("Enter the 6-digit code from your authenticator app")
      return
    }
    try {
      const result = await confirm.mutateAsync(code)
      setCodes(result.codes ?? [])
    } catch (error) {
      toast.error("Verification failed", {
        description: error instanceof Error ? error.message : "Check the code and try again",
      })
    }
  }

  const qrContent = useMemo(() => {
    if (initiate.isPending || !setup) {
      return (
        <div className="space-y-4">
          <Skeleton className="h-44 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      )
    }
    return (
      <div className="space-y-4">
        <div className="flex justify-center rounded-lg border border-border/60 bg-white p-4">
          <img src={setup.qrCode} alt="MFA QR code" className="h-48 w-48" />
        </div>
        <Collapsible open={secretOpen} onOpenChange={setSecretOpen}>
          <CollapsibleTrigger asChild>
            <button
              type="button"
              className="flex w-full items-center justify-center gap-1.5 text-sm text-muted-foreground transition-colors hover:text-foreground"
            >
              <span>Can&apos;t scan? Enter manually</span>
              <ChevronDown
                className={cn(
                  "h-4 w-4 transition-transform duration-200",
                  secretOpen && "rotate-180",
                )}
              />
            </button>
          </CollapsibleTrigger>
          <CollapsibleContent>
            <div className="mt-2 rounded-lg border border-border/60 bg-muted/30 px-4 py-3 font-mono text-sm select-all">
              {setup.secret}
            </div>
          </CollapsibleContent>
        </Collapsible>
        <TotpInput value={code} onChange={setCode} disabled={isLoading} autoFocus />
      </div>
    )
  }, [setup, initiate.isPending, code, isLoading, secretOpen])

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button disabled={disabled}>Enable MFA</Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-primary" />
            Enable multi-factor authentication
          </DialogTitle>
          <DialogDescription>Scan the QR code with your authenticator app, then enter the 6-digit verification code.</DialogDescription>
        </DialogHeader>
        <StepIndicator currentStep={currentStep} />
        {codes ? (
          <BackupCodesDisplay codes={codes} description="Save these codes in a secure place. Each code can be used once if you lose access to your authenticator." />
        ) : (
          qrContent
        )}
        <DialogFooter>
          {codes ? (
            <Button onClick={() => setOpen(false)}>Done</Button>
          ) : (
            <Button onClick={handleConfirm} disabled={isLoading || code.length < 6}>
              Verify &amp; finish
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
