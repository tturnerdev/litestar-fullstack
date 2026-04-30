import { useState } from "react"
import { Info, ShieldAlert, ShieldCheck } from "lucide-react"
import { toast } from "sonner"
import { BackupCodesDisplay } from "@/components/mfa/backup-codes-display"
import { MfaDisableDialog } from "@/components/mfa/mfa-disable-dialog"
import { MfaSetupDialog } from "@/components/mfa/mfa-setup-dialog"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useMfaStatus, useRegenerateBackupCodes } from "@/lib/api/hooks/auth"
import { formatDateLong } from "@/lib/date-utils"

const TOTAL_BACKUP_CODES = 10

function InfoTooltip({ text }: { text: string }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button type="button" className="inline-flex items-center text-muted-foreground transition-colors hover:text-foreground">
          <Info className="h-3.5 w-3.5" />
          <span className="sr-only">More info</span>
        </button>
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-xs">
        {text}
      </TooltipContent>
    </Tooltip>
  )
}

function BackupCodesProgress({ remaining }: { remaining: number }) {
  const percent = (remaining / TOTAL_BACKUP_CODES) * 100
  const color = percent > 50 ? "bg-green-500" : percent > 20 ? "bg-amber-500" : "bg-red-500"
  const textColor = percent > 50 ? "text-green-600" : percent > 20 ? "text-amber-600" : "text-red-600"

  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between text-sm">
        <span className="flex items-center gap-1.5 text-muted-foreground">
          Backup codes remaining
          <InfoTooltip text="Backup codes let you sign in if you lose access to your authenticator app. Each code can only be used once." />
        </span>
        <span className={`font-medium tabular-nums ${textColor}`}>
          {remaining} of {TOTAL_BACKUP_CODES}
        </span>
      </div>
      <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
        <div
          className={`h-full rounded-full transition-all ${color}`}
          style={{ width: `${percent}%` }}
        />
      </div>
    </div>
  )
}

export function MfaSection() {
  const { data, isLoading, isError } = useMfaStatus()
  const regenerate = useRegenerateBackupCodes()
  const [regenOpen, setRegenOpen] = useState(false)
  const [regenPassword, setRegenPassword] = useState("")
  const [regenCodes, setRegenCodes] = useState<string[] | null>(null)

  if (isLoading) {
    return <SkeletonCard />
  }

  if (isError || !data) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Multi-factor authentication</CardTitle>
          <CardDescription>We could not load MFA status.</CardDescription>
        </CardHeader>
      </Card>
    )
  }

  const handleRegenerate = async () => {
    if (!regenPassword) {
      toast.error("Enter your password to regenerate backup codes")
      return
    }
    try {
      const result = await regenerate.mutateAsync(regenPassword)
      setRegenCodes(result.codes ?? [])
    } catch (error) {
      toast.error("Unable to regenerate codes", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          Multi-factor authentication
          <InfoTooltip text="Multi-factor authentication adds a second step to your sign-in process, making your account much more secure against unauthorized access." />
        </CardTitle>
        <CardDescription>{data.enabled ? "MFA is enabled on your account." : "Add an extra layer of security to your account."}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Status banner */}
        {data.enabled ? (
          <div className="flex items-center gap-3 rounded-lg border border-green-200 bg-green-50 px-4 py-3 dark:border-green-900 dark:bg-green-950/30">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-green-100 dark:bg-green-900/50">
              <ShieldCheck className="h-5 w-5 text-green-600 dark:text-green-400" />
            </div>
            <div className="min-w-0">
              <p className="text-sm font-medium text-green-800 dark:text-green-300">Protected</p>
              <p className="text-xs text-green-600 dark:text-green-400">
                Your account is secured with multi-factor authentication.
                {data.confirmedAt && (
                  <span> Enabled on {formatDateLong(data.confirmedAt)}.</span>
                )}
              </p>
            </div>
          </div>
        ) : (
          <div className="flex items-center gap-3 rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 dark:border-amber-900 dark:bg-amber-950/30">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-amber-100 dark:bg-amber-900/50">
              <ShieldAlert className="h-5 w-5 text-amber-600 dark:text-amber-400" />
            </div>
            <div className="min-w-0">
              <p className="text-sm font-medium text-amber-800 dark:text-amber-300">Not Protected</p>
              <p className="text-xs text-amber-600 dark:text-amber-400">
                Your account does not have multi-factor authentication enabled. We strongly recommend enabling it.
              </p>
            </div>
          </div>
        )}

        {/* Backup codes progress (only when MFA is enabled) */}
        {data.enabled && data.backupCodesRemaining != null && (
          <BackupCodesProgress remaining={data.backupCodesRemaining} />
        )}

        {/* Actions */}
        {data.enabled ? (
          <div className="flex flex-wrap gap-2">
            <MfaDisableDialog />
            <Button variant="outline" onClick={() => setRegenOpen(true)}>
              Regenerate backup codes
            </Button>
          </div>
        ) : (
          <MfaSetupDialog />
        )}
      </CardContent>
      <Dialog open={regenOpen} onOpenChange={setRegenOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Regenerate backup codes</DialogTitle>
            <DialogDescription>Confirm your password to generate a fresh set of codes.</DialogDescription>
          </DialogHeader>
          {regenCodes ? (
            <BackupCodesDisplay codes={regenCodes} description="These codes replace your previous set. Store them securely." />
          ) : (
            <Input type="password" placeholder="Password" value={regenPassword} onChange={(event) => setRegenPassword(event.target.value)} />
          )}
          <DialogFooter>
            {regenCodes ? (
              <Button onClick={() => setRegenOpen(false)}>Done</Button>
            ) : (
              <Button onClick={handleRegenerate} disabled={regenerate.isPending}>
                Regenerate
              </Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  )
}
