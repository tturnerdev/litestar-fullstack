import { createFileRoute, Link, useNavigate, useSearch } from "@tanstack/react-router"
import { motion } from "framer-motion"
import { ArrowLeft, ShieldCheck } from "lucide-react"
import { useState } from "react"
import { toast } from "sonner"
import { z } from "zod"
import { AuthHeroPanel } from "@/components/auth/auth-hero-panel"
import { Icons } from "@/components/icons"
import { TotpInput } from "@/components/mfa/totp-input"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useVerifyMfaChallenge } from "@/lib/api/hooks/auth"
import { useAuthStore } from "@/lib/auth"
import { getSafeRedirectUrl } from "@/lib/redirect-utils"

export const Route = createFileRoute("/_public/mfa-challenge")({
  validateSearch: (search) =>
    z
      .object({
        redirect: z.string().optional(),
      })
      .parse(search),
  component: MfaChallengePage,
})

function MfaChallengePage() {
  const navigate = useNavigate()
  const { redirect } = useSearch({ from: "/_public/mfa-challenge" })
  const { completeMfaLogin } = useAuthStore()
  const verify = useVerifyMfaChallenge()
  const [tab, setTab] = useState("totp")
  const [code, setCode] = useState("")
  const [recoveryCode, setRecoveryCode] = useState("")

  // Validate and get safe redirect destination
  const finalRedirect = getSafeRedirectUrl(redirect)

  const handleVerify = async () => {
    try {
      const payload = tab === "totp" ? { code } : { recovery_code: recoveryCode.trim().toUpperCase() }
      const response = await verify.mutateAsync(payload)
      const accessToken = (response as { access_token?: string })?.access_token
      if (!accessToken) {
        toast.error("Verification failed")
        return
      }
      await completeMfaLogin(accessToken)
      toast.success("MFA verified")
      navigate({ to: finalRedirect })
    } catch (error) {
      toast.error("Verification failed", {
        description: error instanceof Error ? error.message : "Try again",
      })
    }
  }

  const disableAction = verify.isPending || (tab === "totp" ? code.length < 6 : !recoveryCode)

  return (
    <div className="relative flex min-h-screen w-full">
      <AuthHeroPanel showTestimonial={false} description="Two-factor authentication keeps your account secure." />
      <div className="flex flex-1 flex-col items-center justify-center bg-brand-gray-light px-4 py-12 dark:bg-background">
        <motion.div
          className="w-full max-w-md"
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, ease: [0.25, 0.1, 0.25, 1] }}
        >
          <div className="mb-8 flex flex-col items-center space-y-3">
            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-primary/10 shadow-sm">
              <ShieldCheck className="h-6 w-6 text-primary" />
            </div>
            <h1 className="text-2xl font-semibold tracking-tight">Verify your identity</h1>
            <p className="text-center text-sm text-muted-foreground">Enter a code from your authenticator app or use a backup code.</p>
          </div>

          <Card className="border-border/50 bg-card/80 shadow-lg backdrop-blur-sm dark:bg-card/60">
            <CardContent className="space-y-5 px-6 py-6">
              <Tabs value={tab} onValueChange={setTab}>
                <TabsList className="grid w-full grid-cols-2">
                  <TabsTrigger value="totp">Authenticator</TabsTrigger>
                  <TabsTrigger value="recovery">Backup code</TabsTrigger>
                </TabsList>
                <TabsContent value="totp" className="space-y-3 pt-4">
                  <TotpInput value={code} onChange={setCode} autoFocus />
                  <p className="text-xs text-muted-foreground/70">Enter the 6-digit code from your authenticator app</p>
                </TabsContent>
                <TabsContent value="recovery" className="space-y-3 pt-4">
                  <Input placeholder="XXXX-XXXX" value={recoveryCode} onChange={(event) => setRecoveryCode(event.target.value)} />
                  <p className="text-xs text-muted-foreground/70">Enter one of your backup recovery codes</p>
                </TabsContent>
              </Tabs>

              <Button className="w-full" onClick={handleVerify} disabled={disableAction}>
                {verify.isPending ? <Icons.spinner className="mr-2 h-4 w-4 animate-spin" /> : null}
                {verify.isPending ? "Verifying..." : "Verify"}
              </Button>
            </CardContent>
          </Card>

          <div className="mt-6 text-center">
            <Button asChild variant="ghost" size="sm">
              <Link to="/login">
                <ArrowLeft className="mr-2 h-4 w-4" />
                Back to login
              </Link>
            </Button>
          </div>
        </motion.div>
      </div>
    </div>
  )
}
