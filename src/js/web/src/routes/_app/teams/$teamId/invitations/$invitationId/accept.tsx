import { useMutation, useQuery } from "@tanstack/react-query"
import { createFileRoute, useNavigate, useParams } from "@tanstack/react-router"
import { AnimatePresence, motion } from "framer-motion"
import { AlertCircle, CheckCircle, Users, XCircle } from "lucide-react"
import { useState } from "react"
import { toast } from "sonner"
import { Icons } from "@/components/icons"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { EmptyState } from "@/components/ui/empty-state"
import { PageContainer } from "@/components/ui/page-layout"
import { acceptTeamInvitation, getTeam, rejectTeamInvitation } from "@/lib/generated/api"

export const Route = createFileRoute("/_app/teams/$teamId/invitations/$invitationId/accept")({
  component: AcceptInvitationPage,
})

function AcceptInvitationPage() {
  const navigate = useNavigate()
  const { teamId, invitationId } = useParams({
    from: "/_app/teams/$teamId/invitations/$invitationId/accept",
  })
  const [status, setStatus] = useState<"pending" | "accepting" | "declining" | "accepted" | "declined" | "error">("pending")
  const [errorMessage, setErrorMessage] = useState<string | null>(null)

  const { data: team, isLoading: isTeamLoading, isError: isTeamError } = useQuery({
    queryKey: ["team", teamId],
    queryFn: async () => {
      const response = await getTeam({ path: { team_id: teamId } })
      return response.data
    },
    retry: false,
  })

  const acceptMutation = useMutation({
    mutationFn: async () => {
      const response = await acceptTeamInvitation({
        path: { team_id: teamId, invitation_id: invitationId },
      })
      if (response.error) {
        throw new Error(response.error.detail || "Failed to accept invitation")
      }
      return response.data
    },
    onMutate: () => {
      setStatus("accepting")
      setErrorMessage(null)
    },
    onSuccess: () => {
      setStatus("accepted")
      toast.success("You've joined the team!")
      // Navigate to the team page after a short delay
      setTimeout(() => {
        navigate({ to: "/teams/$teamId", params: { teamId } })
      }, 1500)
    },
    onError: (error: Error) => {
      setStatus("error")
      setErrorMessage(error.message)
      toast.error("Failed to accept invitation", {
        description: error.message,
      })
    },
  })

  const declineMutation = useMutation({
    mutationFn: async () => {
      const response = await rejectTeamInvitation({
        path: { team_id: teamId, invitation_id: invitationId },
      })
      if (response.error) {
        throw new Error(response.error.detail || "Failed to decline invitation")
      }
      return response.data
    },
    onMutate: () => {
      setStatus("declining")
      setErrorMessage(null)
    },
    onSuccess: () => {
      setStatus("declined")
      toast.success("Invitation declined")
      // Navigate to teams list after a short delay
      setTimeout(() => {
        navigate({ to: "/teams" })
      }, 1500)
    },
    onError: (error: Error) => {
      setStatus("error")
      setErrorMessage(error.message)
      toast.error("Failed to decline invitation", {
        description: error.message,
      })
    },
  })

  const isPending = status === "pending"
  const isProcessing = status === "accepting" || status === "declining"
  const isComplete = status === "accepted" || status === "declined"

  const memberCount = team?.members?.length

  if (isTeamError) {
    return (
      <PageContainer className="flex flex-1 items-center justify-center">
        <EmptyState
          icon={AlertCircle}
          title="Unable to load invitation"
          description="This invitation may be invalid or expired. Please check the link and try again."
          action={
            <Button variant="outline" size="sm" onClick={() => window.location.reload()}>
              Refresh page
            </Button>
          }
        />
      </PageContainer>
    )
  }

  return (
    <PageContainer className="relative flex flex-1 items-center justify-center overflow-hidden">
      {/* Gradient background */}
      <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
        <div className="h-[500px] w-[500px] rounded-full bg-primary/5 blur-3xl" />
      </div>
      <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
        <div className="h-[300px] w-[300px] translate-x-20 translate-y-10 rounded-full bg-primary/8 blur-2xl" />
      </div>

      <motion.div
        className="relative z-10 w-full max-w-md"
        initial={{ opacity: 0, y: 24, scale: 0.97 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ duration: 0.5, ease: [0.25, 0.1, 0.25, 1] }}
      >
        <Card className="border-border/60 bg-card/80 shadow-xl shadow-primary/15">
          <CardHeader className="text-center">
            <div className="mx-auto mb-4">
              <AnimatePresence mode="wait">
                {status === "accepted" ? (
                  <motion.div
                    key="accepted"
                    className="flex h-16 w-16 items-center justify-center rounded-full bg-emerald-500/10"
                    initial={{ scale: 0, opacity: 0 }}
                    animate={{ scale: 1, opacity: 1 }}
                    transition={{ type: "spring", stiffness: 300, damping: 15 }}
                  >
                    <CheckCircle className="h-8 w-8 text-emerald-500" />
                  </motion.div>
                ) : status === "declined" ? (
                  <motion.div
                    key="declined"
                    className="flex h-16 w-16 items-center justify-center rounded-full bg-muted"
                    initial={{ scale: 0, opacity: 0 }}
                    animate={{ scale: 1, opacity: 1 }}
                    transition={{ type: "spring", stiffness: 300, damping: 15 }}
                  >
                    <XCircle className="h-8 w-8 text-muted-foreground" />
                  </motion.div>
                ) : (
                  <motion.div
                    key="pending"
                    className="flex h-16 w-16 items-center justify-center rounded-full bg-primary/10"
                    initial={{ scale: 0.8, opacity: 0 }}
                    animate={{ scale: 1, opacity: 1 }}
                    transition={{ duration: 0.4 }}
                  >
                    <Users className="h-8 w-8 text-primary" />
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
            <CardTitle className="text-xl">
              {status === "accepted" ? "Welcome to the team!" : status === "declined" ? "Invitation declined" : "Team Invitation"}
            </CardTitle>
            <CardDescription className="mt-1">
              {status === "accepted" ? (
                "You're now a member. Redirecting..."
              ) : status === "declined" ? (
                "You won't be added to this team."
              ) : isTeamLoading ? (
                "Loading invitation details..."
              ) : team ? (
                <>
                  You've been invited to join <strong className="text-foreground">{team.name}</strong>
                </>
              ) : (
                "You've been invited to join a team"
              )}
            </CardDescription>
          </CardHeader>

          <CardContent>
            {/* Team details */}
            {isPending && team && (team.description || memberCount != null) && (
              <motion.div
                className="mb-4 rounded-lg border border-border/40 bg-muted/30 p-4 space-y-2"
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.2, duration: 0.4 }}
              >
                {team.description && (
                  <p className="text-sm text-muted-foreground">{team.description}</p>
                )}
                {memberCount != null && memberCount > 0 && (
                  <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                    <Users className="h-3.5 w-3.5" />
                    <span>
                      {memberCount} {memberCount === 1 ? "member" : "members"}
                    </span>
                  </div>
                )}
              </motion.div>
            )}

            {status === "error" && errorMessage && (
              <Alert variant="destructive" className="mb-4">
                <AlertDescription>{errorMessage}</AlertDescription>
              </Alert>
            )}

            {isProcessing && (
              <div className="flex flex-col items-center space-y-3 py-4">
                <Icons.spinner className="h-8 w-8 animate-spin text-primary" />
                <p className="text-sm text-muted-foreground">{status === "accepting" ? "Joining team..." : "Declining invitation..."}</p>
              </div>
            )}

            <AnimatePresence>
              {isComplete && (
                <motion.div
                  className="flex flex-col items-center space-y-3 py-4"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.3 }}
                >
                  <Icons.spinner className="h-6 w-6 animate-spin text-muted-foreground" />
                  <p className="text-sm text-muted-foreground">Redirecting...</p>
                </motion.div>
              )}
            </AnimatePresence>
          </CardContent>

          {(isPending || status === "error") && (
            <CardFooter className="flex flex-col gap-2">
              <Button className="w-full" onClick={() => acceptMutation.mutate()} disabled={isProcessing}>
                Accept Invitation
              </Button>
              <Button variant="outline" className="w-full" onClick={() => declineMutation.mutate()} disabled={isProcessing}>
                Decline
              </Button>
            </CardFooter>
          )}
        </Card>
      </motion.div>
    </PageContainer>
  )
}
