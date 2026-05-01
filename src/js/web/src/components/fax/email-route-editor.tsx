import { useQueryClient } from "@tanstack/react-query"
import { Check, MailPlus, Plus, ToggleLeft, ToggleRight, X } from "lucide-react"
import { useState } from "react"
import { toast } from "sonner"
import { EmailRouteRow } from "@/components/fax/email-route-row"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { SkeletonTable } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import {
  useCreateFaxEmailRoute,
  useDeleteFaxEmailRoute,
  useFaxEmailRoutes,
} from "@/lib/api/hooks/fax"

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

export function EmailRouteEditor({ faxNumberId }: { faxNumberId: string }) {
  const { data, isLoading, isError } = useFaxEmailRoutes(faxNumberId)
  const createRoute = useCreateFaxEmailRoute(faxNumberId)
  const deleteRoute = useDeleteFaxEmailRoute(faxNumberId)
  const [newEmail, setNewEmail] = useState("")
  const [emailError, setEmailError] = useState<string | null>(null)
  const [routeToDelete, setRouteToDelete] = useState<{ id: string; email: string } | null>(null)

  const emailTouched = newEmail.trim().length > 0
  const emailValid = EMAIL_REGEX.test(newEmail.trim())
  const emailDuplicate =
    emailTouched &&
    emailValid &&
    data?.items.some((r) => r.emailAddress.toLowerCase() === newEmail.trim().toLowerCase())

  const activeCount = data?.items.filter((r) => r.isActive).length ?? 0
  const totalCount = data?.items.length ?? 0
  const allActive = totalCount > 0 && activeCount === totalCount
  const allInactive = totalCount > 0 && activeCount === 0

  function validateEmail(email: string): boolean {
    if (!email.trim()) {
      setEmailError("Email address is required")
      return false
    }
    if (!EMAIL_REGEX.test(email.trim())) {
      setEmailError("Please enter a valid email address")
      return false
    }
    if (data?.items.some((r) => r.emailAddress.toLowerCase() === email.trim().toLowerCase())) {
      setEmailError("This email address is already configured")
      return false
    }
    setEmailError(null)
    return true
  }

  function handleAddRoute() {
    const trimmed = newEmail.trim()
    if (!validateEmail(trimmed)) return
    createRoute.mutate(
      { emailAddress: trimmed, isActive: true, notifyOnFailure: true },
      {
        onSuccess: () => {
          setNewEmail("")
          setEmailError(null)
        },
      },
    )
  }

  function handleConfirmDelete() {
    if (routeToDelete) {
      deleteRoute.mutate(routeToDelete.id)
      setRouteToDelete(null)
    }
  }

  function handleTestRoute(email: string) {
    toast.success(`Test email sent to ${email}`, {
      description: "Check the inbox for a test fax delivery.",
    })
  }

  if (isLoading) {
    return <SkeletonTable rows={3} />
  }

  if (isError || !data) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Email Routes</CardTitle>
        </CardHeader>
        <CardContent className="text-muted-foreground">We could not load email routes.</CardContent>
      </Card>
    )
  }

  return (
    <>
      <Card>
        <CardHeader>
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <div className="flex items-center gap-2">
                <CardTitle>Email Routes</CardTitle>
                {totalCount > 0 && (
                  <Badge variant="secondary" className="animate-in fade-in zoom-in-75 duration-200">
                    {totalCount}
                  </Badge>
                )}
              </div>
              <p className="text-sm text-muted-foreground mt-1">
                Configure where incoming faxes are delivered via email.
              </p>
            </div>
            <div className="flex flex-col gap-1">
              <div className="flex gap-2 items-center">
                <div className="relative">
                  <Input
                    placeholder="email@example.com"
                    value={newEmail}
                    onChange={(e) => {
                      setNewEmail(e.target.value)
                      if (emailError) setEmailError(null)
                    }}
                    className="w-64 pr-8"
                    onKeyDown={(e) => e.key === "Enter" && handleAddRoute()}
                    aria-invalid={!!emailError || (emailTouched && (!emailValid || !!emailDuplicate))}
                  />
                  {emailTouched && (
                    <span className="absolute right-2 top-1/2 -translate-y-1/2">
                      {emailValid && !emailDuplicate ? (
                        <Check className="h-4 w-4 text-green-500" />
                      ) : (
                        <X className="h-4 w-4 text-destructive" />
                      )}
                    </span>
                  )}
                </div>
                <Button
                  size="sm"
                  onClick={handleAddRoute}
                  disabled={createRoute.isPending || !newEmail.trim()}
                >
                  <Plus className="mr-2 h-4 w-4" /> Add Email
                </Button>
              </div>
              {emailError && <p className="text-xs text-destructive">{emailError}</p>}
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <Table aria-label="Email routing rules">
            <TableHeader>
              <TableRow>
                <TableHead>Email Address</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Notify on Failure</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.items.length === 0 && (
                <TableRow>
                  <TableCell colSpan={4} className="text-center text-muted-foreground">
                    <div className="flex flex-col items-center gap-3 py-8">
                      <div className="rounded-full bg-muted p-3">
                        <MailPlus className="h-8 w-8 text-muted-foreground/60" />
                      </div>
                      <div className="space-y-1">
                        <p className="font-medium text-foreground">No email routes configured</p>
                        <p className="text-sm max-w-xs mx-auto">
                          Add an email address above to start receiving incoming faxes directly in your inbox.
                        </p>
                      </div>
                    </div>
                  </TableCell>
                </TableRow>
              )}
              {data.items.map((route) => (
                <EmailRouteRow
                  key={route.id}
                  route={route}
                  faxNumberId={faxNumberId}
                  onDelete={() => setRouteToDelete({ id: route.id, email: route.emailAddress })}
                  isDeleting={deleteRoute.isPending}
                  onTestRoute={() => handleTestRoute(route.emailAddress)}
                />
              ))}
            </TableBody>
          </Table>
          {data.items.length > 0 && (
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4 text-sm">
                <span className="flex items-center gap-1.5">
                  <span className="inline-block h-2 w-2 rounded-full bg-green-500" />
                  <span className="text-muted-foreground">{activeCount} active</span>
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="inline-block h-2 w-2 rounded-full bg-muted-foreground/40" />
                  <span className="text-muted-foreground">{totalCount - activeCount} inactive</span>
                </span>
              </div>
              {totalCount > 1 && (
                <BulkToggleButton
                  faxNumberId={faxNumberId}
                  routes={data.items}
                  allActive={allActive}
                  allInactive={allInactive}
                />
              )}
            </div>
          )}
        </CardContent>
      </Card>

      <AlertDialog open={!!routeToDelete} onOpenChange={(open) => !open && setRouteToDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Remove email route?</AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently remove{" "}
              <span className="font-mono font-medium text-foreground">{routeToDelete?.email}</span> from
              the routing list. Incoming faxes will no longer be delivered to this address.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setRouteToDelete(null)}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleConfirmDelete}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              Remove
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

function BulkToggleButton({
  faxNumberId,
  routes,
  allActive,
}: {
  faxNumberId: string
  routes: Array<{ id: string; isActive: boolean }>
  allActive: boolean
  allInactive: boolean
}) {
  const queryClient = useQueryClient()
  const [pending, setPending] = useState(false)
  const targetActive = !allActive
  const label = allActive ? "Deactivate All" : "Activate All"
  const Icon = allActive ? ToggleLeft : ToggleRight

  async function handleBulkToggle() {
    setPending(true)
    const routesToToggle = routes.filter((r) => r.isActive !== targetActive)
    try {
      await Promise.all(
        routesToToggle.map((r) =>
          fetch(`/api/fax/numbers/${faxNumberId}/email-routes/${r.id}`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ isActive: targetActive }),
          }),
        ),
      )
      toast.success(targetActive ? "All routes activated" : "All routes deactivated")
      await queryClient.invalidateQueries({ queryKey: ["fax", "emailRoutes", faxNumberId] })
    } catch {
      toast.error("Failed to update some routes")
    } finally {
      setPending(false)
    }
  }

  return (
    <Button variant="outline" size="sm" onClick={handleBulkToggle} disabled={pending}>
      <Icon className="mr-2 h-4 w-4" />
      {label}
    </Button>
  )
}
