import { Mail, Plus } from "lucide-react"
import { useState } from "react"
import { EmailRouteRow } from "@/components/fax/email-route-row"
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
    <Card>
      <CardHeader>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <CardTitle>Email Routes</CardTitle>
            <p className="text-sm text-muted-foreground mt-1">
              Configure where incoming faxes are delivered via email.
            </p>
          </div>
          <div className="flex flex-col gap-1">
            <div className="flex gap-2">
              <Input
                placeholder="email@example.com"
                value={newEmail}
                onChange={(e) => {
                  setNewEmail(e.target.value)
                  if (emailError) setEmailError(null)
                }}
                className="w-64"
                onKeyDown={(e) => e.key === "Enter" && handleAddRoute()}
                aria-invalid={!!emailError}
              />
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
        <Table>
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
                  <div className="flex flex-col items-center gap-2 py-4">
                    <Mail className="h-8 w-8 text-muted-foreground/50" />
                    <p>No email routes configured.</p>
                    <p className="text-xs">
                      Add an email address above to start receiving faxes via email.
                    </p>
                  </div>
                </TableCell>
              </TableRow>
            )}
            {data.items.map((route) => (
              <EmailRouteRow
                key={route.id}
                route={route}
                faxNumberId={faxNumberId}
                onDelete={() => deleteRoute.mutate(route.id)}
                isDeleting={deleteRoute.isPending}
              />
            ))}
          </TableBody>
        </Table>
        {data.items.length > 0 && (
          <p className="text-xs text-muted-foreground">
            {data.items.filter((r) => r.isActive).length} of {data.items.length} routes active
          </p>
        )}
      </CardContent>
    </Card>
  )
}
