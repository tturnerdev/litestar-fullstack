import { Mail, Plus, Trash2 } from "lucide-react"
import { useState } from "react"
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
  useUpdateFaxEmailRoute,
} from "@/lib/api/hooks/fax"

export function EmailRouteEditor({ faxNumberId }: { faxNumberId: string }) {
  const { data, isLoading, isError } = useFaxEmailRoutes(faxNumberId)
  const createRoute = useCreateFaxEmailRoute(faxNumberId)
  const deleteRoute = useDeleteFaxEmailRoute(faxNumberId)
  const [newEmail, setNewEmail] = useState("")

  function handleAddRoute() {
    const trimmed = newEmail.trim()
    if (!trimmed) return
    createRoute.mutate({ emailAddress: trimmed }, {
      onSuccess: () => setNewEmail(""),
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
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle>Email Routes</CardTitle>
          <div className="flex gap-2">
            <Input
              placeholder="email@example.com"
              value={newEmail}
              onChange={(e) => setNewEmail(e.target.value)}
              className="w-64"
              onKeyDown={(e) => e.key === "Enter" && handleAddRoute()}
            />
            <Button size="sm" onClick={handleAddRoute} disabled={createRoute.isPending || !newEmail.trim()}>
              <Plus className="mr-2 h-4 w-4" /> Add
            </Button>
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
                    <p>No email routes configured. Add one above.</p>
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
      </CardContent>
    </Card>
  )
}

function EmailRouteRow({
  route,
  faxNumberId,
  onDelete,
  isDeleting,
}: {
  route: { id: string; emailAddress: string; isActive: boolean; notifyOnFailure: boolean }
  faxNumberId: string
  onDelete: () => void
  isDeleting: boolean
}) {
  const updateRoute = useUpdateFaxEmailRoute(faxNumberId, route.id)

  return (
    <TableRow>
      <TableCell className="font-mono text-sm">{route.emailAddress}</TableCell>
      <TableCell>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => updateRoute.mutate({ isActive: !route.isActive })}
          disabled={updateRoute.isPending}
        >
          <Badge variant={route.isActive ? "default" : "secondary"}>
            {route.isActive ? "Active" : "Inactive"}
          </Badge>
        </Button>
      </TableCell>
      <TableCell>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => updateRoute.mutate({ notifyOnFailure: !route.notifyOnFailure })}
          disabled={updateRoute.isPending}
        >
          <Badge variant={route.notifyOnFailure ? "default" : "outline"}>
            {route.notifyOnFailure ? "Yes" : "No"}
          </Badge>
        </Button>
      </TableCell>
      <TableCell className="text-right">
        <Button variant="outline" size="sm" onClick={onDelete} disabled={isDeleting}>
          <Trash2 className="h-4 w-4" />
        </Button>
      </TableCell>
    </TableRow>
  )
}
