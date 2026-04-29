import { Link } from "@tanstack/react-router"
import { AlertTriangle, Loader2, Trash2 } from "lucide-react"
import { useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { SkeletonTable } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useDeleteExtension, useExtensions } from "@/lib/api/hooks/voice"

const PAGE_SIZE = 25

export function ExtensionTable() {
  const [page, setPage] = useState(1)
  const { data, isLoading, isError } = useExtensions(page, PAGE_SIZE)
  const [deleteTarget, setDeleteTarget] = useState<{ id: string; displayName: string; extensionNumber: string } | null>(null)
  const deleteMutation = useDeleteExtension()

  if (isLoading) return <SkeletonTable rows={6} />

  if (isError || !data) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Extensions</CardTitle>
        </CardHeader>
        <CardContent className="text-muted-foreground">We could not load extensions.</CardContent>
      </Card>
    )
  }

  const totalPages = Math.max(1, Math.ceil(data.total / PAGE_SIZE))

  return (
    <Card>
      <CardHeader>
        <CardTitle>Extensions</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Extension</TableHead>
              <TableHead>Display Name</TableHead>
              <TableHead>Phone Number</TableHead>
              <TableHead>Status</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.items.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} className="h-24 text-center text-muted-foreground">
                  No extensions found.
                </TableCell>
              </TableRow>
            ) : (
              data.items.map((ext) => (
                <TableRow key={ext.id}>
                  <TableCell className="font-mono">{ext.extensionNumber}</TableCell>
                  <TableCell>{ext.displayName}</TableCell>
                  <TableCell>{ext.phoneNumberId ? <Badge variant="secondary">Assigned</Badge> : <span className="text-muted-foreground">--</span>}</TableCell>
                  <TableCell>
                    <Badge variant={ext.isActive ? "default" : "outline"}>{ext.isActive ? "Active" : "Inactive"}</Badge>
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-2">
                      <Button asChild variant="outline" size="sm">
                        <Link to="/voice/extensions/$extensionId" params={{ extensionId: ext.id }}>
                          Settings
                        </Link>
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        className="text-destructive hover:bg-destructive hover:text-destructive-foreground"
                        onClick={() => setDeleteTarget({ id: ext.id, displayName: ext.displayName, extensionNumber: ext.extensionNumber })}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
        {totalPages > 1 && (
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">
              Page {page} of {totalPages}
            </p>
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page <= 1}>
                Previous
              </Button>
              <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page >= totalPages}>
                Next
              </Button>
            </div>
          </div>
        )}
      </CardContent>

      <Dialog open={deleteTarget !== null} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-destructive" />
              Delete Extension
            </DialogTitle>
            <DialogDescription>
              Are you sure you want to delete extension{" "}
              <span className="font-medium">{deleteTarget?.displayName}</span>{" "}
              (Ext. <span className="font-mono">{deleteTarget?.extensionNumber}</span>)? This action cannot be undone.
              All associated forwarding rules, voicemail, and DND settings will be permanently removed.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)} disabled={deleteMutation.isPending}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => {
                if (!deleteTarget) return
                deleteMutation.mutate(deleteTarget.id, {
                  onSuccess: () => setDeleteTarget(null),
                })
              }}
              disabled={deleteMutation.isPending}
            >
              {deleteMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  )
}
