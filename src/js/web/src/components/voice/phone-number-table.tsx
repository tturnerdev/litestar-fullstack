import { AlertCircle, AlertTriangle, Loader2, Phone, Trash2 } from "lucide-react"
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
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { SkeletonTable } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useDeletePhoneNumber, usePhoneNumbers, useUpdatePhoneNumber } from "@/lib/api/hooks/voice"

const PAGE_SIZE = 25

function TypeBadge({ type }: { type: string }) {
  const labels: Record<string, string> = {
    local: "Local",
    toll_free: "Toll-Free",
    international: "International",
  }
  return <Badge variant="secondary">{labels[type] ?? type}</Badge>
}

export function PhoneNumberTable() {
  const [page, setPage] = useState(1)
  const { data, isLoading, isError } = usePhoneNumbers(page, PAGE_SIZE)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [editLabel, setEditLabel] = useState("")
  const [editCallerId, setEditCallerId] = useState("")
  const [deleteTarget, setDeleteTarget] = useState<{ id: string; number: string } | null>(null)

  const updateMutation = useUpdatePhoneNumber(editingId ?? "")
  const deleteMutation = useDeletePhoneNumber()

  if (isLoading) return <SkeletonTable rows={6} />

  if (isError || !data) {
    return (
      <EmptyState
        icon={AlertCircle}
        title="Unable to load phone numbers"
        description="Something went wrong while fetching your phone numbers. Please try refreshing the page."
        action={
          <Button variant="outline" size="sm" onClick={() => window.location.reload()}>
            Refresh page
          </Button>
        }
      />
    )
  }

  const totalPages = Math.max(1, Math.ceil(data.total / PAGE_SIZE))

  function startEdit(id: string, label: string | null, callerIdName: string | null) {
    setEditingId(id)
    setEditLabel(label ?? "")
    setEditCallerId(callerIdName ?? "")
  }

  function cancelEdit() {
    setEditingId(null)
  }

  function saveEdit() {
    if (!editingId) return
    updateMutation.mutate({ label: editLabel || null, callerIdName: editCallerId || null }, { onSuccess: () => setEditingId(null) })
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Phone Numbers</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Number</TableHead>
              <TableHead>Label</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Caller ID</TableHead>
              <TableHead>Status</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.items.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="p-0">
                  <EmptyState
                    icon={Phone}
                    title="No phone numbers yet"
                    description="Add your first phone number to start routing calls to your extensions."
                    className="border-0 rounded-none"
                  />
                </TableCell>
              </TableRow>
            ) : (
              data.items.map((pn) => (
                <TableRow key={pn.id}>
                  <TableCell className="font-mono">{pn.number}</TableCell>
                  <TableCell>
                    {editingId === pn.id ? (
                      <Input value={editLabel} onChange={(e) => setEditLabel(e.target.value)} placeholder="Label" className="h-8 w-32" />
                    ) : (
                      (pn.label ?? <span className="text-muted-foreground">--</span>)
                    )}
                  </TableCell>
                  <TableCell>
                    <TypeBadge type={pn.numberType} />
                  </TableCell>
                  <TableCell>
                    {editingId === pn.id ? (
                      <Input value={editCallerId} onChange={(e) => setEditCallerId(e.target.value)} placeholder="Caller ID name" className="h-8 w-36" />
                    ) : (
                      (pn.callerIdName ?? <span className="text-muted-foreground">--</span>)
                    )}
                  </TableCell>
                  <TableCell>
                    <Badge variant={pn.isActive ? "default" : "outline"}>{pn.isActive ? "Active" : "Inactive"}</Badge>
                  </TableCell>
                  <TableCell className="text-right">
                    {editingId === pn.id ? (
                      <div className="flex justify-end gap-2">
                        <Button size="sm" onClick={saveEdit} disabled={updateMutation.isPending}>
                          Save
                        </Button>
                        <Button size="sm" variant="outline" onClick={cancelEdit}>
                          Cancel
                        </Button>
                      </div>
                    ) : (
                      <div className="flex justify-end gap-2">
                        <Button size="sm" variant="outline" onClick={() => startEdit(pn.id, pn.label, pn.callerIdName)}>
                          Edit
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          className="text-destructive hover:bg-destructive hover:text-destructive-foreground"
                          onClick={() => setDeleteTarget({ id: pn.id, number: pn.number })}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    )}
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
              Delete Phone Number
            </DialogTitle>
            <DialogDescription>
              Are you sure you want to delete <span className="font-mono font-medium">{deleteTarget?.number}</span>? This action cannot be undone.
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
