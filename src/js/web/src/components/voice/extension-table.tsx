import { Link } from "@tanstack/react-router"
import { useQueryClient } from "@tanstack/react-query"
import { AlertTriangle, Download, Loader2, Phone, Settings, Trash2 } from "lucide-react"
import { useCallback, useMemo, useState } from "react"
import {
  AlertDialog,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Badge } from "@/components/ui/badge"
import { BulkActionBar, createBulkDeleteAction, createExportAction } from "@/components/ui/bulk-action-bar"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { SkeletonTable } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useTableSelection } from "@/hooks/use-table-selection"
import { type Extension, useDeleteExtension, useExtensions } from "@/lib/api/hooks/voice"
import { exportToCsv, type CsvHeader } from "@/lib/csv-export"
import { client } from "@/lib/generated/api/client.gen"

const PAGE_SIZE = 25

const csvHeaders: CsvHeader<Extension>[] = [
  { label: "Extension", accessor: (e) => e.extensionNumber },
  { label: "Display Name", accessor: (e) => e.displayName },
  { label: "Phone Number Assigned", accessor: (e) => (e.phoneNumberId ? "Yes" : "No") },
  { label: "Active", accessor: (e) => (e.isActive ? "Yes" : "No") },
]

const getId = (e: Extension) => e.id

async function apiFetch<T>(url: string, options?: RequestInit): Promise<T> {
  const config = client.getConfig()
  const baseUrl = config.baseUrl ?? ""
  const token = typeof window !== "undefined" ? window.localStorage.getItem("access_token") : null
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  }
  const response = await fetch(`${baseUrl}${url}`, {
    credentials: "include",
    ...options,
    headers: { ...headers, ...(options?.headers as Record<string, string>) },
  })
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new Error(body.detail ?? `Request failed (${response.status})`)
  }
  if (response.status === 204) return undefined as unknown as T
  return response.json()
}

export function ExtensionTable() {
  const [page, setPage] = useState(1)
  const { data, isLoading, isError } = useExtensions(page, PAGE_SIZE)
  const [deleteTarget, setDeleteTarget] = useState<{ id: string; displayName: string; extensionNumber: string } | null>(null)
  const deleteMutation = useDeleteExtension()
  const queryClient = useQueryClient()

  const items: Extension[] = useMemo(() => data?.items ?? [], [data])
  const selection = useTableSelection(items, getId)

  const handleSelectAllToggle = useCallback(() => {
    if (selection.allSelected) {
      selection.deselectAll()
    } else {
      selection.selectAll()
    }
  }, [selection])

  const handleExportAll = useCallback(() => {
    if (!items.length) return
    exportToCsv("extensions", csvHeaders, items)
  }, [items])

  const bulkActions = useMemo(() => [
    createBulkDeleteAction(
      async (id) => {
        await apiFetch<void>(`/api/voice/extensions/${id}`, { method: "DELETE" })
      },
      () => queryClient.invalidateQueries({ queryKey: ["voice", "extensions"] }),
    ),
    createExportAction<Extension>(
      "extensions-selected",
      csvHeaders,
      (ids) => items.filter((e) => ids.includes(e.id)),
    ),
  ], [items, queryClient])

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
    <>
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Extensions ({data.total})</CardTitle>
            <Button variant="outline" size="sm" onClick={handleExportAll} disabled={items.length === 0}>
              <Download className="mr-1 h-3.5 w-3.5" />
              Export All
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-10">
                  <Checkbox
                    checked={selection.allSelected}
                    indeterminate={selection.someSelected}
                    onChange={handleSelectAllToggle}
                    aria-label="Select all extensions"
                  />
                </TableHead>
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
                  <TableCell colSpan={6} className="h-24 text-center text-muted-foreground">
                    <div className="flex flex-col items-center gap-2">
                      <Phone className="h-6 w-6 text-muted-foreground/60" />
                      No extensions found.
                    </div>
                  </TableCell>
                </TableRow>
              ) : (
                data.items.map((ext, idx) => (
                  <TableRow
                    key={ext.id}
                    data-state={selection.isSelected(ext.id) ? "selected" : undefined}
                    className={`hover:bg-muted/50 ${idx % 2 === 0 ? "bg-muted/20" : ""} ${selection.isSelected(ext.id) ? "bg-primary/10" : ""}`}
                  >
                    <TableCell>
                      <Checkbox
                        checked={selection.isSelected(ext.id)}
                        onChange={() => selection.toggle(ext.id)}
                        aria-label={`Select extension ${ext.extensionNumber}`}
                      />
                    </TableCell>
                    <TableCell className="font-mono">{ext.extensionNumber}</TableCell>
                    <TableCell>{ext.displayName}</TableCell>
                    <TableCell>{ext.phoneNumberId ? <Badge variant="secondary">Assigned</Badge> : <span className="text-muted-foreground">--</span>}</TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1.5">
                        <span className={`inline-block h-2 w-2 rounded-full ${ext.isActive ? "bg-green-500" : "bg-gray-400"}`} />
                        <Badge variant={ext.isActive ? "default" : "outline"}>{ext.isActive ? "Active" : "Inactive"}</Badge>
                      </div>
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-2">
                        <Button asChild variant="outline" size="sm">
                          <Link to="/voice/extensions/$extensionId" params={{ extensionId: ext.id }}>
                            <Settings className="mr-1 h-3.5 w-3.5" />
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
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">
              Showing {items.length} of {data.total} extension{data.total === 1 ? "" : "s"}
            </p>
            {totalPages > 1 && (
              <div className="flex items-center gap-3">
                <span className="text-sm text-muted-foreground">
                  Page {page} of {totalPages}
                </span>
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
          </div>
        </CardContent>

        <AlertDialog open={deleteTarget !== null} onOpenChange={(open) => !open && setDeleteTarget(null)}>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle className="flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-destructive" />
                Delete Extension
              </AlertDialogTitle>
              <AlertDialogDescription>
                Are you sure you want to delete extension{" "}
                <span className="font-medium">{deleteTarget?.displayName}</span>{" "}
                (Ext. <span className="font-mono">{deleteTarget?.extensionNumber}</span>)? This action cannot be undone.
                All associated forwarding rules, voicemail, and DND settings will be permanently removed.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
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
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </Card>

      <BulkActionBar
        selectedCount={selection.selectedCount}
        selectedIds={[...selection.selectedIds]}
        onClearSelection={selection.deselectAll}
        actions={bulkActions}
      />
    </>
  )
}
