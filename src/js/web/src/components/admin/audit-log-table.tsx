import { useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { SkeletonTable } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useAdminAuditLogs } from "@/lib/api/hooks/admin"
import type { AuditLogEntry } from "@/lib/generated/api"

const PAGE_SIZE = 50

const DOMAIN_OPTIONS = [
  { value: "", label: "All domains" },
  { value: "account", label: "Account" },
  { value: "admin", label: "Admin" },
  { value: "team", label: "Team" },
  { value: "device", label: "Device" },
  { value: "voice", label: "Voice" },
  { value: "fax", label: "Fax" },
  { value: "support", label: "Support" },
  { value: "location", label: "Location" },
  { value: "connection", label: "Connection" },
  { value: "organization", label: "Organization" },
] as const

function getActionBadgeVariant(action: string): "default" | "secondary" | "outline" | "destructive" {
  if (action.includes("delete") || action.includes("remove") || action.includes("revoke")) return "destructive"
  if (action.includes("create") || action.includes("register") || action.includes("add")) return "default"
  if (action.includes("update") || action.includes("change")) return "secondary"
  return "outline"
}

interface AuditDiffViewProps {
  details: Record<string, unknown> | null | undefined
}

function AuditDiffView({ details }: AuditDiffViewProps) {
  if (!details) {
    return <p className="text-sm text-muted-foreground">No details recorded.</p>
  }

  const before = details.before as Record<string, unknown> | null | undefined
  const after = details.after as Record<string, unknown> | null | undefined
  const metadata = details.metadata as Record<string, unknown> | null | undefined

  const hasChanges = before !== undefined || after !== undefined

  return (
    <div className="space-y-4">
      {hasChanges && (
        <div className="space-y-2">
          <h4 className="text-sm font-medium">Changes</h4>
          {before === null && after ? (
            <div className="rounded-md border bg-green-50 p-3 dark:bg-green-950/30">
              <p className="mb-2 text-xs font-medium text-green-700 dark:text-green-400">Created</p>
              <div className="space-y-1">
                {Object.entries(after).map(([key, value]) => (
                  <div key={key} className="flex items-start gap-2 text-sm">
                    <span className="font-mono text-xs text-muted-foreground">{key}:</span>
                    <span className="text-green-700 dark:text-green-400">{formatValue(value)}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : after === null && before ? (
            <div className="rounded-md border bg-red-50 p-3 dark:bg-red-950/30">
              <p className="mb-2 text-xs font-medium text-red-700 dark:text-red-400">Deleted</p>
              <div className="space-y-1">
                {Object.entries(before).map(([key, value]) => (
                  <div key={key} className="flex items-start gap-2 text-sm">
                    <span className="font-mono text-xs text-muted-foreground">{key}:</span>
                    <span className="text-red-700 dark:text-red-400 line-through">{formatValue(value)}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : before && after ? (
            <div className="space-y-1">
              {Object.keys({ ...before, ...after }).map((key) => {
                const oldVal = (before as Record<string, unknown>)[key]
                const newVal = (after as Record<string, unknown>)[key]
                return (
                  <div key={key} className="flex items-start gap-2 rounded-md border p-2 text-sm">
                    <span className="min-w-[120px] font-mono text-xs text-muted-foreground">{key}</span>
                    <span className="text-red-600 line-through dark:text-red-400">{formatValue(oldVal)}</span>
                    <span className="text-muted-foreground">-&gt;</span>
                    <span className="text-green-600 dark:text-green-400">{formatValue(newVal)}</span>
                  </div>
                )
              })}
            </div>
          ) : null}
        </div>
      )}

      {metadata && Object.keys(metadata).length > 0 && (
        <div className="space-y-2">
          <h4 className="text-sm font-medium">Metadata</h4>
          <div className="rounded-md border bg-muted/50 p-3">
            <div className="space-y-1">
              {Object.entries(metadata).map(([key, value]) => (
                <div key={key} className="flex items-start gap-2 text-sm">
                  <span className="font-mono text-xs text-muted-foreground">{key}:</span>
                  <span>{formatValue(value)}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {!hasChanges && !metadata && (
        <div className="rounded-md border bg-muted/50 p-3">
          <pre className="text-xs whitespace-pre-wrap">{JSON.stringify(details, null, 2)}</pre>
        </div>
      )}
    </div>
  )
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return "null"
  if (typeof value === "boolean") return value ? "true" : "false"
  if (typeof value === "object") return JSON.stringify(value)
  return String(value)
}

interface AuditDetailDialogProps {
  entry: AuditLogEntry | null
  open: boolean
  onOpenChange: (open: boolean) => void
}

function AuditDetailDialog({ entry, open, onOpenChange }: AuditDetailDialogProps) {
  if (!entry) return null

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[80vh] max-w-2xl overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            Audit Entry
            <Badge variant={getActionBadgeVariant(entry.action)}>{entry.action}</Badge>
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <p className="text-xs text-muted-foreground">Actor</p>
              <p>{entry.actorEmail ?? entry.actorId ?? "System"}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Time</p>
              <p>{new Date(entry.createdAt).toLocaleString()}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Target</p>
              <p>
                {entry.targetType && <Badge variant="outline" className="mr-1">{entry.targetType}</Badge>}
                {entry.targetLabel ?? entry.targetId ?? "-"}
              </p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">IP Address</p>
              <p className="font-mono text-xs">{entry.ipAddress ?? "-"}</p>
            </div>
          </div>

          <div className="border-t pt-4">
            <AuditDiffView details={entry.details as Record<string, unknown> | null | undefined} />
          </div>

          {entry.userAgent && (
            <div className="border-t pt-4">
              <p className="text-xs text-muted-foreground">User Agent</p>
              <p className="text-xs break-all">{entry.userAgent}</p>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
}

export function AuditLogTable() {
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState("")
  const [action, setAction] = useState("")
  const [domainFilter, setDomainFilter] = useState("")
  const [actorId, setActorId] = useState("")
  const [targetType, setTargetType] = useState("")
  const [startDate, setStartDate] = useState("")
  const [endDate, setEndDate] = useState("")
  const [selectedEntry, setSelectedEntry] = useState<AuditLogEntry | null>(null)
  const [detailOpen, setDetailOpen] = useState(false)

  const { data, isLoading, isError } = useAdminAuditLogs({
    page,
    pageSize: PAGE_SIZE,
    search: search || undefined,
    action: action || undefined,
    domain: domainFilter || undefined,
    actorId: actorId || undefined,
    targetType: targetType || undefined,
    startDate: startDate || undefined,
    endDate: endDate || undefined,
  })

  const handleRowClick = (entry: AuditLogEntry) => {
    setSelectedEntry(entry)
    setDetailOpen(true)
  }

  if (isLoading) {
    return <SkeletonTable rows={6} />
  }

  if (isError || !data) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Audit log</CardTitle>
        </CardHeader>
        <CardContent className="text-muted-foreground">We could not load audit logs.</CardContent>
      </Card>
    )
  }

  const totalPages = Math.max(1, Math.ceil(data.total / PAGE_SIZE))

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>Audit log</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-3 md:grid-cols-3 lg:grid-cols-6">
            <Input placeholder="Search" value={search} onChange={(event) => { setSearch(event.target.value); setPage(1) }} />
            <Select value={domainFilter || "_all"} onValueChange={(value) => { setDomainFilter(value === "_all" ? "" : value); setPage(1) }}>
              <SelectTrigger>
                <SelectValue placeholder="All domains" />
              </SelectTrigger>
              <SelectContent>
                {DOMAIN_OPTIONS.map((opt) => (
                  <SelectItem key={opt.value || "_all"} value={opt.value || "_all"}>
                    {opt.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Input placeholder="Action" value={action} onChange={(event) => { setAction(event.target.value); setPage(1) }} />
            <Input placeholder="Target type" value={targetType} onChange={(event) => { setTargetType(event.target.value); setPage(1) }} />
            <Input type="date" placeholder="Start date" value={startDate} onChange={(event) => { setStartDate(event.target.value); setPage(1) }} />
            <Input type="date" placeholder="End date" value={endDate} onChange={(event) => { setEndDate(event.target.value); setPage(1) }} />
          </div>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Action</TableHead>
                <TableHead>Actor</TableHead>
                <TableHead>Target</TableHead>
                <TableHead>Details</TableHead>
                <TableHead>Created</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.items.length === 0 && (
                <TableRow>
                  <TableCell colSpan={5} className="text-center text-muted-foreground">
                    No audit entries found.
                  </TableCell>
                </TableRow>
              )}
              {data.items.map((entry) => {
                const details = entry.details as Record<string, unknown> | null | undefined
                const hasChanges = details && (details.before !== undefined || details.after !== undefined)
                const hasMeta = details?.metadata !== undefined

                return (
                  <TableRow
                    key={entry.id}
                    className="cursor-pointer hover:bg-muted/50"
                    onClick={() => handleRowClick(entry)}
                  >
                    <TableCell>
                      <Badge variant={getActionBadgeVariant(entry.action)} className="text-xs">
                        {entry.action}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground">{entry.actorEmail ?? entry.actorId ?? "System"}</TableCell>
                    <TableCell className="text-muted-foreground">
                      {entry.targetType && (
                        <Badge variant="outline" className="mr-1 text-xs">
                          {entry.targetType}
                        </Badge>
                      )}
                      {entry.targetLabel ?? entry.targetId ?? "-"}
                    </TableCell>
                    <TableCell>
                      {hasChanges && (
                        <Badge variant="secondary" className="text-xs">
                          diff
                        </Badge>
                      )}
                      {hasMeta && (
                        <Badge variant="outline" className="ml-1 text-xs">
                          meta
                        </Badge>
                      )}
                      {!hasChanges && !hasMeta && details && (
                        <Badge variant="outline" className="text-xs">
                          data
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-muted-foreground">{new Date(entry.createdAt).toLocaleString()}</TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
          <div className="flex items-center justify-between">
            <p className="text-xs text-muted-foreground">
              {data.total} entries {" "} | {" "} Page {page} of {totalPages}
            </p>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page <= 1}>
                Previous
              </Button>
              <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page >= totalPages}>
                Next
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
      <AuditDetailDialog entry={selectedEntry} open={detailOpen} onOpenChange={setDetailOpen} />
    </>
  )
}
