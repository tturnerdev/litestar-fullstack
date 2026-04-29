import { useMemo, useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { ExportButton } from "@/components/ui/export-button"
import { Input } from "@/components/ui/input"
import { SkeletonTable } from "@/components/ui/skeleton"
import { type SortDirection, SortableHeader, nextSortDirection } from "@/components/ui/sortable-header"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { UserRowActions } from "@/components/admin/user-row-actions"
import { useAdminUsers } from "@/lib/api/hooks/admin"
import type { AdminUserSummary } from "@/lib/generated/api"

const USER_EXPORT_COLUMNS = [
  { key: "name", header: "Name" },
  { key: "email", header: "Email" },
  { key: "isActive", header: "Active" },
  { key: "isSuperuser", header: "Superuser" },
  { key: "isVerified", header: "Verified" },
  { key: "loginCount", header: "Login Count" },
  { key: "createdAt", header: "Created At" },
]

const PAGE_SIZE = 25

function compareValues(a: unknown, b: unknown, direction: SortDirection): number {
  const dir = direction === "desc" ? -1 : 1
  if (a == null && b == null) return 0
  if (a == null) return 1
  if (b == null) return -1
  if (typeof a === "string" && typeof b === "string") return dir * a.localeCompare(b)
  if (a < b) return -1 * dir
  if (a > b) return 1 * dir
  return 0
}

export function UserTable() {
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState("")
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDirection, setSortDirection] = useState<SortDirection>(null)
  const { data, isLoading, isError } = useAdminUsers(page, PAGE_SIZE, search || undefined)

  const sortedItems = useMemo(() => {
    if (!data?.items || !sortKey || !sortDirection) return data?.items ?? []
    return [...data.items].sort((a, b) => {
      const aVal = a[sortKey as keyof AdminUserSummary]
      const bVal = b[sortKey as keyof AdminUserSummary]
      return compareValues(aVal, bVal, sortDirection)
    })
  }, [data?.items, sortKey, sortDirection])

  const handleSort = (key: string) => {
    const next = nextSortDirection(sortKey, sortDirection, key)
    setSortKey(next.sort)
    setSortDirection(next.direction)
  }

  if (isLoading) {
    return <SkeletonTable rows={6} />
  }

  if (isError || !data) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Users</CardTitle>
        </CardHeader>
        <CardContent className="text-muted-foreground">We could not load users.</CardContent>
      </Card>
    )
  }

  const totalPages = Math.max(1, Math.ceil(data.total / PAGE_SIZE))

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle>Users</CardTitle>
        <div className="flex items-center gap-3">
        <div className="w-64">
          <Input
            placeholder="Search users..."
            value={search}
            onChange={(e) => {
              setSearch(e.target.value)
              setPage(1)
            }}
          />
        </div>
        <ExportButton data={(data?.items ?? []) as Record<string, unknown>[]} filename="users" columns={USER_EXPORT_COLUMNS} />
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <Table>
          <TableHeader>
            <TableRow>
              <SortableHeader label="Name" sortKey="name" currentSort={sortKey} currentDirection={sortDirection} onSort={handleSort} />
              <SortableHeader label="Email" sortKey="email" currentSort={sortKey} currentDirection={sortDirection} onSort={handleSort} />
              <TableHead>Status</TableHead>
              <TableHead>Role</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {sortedItems.length === 0 && (
              <TableRow>
                <TableCell colSpan={5} className="text-center text-muted-foreground">
                  No users found.
                </TableCell>
              </TableRow>
            )}
            {sortedItems.map((user) => (
              <TableRow key={user.id}>
                <TableCell className="font-medium">{user.name ?? user.email}</TableCell>
                <TableCell className="text-muted-foreground">{user.email}</TableCell>
                <TableCell>
                  <Badge variant={user.isActive ? "default" : "secondary"}>
                    {user.isActive ? "Active" : "Inactive"}
                  </Badge>
                </TableCell>
                <TableCell>
                  {user.isSuperuser ? (
                    <Badge variant="destructive">Superuser</Badge>
                  ) : (
                    <span className="text-muted-foreground">Member</span>
                  )}
                </TableCell>
                <TableCell className="text-right">
                  <UserRowActions user={user} />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        <div className="flex items-center justify-between">
          <p className="text-xs text-muted-foreground">
            Showing {data.items.length} of {data.total} users &middot; Page {page} of {totalPages}
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
  )
}
