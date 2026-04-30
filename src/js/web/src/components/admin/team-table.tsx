import { Link, useNavigate } from "@tanstack/react-router"
import { Search, Users, Users2 } from "lucide-react"
import { useMemo, useState } from "react"
import { TeamRowActions } from "@/components/admin/team-row-actions"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { EmptyState } from "@/components/ui/empty-state"
import { ErrorState } from "@/components/ui/error-state"
import { ExportButton } from "@/components/ui/export-button"
import { Input } from "@/components/ui/input"
import { SkeletonTable } from "@/components/ui/skeleton"
import { type SortDirection, SortableHeader, nextSortDirection } from "@/components/ui/sortable-header"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import type { AdminTeamSummary } from "@/lib/generated/api"
import { useAdminTeams } from "@/lib/api/hooks/admin"

function timeAgo(dateString: string): string {
  const date = new Date(dateString)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffSeconds = Math.floor(diffMs / 1000)
  const diffMinutes = Math.floor(diffSeconds / 60)
  const diffHours = Math.floor(diffMinutes / 60)
  const diffDays = Math.floor(diffHours / 24)
  const diffMonths = Math.floor(diffDays / 30)
  const diffYears = Math.floor(diffDays / 365)

  if (diffSeconds < 60) return "just now"
  if (diffMinutes < 60) return `${diffMinutes}m ago`
  if (diffHours < 24) return `${diffHours}h ago`
  if (diffDays < 30) return `${diffDays}d ago`
  if (diffMonths < 12) return `${diffMonths}mo ago`
  return `${diffYears}y ago`
}

const TEAM_EXPORT_COLUMNS = [
  { key: "name", header: "Name" },
  { key: "slug", header: "Slug" },
  { key: "memberCount", header: "Members" },
  { key: "isActive", header: "Active" },
  { key: "createdAt", header: "Created At" },
]

const PAGE_SIZE = 25

function compareValues(a: unknown, b: unknown, direction: SortDirection): number {
  const dir = direction === "desc" ? -1 : 1
  if (a == null && b == null) return 0
  if (a == null) return 1
  if (b == null) return -1
  if (typeof a === "string" && typeof b === "string") return dir * a.localeCompare(b)
  if (typeof a === "number" && typeof b === "number") return dir * (a - b)
  if (a < b) return -1 * dir
  if (a > b) return 1 * dir
  return 0
}

export function TeamTable() {
  const navigate = useNavigate()
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState("")
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDirection, setSortDirection] = useState<SortDirection>(null)
  const { data, isLoading, isError, refetch } = useAdminTeams({ page, pageSize: PAGE_SIZE })

  if (isLoading) {
    return <SkeletonTable rows={6} />
  }

  if (isError || !data) {
    return (
      <Card>
        <CardContent>
          <ErrorState title="Unable to load teams" description="Something went wrong while fetching team data." onRetry={() => refetch()} />
        </CardContent>
      </Card>
    )
  }

  const totalPages = Math.max(1, Math.ceil(data.total / PAGE_SIZE))
  const lowerSearch = search.toLowerCase()
  const filtered = search
    ? data.items.filter((t) => t.name.toLowerCase().includes(lowerSearch) || t.slug.toLowerCase().includes(lowerSearch))
    : data.items

  const sortedItems = useMemo(() => {
    if (!sortKey || !sortDirection) return filtered
    return [...filtered].sort((a, b) => {
      const aVal = a[sortKey as keyof AdminTeamSummary]
      const bVal = b[sortKey as keyof AdminTeamSummary]
      return compareValues(aVal, bVal, sortDirection)
    })
  }, [filtered, sortKey, sortDirection])

  const handleSort = (key: string) => {
    const next = nextSortDirection(sortKey, sortDirection, key)
    setSortKey(next.sort)
    setSortDirection(next.direction)
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0">
        <CardTitle>Teams{data.total > 0 ? ` (${data.total})` : ""}</CardTitle>
        <div className="flex items-center gap-3">
          <div className="relative w-64">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input placeholder="Filter teams..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-9" />
          </div>
          <ExportButton data={(data?.items ?? []) as Record<string, unknown>[]} filename="teams" columns={TEAM_EXPORT_COLUMNS} />
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <Table>
          <TableHeader>
            <TableRow>
              <SortableHeader label="Name" sortKey="name" currentSort={sortKey} currentDirection={sortDirection} onSort={handleSort} />
              <SortableHeader label="Slug" sortKey="slug" currentSort={sortKey} currentDirection={sortDirection} onSort={handleSort} />
              <SortableHeader label="Members" sortKey="memberCount" currentSort={sortKey} currentDirection={sortDirection} onSort={handleSort} />
              <TableHead>Status</TableHead>
              <TableHead>Created</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filtered.length === 0 && (
              <TableRow>
                <TableCell colSpan={6}>
                  <EmptyState icon={Users2} title={search ? "No teams match your filter" : "No teams found"} description="Try adjusting your search to find what you're looking for." variant="no-results" />
                </TableCell>
              </TableRow>
            )}
            {sortedItems.map((team, index) => (
              <TableRow
                key={team.id}
                className={`cursor-pointer hover:bg-muted/50 ${index % 2 === 1 ? "bg-muted/20" : ""}`}
                onClick={() => navigate({ to: "/admin/teams/$teamId", params: { teamId: team.id } })}
              >
                <TableCell className="font-medium">
                  <Link to="/admin/teams/$teamId" params={{ teamId: team.id }} className="hover:underline" onClick={(e) => e.stopPropagation()}>
                    {team.name}
                  </Link>
                </TableCell>
                <TableCell className="text-muted-foreground">{team.slug}</TableCell>
                <TableCell>
                  <span className="inline-flex items-center gap-1.5 text-sm">
                    <Users className="h-3.5 w-3.5 text-muted-foreground" />
                    {team.memberCount ?? 0}
                  </span>
                </TableCell>
                <TableCell>
                  <span className="inline-flex items-center gap-1.5">
                    <span className={`h-2 w-2 rounded-full ${team.isActive ? "bg-green-500" : "bg-gray-400"}`} />
                    <Badge variant={team.isActive ? "default" : "secondary"}>{team.isActive ? "Active" : "Inactive"}</Badge>
                  </span>
                </TableCell>
                <TableCell className="text-muted-foreground">
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <span>{timeAgo(team.createdAt)}</span>
                    </TooltipTrigger>
                    <TooltipContent>{new Date(team.createdAt).toLocaleString()}</TooltipContent>
                  </Tooltip>
                </TableCell>
                <TableCell className="text-right" onClick={(e) => e.stopPropagation()}>
                  <TeamRowActions team={team} />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        <div className="flex items-center justify-between">
          <p className="text-xs text-muted-foreground">
            {search ? `${filtered.length} of ${data.items.length} teams` : `Page ${page} of ${totalPages}`}
            {" · "}
            {data.total} total
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
