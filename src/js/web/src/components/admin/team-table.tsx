import { Link } from "@tanstack/react-router"
import { Search } from "lucide-react"
import { useState } from "react"
import { TeamRowActions } from "@/components/admin/team-row-actions"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { SkeletonTable } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useAdminTeams } from "@/lib/api/hooks/admin"

const PAGE_SIZE = 25

export function TeamTable() {
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState("")
  const { data, isLoading, isError } = useAdminTeams(page, PAGE_SIZE)

  if (isLoading) {
    return <SkeletonTable rows={6} />
  }

  if (isError || !data) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Teams</CardTitle>
        </CardHeader>
        <CardContent className="text-muted-foreground">We could not load teams.</CardContent>
      </Card>
    )
  }

  const totalPages = Math.max(1, Math.ceil(data.total / PAGE_SIZE))
  const lowerSearch = search.toLowerCase()
  const filtered = search
    ? data.items.filter((t) => t.name.toLowerCase().includes(lowerSearch) || t.slug.toLowerCase().includes(lowerSearch))
    : data.items

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0">
        <CardTitle>Teams</CardTitle>
        <div className="relative w-64">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input placeholder="Filter teams..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-9" />
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Slug</TableHead>
              <TableHead>Members</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Created</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filtered.length === 0 && (
              <TableRow>
                <TableCell colSpan={6} className="text-center text-muted-foreground">
                  {search ? "No teams match your filter." : "No teams found."}
                </TableCell>
              </TableRow>
            )}
            {filtered.map((team) => (
              <TableRow key={team.id}>
                <TableCell className="font-medium">
                  <Link to="/admin/teams/$teamId" params={{ teamId: team.id }} className="hover:underline">
                    {team.name}
                  </Link>
                </TableCell>
                <TableCell className="text-muted-foreground">{team.slug}</TableCell>
                <TableCell>{team.memberCount ?? 0}</TableCell>
                <TableCell>
                  <Badge variant={team.isActive ? "default" : "secondary"}>{team.isActive ? "Active" : "Inactive"}</Badge>
                </TableCell>
                <TableCell className="text-muted-foreground">
                  {new Date(team.createdAt).toLocaleDateString()}
                </TableCell>
                <TableCell className="text-right">
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
