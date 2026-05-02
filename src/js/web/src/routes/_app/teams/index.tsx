import { createFileRoute, Link, useNavigate } from "@tanstack/react-router"
import { useCallback, useEffect, useMemo, useState } from "react"
import {
  Check,
  Crown,
  Download,
  Home,
  Plus,
  Search,
  Shield,
  Users,
  X,
} from "lucide-react"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { Badge } from "@/components/ui/badge"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { BulkActionBar, createBulkDeleteAction, createExportAction } from "@/components/ui/bulk-action-bar"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonTable } from "@/components/ui/skeleton"
import { nextSortDirection, SortableHeader, type SortDirection } from "@/components/ui/sortable-header"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useAuthStore } from "@/lib/auth"
import { useTeams, useDeleteTeam } from "@/lib/api/hooks/teams"
import { exportToCsv, type CsvHeader } from "@/lib/csv-export"
import { useDebouncedValue } from "@/hooks/use-debounced-value"
import { useDocumentTitle } from "@/hooks/use-document-title"
import type { Team } from "@/lib/generated/api"

export const Route = createFileRoute("/_app/teams/")({
  component: TeamsPage,
})

// ── Helpers ──────────────────────────────────────────────────────────────

function getTeamInitials(name: string): string {
  return name
    .split(/\s+/)
    .map((word) => word[0])
    .join("")
    .toUpperCase()
    .slice(0, 2)
}

function getTeamColor(name: string): string {
  const colors = [
    "bg-blue-500/15 text-blue-600 dark:text-blue-400",
    "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400",
    "bg-violet-500/15 text-violet-600 dark:text-violet-400",
    "bg-amber-500/15 text-amber-600 dark:text-amber-400",
    "bg-rose-500/15 text-rose-600 dark:text-rose-400",
    "bg-cyan-500/15 text-cyan-600 dark:text-cyan-400",
    "bg-fuchsia-500/15 text-fuchsia-600 dark:text-fuchsia-400",
    "bg-orange-500/15 text-orange-600 dark:text-orange-400",
  ]
  const index = name.split("").reduce((acc, char) => acc + char.charCodeAt(0), 0) % colors.length
  return colors[index]
}

const csvHeaders: CsvHeader<Team>[] = [
  { label: "Name", accessor: (t) => t.name },
  { label: "Description", accessor: (t) => t.description ?? "" },
  { label: "Member Count", accessor: (t) => t.members?.length ?? 0 },
]

// ── Main page ────────────────────────────────────────────────────────────

function TeamsPage() {
  useDocumentTitle("Teams")
  const navigate = useNavigate()
  const { user, currentTeam, setCurrentTeam, setTeams } = useAuthStore()

  // Keyboard shortcut: "N" opens the create page
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "n" && !e.ctrlKey && !e.metaKey && !e.altKey) {
        const target = e.target as HTMLElement
        if (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable) return
        e.preventDefault()
        navigate({ to: "/teams/new" })
      }
    }
    document.addEventListener("keydown", handleKeyDown)
    return () => document.removeEventListener("keydown", handleKeyDown)
  }, [navigate])

  // Search state
  const [search, setSearch] = useState("")
  const debouncedSearch = useDebouncedValue(search)

  // Sort state
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<SortDirection>(null)

  // Selection state
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())

  // Query
  const { data, isLoading, isError, refetch } = useTeams({
    search: debouncedSearch || undefined,
    orderBy: sortKey ?? undefined,
    sortOrder: sortDir ?? undefined,
  })

  const deleteTeamMutation = useDeleteTeam()

  const items = data?.items ?? []

  // Client-side sort for member count (not available server-side)
  const sortedItems = useMemo(() => {
    if (sortKey === "member_count" && sortDir) {
      const sorted = [...items]
      sorted.sort((a, b) => {
        const aCount = a.members?.length ?? 0
        const bCount = b.members?.length ?? 0
        return sortDir === "asc" ? aCount - bCount : bCount - aCount
      })
      return sorted
    }
    return items
  }, [items, sortKey, sortDir])

  // Export all visible
  const handleExportAll = useCallback(() => {
    if (!sortedItems.length) return
    exportToCsv("teams", csvHeaders, sortedItems)
  }, [sortedItems])

  // Keep auth store in sync
  useEffect(() => {
    if (!isLoading && !isError && items.length > 0) {
      setTeams(items)
    }
  }, [isError, isLoading, items, setTeams])

  // Selection helpers
  const allVisibleIds = useMemo(() => sortedItems.map((t) => t.id), [sortedItems])
  const allSelected = sortedItems.length > 0 && sortedItems.every((t) => selectedIds.has(t.id))
  const someSelected = sortedItems.some((t) => selectedIds.has(t.id))

  const toggleAll = useCallback(() => {
    if (allSelected) {
      setSelectedIds(new Set())
    } else {
      setSelectedIds(new Set(allVisibleIds))
    }
  }, [allSelected, allVisibleIds])

  const toggleOne = useCallback((id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) {
        next.delete(id)
      } else {
        next.add(id)
      }
      return next
    })
  }, [])

  // Sort handler
  const handleSort = useCallback(
    (key: string) => {
      const next = nextSortDirection(sortKey, sortDir, key)
      setSortKey(next.sort)
      setSortDir(next.direction)
    },
    [sortKey, sortDir],
  )

  // Bulk actions
  const bulkActions = useMemo(
    () => [
      createBulkDeleteAction(
        (id) => deleteTeamMutation.mutateAsync(id),
        () => {
          setSelectedIds(new Set())
        },
      ),
      createExportAction<Team>(
        "teams-selected",
        csvHeaders,
        (ids) => sortedItems.filter((t) => ids.includes(t.id)),
      ),
    ],
    [sortedItems, deleteTeamMutation],
  )

  const hasData = sortedItems.length > 0
  const hasAnyTeams = (data?.items.length ?? 0) > 0

  const breadcrumbs = (
    <Breadcrumb>
      <BreadcrumbList>
        <BreadcrumbItem>
          <BreadcrumbLink asChild>
            <Link to="/">
              <Home className="h-3.5 w-3.5" />
            </Link>
          </BreadcrumbLink>
        </BreadcrumbItem>
        <BreadcrumbSeparator />
        <BreadcrumbItem>
          <BreadcrumbPage>Teams</BreadcrumbPage>
        </BreadcrumbItem>
      </BreadcrumbList>
    </Breadcrumb>
  )

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Workspace"
        title="Teams"
        description="Manage your teams and collaborate with members."
        breadcrumbs={breadcrumbs}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={handleExportAll} disabled={!sortedItems.length}>
              <Download className="mr-2 h-4 w-4" />
              Export
            </Button>
            <Button size="sm" asChild>
              <Link to="/teams/new">
                <Plus className="mr-2 h-4 w-4" /> New team
                <kbd className="ml-1.5 hidden rounded border border-border bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground sm:inline">N</kbd>
              </Link>
            </Button>
          </div>
        }
      />

      {/* Search */}
      <PageSection>
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative max-w-sm flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search teams by name..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9 pr-8"
            />
            {search && (
              <button
                type="button"
                onClick={() => setSearch("")}
                className="absolute right-2 top-1/2 -translate-y-1/2 rounded-sm p-0.5 text-muted-foreground hover:text-foreground"
              >
                <X className="h-3.5 w-3.5" />
                <span className="sr-only">Clear search</span>
              </button>
            )}
          </div>
        </div>
      </PageSection>

      {/* Content */}
      <PageSection delay={0.1}>
        {isLoading ? (
          <SkeletonTable rows={4} />
        ) : isError ? (
          <EmptyState
            icon={Users}
            title="Unable to load teams"
            description="Something went wrong while fetching your teams. Please try again."
            action={
              <Button variant="outline" size="sm" onClick={() => refetch()}>
                Try again
              </Button>
            }
          />
        ) : !hasAnyTeams && !search ? (
          <EmptyState
            icon={Users}
            title="Create your first team"
            description="Teams help you organize members and control access across the app. Get started by creating your first team."
            action={
              <Button size="sm" asChild>
                <Link to="/teams/new">
                  <Plus className="mr-2 h-4 w-4" /> Create team
                </Link>
              </Button>
            }
          />
        ) : !hasData ? (
          <EmptyState
            icon={Search}
            variant="no-results"
            title="No matching teams"
            description={`No teams match "${search}". Try a different search term.`}
            action={
              <Button
                variant="outline"
                size="sm"
                onClick={() => setSearch("")}
              >
                Clear search
              </Button>
            }
          />
        ) : (
          <div className="space-y-3">
            {/* Result count */}
            <div className="flex items-center justify-between">
              <p className="text-sm text-muted-foreground">
                {sortedItems.length} team{sortedItems.length === 1 ? "" : "s"}
                {data?.total != null && data.total !== sortedItems.length && ` of ${data.total} total`}
                {search && " (filtered)"}
              </p>
            </div>

            {/* Table */}
            <div className="overflow-x-auto rounded-md border border-border/60 bg-card/80">
              <Table aria-label="Teams">
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-10">
                      <Checkbox
                        checked={allSelected}
                        indeterminate={someSelected && !allSelected}
                        onChange={toggleAll}
                        aria-label="Select all teams"
                      />
                    </TableHead>
                    <SortableHeader
                      label="Team"
                      sortKey="name"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <SortableHeader
                      label="Members"
                      sortKey="member_count"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <TableHead className="hidden md:table-cell">Your Role</TableHead>
                    <TableHead className="hidden md:table-cell">Tags</TableHead>
                    <TableHead className="hidden md:table-cell">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {sortedItems.map((team) => (
                    <TeamRow
                      key={team.id}
                      team={team}
                      selected={selectedIds.has(team.id)}
                      onToggle={() => toggleOne(team.id)}
                      isActiveTeam={currentTeam?.id === team.id}
                      onSwitchTeam={() => setCurrentTeam(team)}
                      currentUserId={user?.id}
                    />
                  ))}
                </TableBody>
              </Table>
            </div>
          </div>
        )}
      </PageSection>

      {/* Bulk action bar */}
      <BulkActionBar
        selectedCount={selectedIds.size}
        selectedIds={Array.from(selectedIds)}
        onClearSelection={() => setSelectedIds(new Set())}
        actions={bulkActions}
      />
    </PageContainer>
  )
}

// ── Table row ────────────────────────────────────────────────────────────

function TeamRow({
  team,
  selected,
  onToggle,
  isActiveTeam,
  onSwitchTeam,
  currentUserId,
}: {
  team: Team
  selected: boolean
  onToggle: () => void
  isActiveTeam: boolean
  onSwitchTeam: () => void
  currentUserId?: string
}) {
  const members = team.members ?? []
  const memberCount = members.length
  const tags = team.tags ?? []
  const userMembership = members.find((m) => m.userId === currentUserId)
  const isOwner = userMembership?.isOwner
  const isAdmin = userMembership?.role === "ADMIN"

  return (
    <TableRow className="hover:bg-muted/50 transition-colors" data-state={selected ? "selected" : undefined}>
      <TableCell>
        <Checkbox
          checked={selected}
          onChange={(e) => {
            e.stopPropagation()
            onToggle()
          }}
          aria-label={`Select ${team.name}`}
        />
      </TableCell>
      <TableCell>
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={onSwitchTeam}
            className="group/avatar relative shrink-0"
            title={isActiveTeam ? "Current team" : "Click to switch to this team"}
          >
            <Avatar className={`h-9 w-9 transition-all ${getTeamColor(team.name)} ${!isActiveTeam && "group-hover/avatar:ring-2 group-hover/avatar:ring-primary/30"}`}>
              <AvatarFallback className={`text-xs font-semibold ${getTeamColor(team.name)}`}>
                {getTeamInitials(team.name)}
              </AvatarFallback>
            </Avatar>
            {isActiveTeam && (
              <div className="absolute -bottom-0.5 -right-0.5 flex h-4 w-4 items-center justify-center rounded-full bg-primary text-primary-foreground ring-2 ring-background">
                <Check className="h-2.5 w-2.5" />
              </div>
            )}
          </button>
          <Link
            to="/teams/$teamId"
            params={{ teamId: team.id }}
            className="group flex flex-col gap-0.5"
          >
            <span className="font-medium group-hover:underline">{team.name}</span>
            {team.description && (
              <span className="text-xs text-muted-foreground line-clamp-1">{team.description}</span>
            )}
          </Link>
        </div>
      </TableCell>
      <TableCell>
        <span className="flex items-center gap-1.5 text-sm">
          <Users className="h-3.5 w-3.5 text-muted-foreground" />
          {memberCount}
        </span>
      </TableCell>
      <TableCell className="hidden md:table-cell">
        {isOwner ? (
          <Badge className="gap-1 bg-amber-500/15 text-amber-700 hover:bg-amber-500/20 dark:text-amber-400">
            <Crown className="h-3 w-3" />
            Owner
          </Badge>
        ) : isAdmin ? (
          <Badge variant="outline" className="gap-1 border-blue-500/30 text-blue-600 dark:text-blue-400">
            <Shield className="h-3 w-3" />
            Admin
          </Badge>
        ) : userMembership ? (
          <Badge variant="outline" className="gap-1">
            Member
          </Badge>
        ) : (
          <span className="text-xs text-muted-foreground">--</span>
        )}
      </TableCell>
      <TableCell className="hidden md:table-cell">
        {tags.length > 0 ? (
          <div className="flex flex-wrap gap-1">
            {tags.slice(0, 2).map((tag) => (
              <Badge key={tag.id} variant="secondary" className="text-[10px] px-2 py-0.5">
                {tag.name}
              </Badge>
            ))}
            {tags.length > 2 && (
              <Badge variant="outline" className="text-[10px] px-2 py-0.5">
                +{tags.length - 2}
              </Badge>
            )}
          </div>
        ) : (
          <span className="text-xs text-muted-foreground">--</span>
        )}
      </TableCell>
      <TableCell className="hidden md:table-cell">
        {team.isActive === false ? (
          <Badge variant="destructive" className="text-[10px]">Inactive</Badge>
        ) : (
          <span className="flex items-center gap-1.5 text-xs text-emerald-600 dark:text-emerald-400">
            <span className="inline-block h-1.5 w-1.5 rounded-full bg-emerald-500" />
            Active
          </span>
        )}
      </TableCell>
    </TableRow>
  )
}
