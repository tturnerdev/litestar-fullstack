import { createFileRoute, Link, useNavigate } from "@tanstack/react-router"
import { useCallback, useEffect, useMemo, useState } from "react"
import {
  AlertCircle,
  CheckCircle2,
  Download,
  Eye,
  Lock,
  MoreVertical,
  Pencil,
  Search,
  Shield,
  ShieldCheck,
  ShieldOff,
  Trash2,
  UserCheck,
  UserPlus,
  UserX,
  Users,
  X,
  XCircle,
} from "lucide-react"
import { toast } from "sonner"
import { useQueryClient } from "@tanstack/react-query"
import { AdminBreadcrumbs } from "@/components/admin/admin-breadcrumbs"
import { AdminNav } from "@/components/admin/admin-nav"
import { DeleteUserDialog } from "@/components/admin/delete-user-dialog"
import { EditUserDialog } from "@/components/admin/edit-user-dialog"
import { JoinTeamDialog } from "@/components/admin/join-team-dialog"
import { ManagePermissionsDialog } from "@/components/admin/manage-permissions-dialog"
import { ManageRolesDialog } from "@/components/admin/manage-roles-dialog"
import { ToggleUserStatusDialog } from "@/components/admin/toggle-user-status-dialog"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { Badge } from "@/components/ui/badge"
import { type BulkAction, BulkActionBar } from "@/components/ui/bulk-action-bar"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { EmptyState } from "@/components/ui/empty-state"
import { exportToCsv, type CsvHeader } from "@/lib/csv-export"
import { FilterDropdown, type FilterOption } from "@/components/ui/filter-dropdown"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { SkeletonTable } from "@/components/ui/skeleton"
import { nextSortDirection, SortableHeader, type SortDirection } from "@/components/ui/sortable-header"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { DataFreshness } from "@/components/ui/data-freshness"
import { useDebouncedValue } from "@/hooks/use-debounced-value"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"
import { useAdminUsers } from "@/lib/api/hooks/admin"
import { adminDeleteUser, adminUpdateUser } from "@/lib/generated/api"
import type { AdminUserSummary } from "@/lib/generated/api"

export const Route = createFileRoute("/_app/admin/users/")({
  component: AdminUsersPage,
})

// -- Constants ----------------------------------------------------------------

const PAGE_SIZES = [10, 25, 50, 100] as const
const DEFAULT_PAGE_SIZE = 25
const PAGE_SIZE_STORAGE_KEY = "admin-users-page-size"

function getStoredPageSize(): number {
  try {
    const stored = localStorage.getItem(PAGE_SIZE_STORAGE_KEY)
    if (stored) {
      const parsed = Number(stored)
      if ((PAGE_SIZES as readonly number[]).includes(parsed)) return parsed
    }
  } catch {
    // localStorage unavailable
  }
  return DEFAULT_PAGE_SIZE
}

const csvHeaders: CsvHeader<AdminUserSummary>[] = [
  { label: "Name", accessor: (u) => u.name ?? "" },
  { label: "Email", accessor: (u) => u.email },
  { label: "Username", accessor: (u) => u.username ?? "" },
  { label: "Active", accessor: (u) => (u.isActive ? "Yes" : "No") },
  { label: "Superuser", accessor: (u) => (u.isSuperuser ? "Yes" : "No") },
  { label: "Verified", accessor: (u) => (u.isVerified ? "Yes" : "No") },
  { label: "Login Count", accessor: (u) => u.loginCount ?? 0 },
  { label: "Created At", accessor: (u) => formatDateTime(u.createdAt) },
]

const roleOptions: FilterOption[] = [
  { value: "superuser", label: "Superuser" },
  { value: "member", label: "Member" },
]

const statusOptions: FilterOption[] = [
  { value: "active", label: "Active" },
  { value: "inactive", label: "Inactive" },
  { value: "verified", label: "Verified" },
  { value: "unverified", label: "Unverified" },
]

// -- Helpers ------------------------------------------------------------------

function getInitials(name: string | null | undefined, email: string): string {
  if (name) {
    const parts = name.trim().split(/\s+/)
    if (parts.length >= 2) {
      return `${parts[0][0]}${parts[1][0]}`.toUpperCase()
    }
    return name.slice(0, 2).toUpperCase()
  }
  return email.slice(0, 2).toUpperCase()
}

function ActiveStatusIndicator({ isActive }: { isActive: boolean | undefined }) {
  if (isActive) {
    return (
      <span className="flex items-center gap-1.5 text-xs text-emerald-700 dark:text-emerald-400">
        <CheckCircle2 className="h-3.5 w-3.5" />
        Active
      </span>
    )
  }
  return (
    <span className="flex items-center gap-1.5 text-xs text-red-600 dark:text-red-400">
      <XCircle className="h-3.5 w-3.5" />
      Inactive
    </span>
  )
}

function matchesRoleFilter(user: AdminUserSummary, filters: string[]): boolean {
  if (filters.length === 0) return true
  const isSuperuser = user.isSuperuser === true
  if (filters.includes("superuser") && isSuperuser) return true
  if (filters.includes("member") && !isSuperuser) return true
  return false
}

function matchesStatusFilter(user: AdminUserSummary, filters: string[]): boolean {
  if (filters.length === 0) return true
  for (const f of filters) {
    if (f === "active" && user.isActive === true) return true
    if (f === "inactive" && !user.isActive) return true
    if (f === "verified" && user.isVerified === true) return true
    if (f === "unverified" && !user.isVerified) return true
  }
  return false
}

// -- Main page ----------------------------------------------------------------

function AdminUsersPage() {
  useDocumentTitle("Admin — Users")
  const navigate = useNavigate()

  // Filter & search state
  const [search, setSearch] = useState("")
  const debouncedSearch = useDebouncedValue(search)
  const [roleFilter, setRoleFilter] = useState<string[]>([])
  const [statusFilter, setStatusFilter] = useState<string[]>([])
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(getStoredPageSize)

  // Reset page when debounced search changes
  useEffect(() => {
    setPage(1)
  }, [debouncedSearch])

  // Persist page size preference
  const handlePageSizeChange = useCallback((value: string) => {
    const size = Number(value)
    setPageSize(size)
    setPage(1)
    try {
      localStorage.setItem(PAGE_SIZE_STORAGE_KEY, value)
    } catch {
      // localStorage unavailable
    }
  }, [])

  // Sort state
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<SortDirection>(null)

  // Selection state
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())

  // Queries & mutations
  const queryClient = useQueryClient()
  const { data, isLoading, isError, refetch, dataUpdatedAt, isRefetching } = useAdminUsers({
    page,
    pageSize,
    search: debouncedSearch || undefined,
    orderBy: sortKey ?? undefined,
    sortOrder: sortDir ?? undefined,
  })
  // Apply client-side role & status filters
  const filteredItems = useMemo(() => {
    if (!data?.items) return []
    return data.items.filter((user) => {
      if (!matchesRoleFilter(user, roleFilter)) return false
      if (!matchesStatusFilter(user, statusFilter)) return false
      return true
    })
  }, [data?.items, roleFilter, statusFilter])

  // Export handler
  const handleExport = useCallback(() => {
    if (!filteredItems.length) return
    exportToCsv("admin-users", csvHeaders, filteredItems)
  }, [filteredItems])

  // Selection helpers
  const allVisibleIds = useMemo(() => filteredItems.map((u) => u.id), [filteredItems])
  const allSelected = filteredItems.length > 0 && filteredItems.every((u) => selectedIds.has(u.id))
  const someSelected = filteredItems.some((u) => selectedIds.has(u.id))

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
  const bulkActions = useMemo<BulkAction[]>(
    () => [
      {
        key: "activate",
        label: "Activate",
        icon: <ShieldCheck className="h-4 w-4" />,
        variant: "outline",
        confirm: {
          title: "Activate selected users?",
          description: "This will activate all selected users, allowing them to sign in and access the system.",
        },
        onExecute: async (ids) => {
          let succeeded = 0
          let failed = 0
          for (const id of ids) {
            try {
              await adminUpdateUser({ path: { user_id: id }, body: { isActive: true } })
              succeeded++
            } catch {
              failed++
            }
          }
          await queryClient.invalidateQueries({ queryKey: ["admin", "users"] })
          setSelectedIds(new Set())
          if (failed === 0) {
            toast.success(`Activated ${succeeded} user${succeeded !== 1 ? "s" : ""}`)
          } else {
            toast.warning(`${succeeded} activated, ${failed} failed`)
          }
        },
      },
      {
        key: "deactivate",
        label: "Deactivate",
        icon: <ShieldOff className="h-4 w-4" />,
        variant: "outline",
        confirm: {
          title: "Deactivate selected users?",
          description: "This will deactivate all selected users. They will no longer be able to sign in.",
        },
        onExecute: async (ids) => {
          let succeeded = 0
          let failed = 0
          for (const id of ids) {
            try {
              await adminUpdateUser({ path: { user_id: id }, body: { isActive: false } })
              succeeded++
            } catch {
              failed++
            }
          }
          await queryClient.invalidateQueries({ queryKey: ["admin", "users"] })
          setSelectedIds(new Set())
          if (failed === 0) {
            toast.success(`Deactivated ${succeeded} user${succeeded !== 1 ? "s" : ""}`)
          } else {
            toast.warning(`${succeeded} deactivated, ${failed} failed`)
          }
        },
      },
      {
        key: "delete",
        label: "Delete",
        icon: <Trash2 className="h-4 w-4" />,
        variant: "destructive",
        confirm: {
          title: "Delete selected users?",
          description: "This action cannot be undone. All selected users will be permanently deleted.",
        },
        onExecute: async (ids) => {
          let succeeded = 0
          let failed = 0
          for (const id of ids) {
            try {
              await adminDeleteUser({ path: { user_id: id } })
              succeeded++
            } catch {
              failed++
            }
          }
          await queryClient.invalidateQueries({ queryKey: ["admin", "users"] })
          setSelectedIds(new Set())
          if (failed === 0) {
            toast.success(`Deleted ${succeeded} user${succeeded !== 1 ? "s" : ""}`)
          } else {
            toast.warning(`${succeeded} deleted, ${failed} failed`)
          }
        },
      },
    ],
    [queryClient],
  )

  // Row click handler
  const handleRowClick = useCallback(
    (userId: string) => {
      navigate({ to: "/admin/users/$userId", params: { userId } })
    },
    [navigate],
  )

  // Computed
  const activeFilterCount = roleFilter.length + statusFilter.length
  const hasData = filteredItems.length > 0
  const hasAnyUsers = (data?.items.length ?? 0) > 0
  const totalPages = Math.max(1, Math.ceil((data?.total ?? 0) / pageSize))

  // Keyboard shortcuts: ArrowLeft/ArrowRight for pagination
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement
      if (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable) return
      if (e.key === "ArrowLeft" && page > 1) {
        e.preventDefault()
        setPage((p) => Math.max(1, p - 1))
      }
      if (e.key === "ArrowRight" && page < totalPages) {
        e.preventDefault()
        setPage((p) => Math.min(totalPages, p + 1))
      }
    }
    document.addEventListener("keydown", handleKeyDown)
    return () => document.removeEventListener("keydown", handleKeyDown)
  }, [page, totalPages])

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Administration"
        title="Users"
        description="View and manage all users in the system."
        breadcrumbs={<AdminBreadcrumbs />}
        actions={
          <Button variant="outline" size="sm" onClick={handleExport} disabled={!filteredItems.length}>
            <Download className="mr-2 h-4 w-4" />
            Export
          </Button>
        }
      />
      <AdminNav />

      {/* Search & filters */}
      <PageSection>
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative max-w-sm flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search by name, email, or username..."
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
          <FilterDropdown
            label="Role"
            options={roleOptions}
            selected={roleFilter}
            onChange={setRoleFilter}
          />
          <FilterDropdown
            label="Status"
            options={statusOptions}
            selected={statusFilter}
            onChange={setStatusFilter}
          />
          {activeFilterCount > 0 && (
            <Button
              variant="ghost"
              size="sm"
              className="text-xs text-muted-foreground"
              onClick={() => {
                setRoleFilter([])
                setStatusFilter([])
              }}
            >
              Clear all filters
            </Button>
          )}
          <div className="ml-auto">
            <DataFreshness
              dataUpdatedAt={dataUpdatedAt}
              onRefresh={() => refetch()}
              isRefreshing={isRefetching}
            />
          </div>
        </div>
      </PageSection>

      {/* Content */}
      <PageSection delay={0.1}>
        {isLoading ? (
          <SkeletonTable rows={6} />
        ) : isError ? (
          <EmptyState
            icon={AlertCircle}
            title="Unable to load users"
            description="Something went wrong while fetching user data. Please try refreshing the page."
            action={
              <Button variant="outline" size="sm" onClick={() => refetch()}>
                Refresh
              </Button>
            }
          />
        ) : !hasAnyUsers && !search ? (
          <EmptyState
            icon={Users}
            title="No users yet"
            description="Users will appear here once they register or are added to the system."
          />
        ) : !hasData ? (
          <EmptyState
            icon={Users}
            variant="no-results"
            title="No results found"
            description="No users match your current filters. Try adjusting your search or filters."
            action={
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setSearch("")
                  setRoleFilter([])
                  setStatusFilter([])
                }}
              >
                Clear all filters
              </Button>
            }
          />
        ) : (
          <div className="space-y-3">
            {/* Result count & pagination info */}
            <div className="flex items-center justify-between">
              <p className="text-sm text-muted-foreground">
                {filteredItems.length} user{filteredItems.length === 1 ? "" : "s"}
                {(roleFilter.length > 0 || statusFilter.length > 0) && " (filtered)"}
                {data && data.total > pageSize && (
                  <span>
                    {" "}
                    &middot; Page {page} of {totalPages}
                  </span>
                )}
              </p>
            </div>

            {/* Table */}
            <div className="overflow-x-auto rounded-md border border-border/60 bg-card/80">
              <Table aria-label="Users">
                <TableHeader className="sticky top-0 z-10 bg-background">
                  <TableRow>
                    <TableHead className="w-10">
                      <Checkbox
                        checked={allSelected}
                        indeterminate={someSelected && !allSelected}
                        onChange={toggleAll}
                        aria-label="Select all users"
                      />
                    </TableHead>
                    <SortableHeader
                      label="User"
                      sortKey="name"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <SortableHeader
                      label="Email"
                      sortKey="email"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                      className="hidden sm:table-cell"
                    />
                    <SortableHeader
                      label="Role"
                      sortKey="is_superuser"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                      className="hidden sm:table-cell"
                    />
                    <SortableHeader
                      label="Status"
                      sortKey="is_active"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <SortableHeader
                      label="Logins"
                      sortKey="login_count"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                      className="hidden md:table-cell"
                    />
                    <SortableHeader
                      label="Created"
                      sortKey="created_at"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                      className="hidden md:table-cell"
                    />
                    <TableHead className="w-16 text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredItems.map((user, index) => (
                    <UserRow
                      key={user.id}
                      user={user}
                      index={index}
                      selected={selectedIds.has(user.id)}
                      onToggle={() => toggleOne(user.id)}
                      onRowClick={() => handleRowClick(user.id)}
                    />
                  ))}
                </TableBody>
              </Table>
            </div>

            {/* Pagination */}
            <div className="flex items-center justify-end gap-4">
              <div className="flex items-center gap-2">
                <span className="text-sm text-muted-foreground">Rows per page</span>
                <Select value={String(pageSize)} onValueChange={handlePageSizeChange}>
                  <SelectTrigger className="h-8 w-[70px]">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {PAGE_SIZES.map((size) => (
                      <SelectItem key={size} value={String(size)}>
                        {size}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              {totalPages > 1 && (
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      setPage((p) => Math.max(1, p - 1))
                      setSelectedIds(new Set())
                    }}
                    disabled={page <= 1}
                  >
                    Previous
                    <kbd className="ml-1.5 hidden rounded border border-border bg-muted px-1 py-0.5 text-[10px] font-medium text-muted-foreground lg:inline">&larr;</kbd>
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      setPage((p) => Math.min(totalPages, p + 1))
                      setSelectedIds(new Set())
                    }}
                    disabled={page >= totalPages}
                  >
                    Next
                    <kbd className="ml-1.5 hidden rounded border border-border bg-muted px-1 py-0.5 text-[10px] font-medium text-muted-foreground lg:inline">&rarr;</kbd>
                  </Button>
                </div>
              )}
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

// -- Table row ----------------------------------------------------------------

function UserRow({
  user,
  index,
  selected,
  onToggle,
  onRowClick,
}: {
  user: AdminUserSummary
  index: number
  selected: boolean
  onToggle: () => void
  onRowClick: () => void
}) {
  const [editOpen, setEditOpen] = useState(false)
  const [rolesOpen, setRolesOpen] = useState(false)
  const [joinTeamOpen, setJoinTeamOpen] = useState(false)
  const [permissionsOpen, setPermissionsOpen] = useState(false)
  const [statusOpen, setStatusOpen] = useState(false)
  const [deleteOpen, setDeleteOpen] = useState(false)

  return (
    <>
      <TableRow
        data-state={selected ? "selected" : undefined}
        className={`cursor-pointer hover:bg-muted/50 transition-colors ${index % 2 === 1 ? "bg-muted/20" : ""}`}
        onClick={(e) => {
          const target = e.target as HTMLElement
          if (target.closest("[role=checkbox]") || target.closest("[data-slot=dropdown]") || target.closest("button") || target.closest("a")) {
            return
          }
          onRowClick()
        }}
      >
        <TableCell>
          <Checkbox
            checked={selected}
            onChange={(e) => {
              e.stopPropagation()
              onToggle()
            }}
            aria-label={`Select ${user.name ?? user.email}`}
          />
        </TableCell>
        <TableCell>
          <Link
            to="/admin/users/$userId"
            params={{ userId: user.id }}
            className="group flex items-center gap-3"
            onClick={(e) => e.stopPropagation()}
          >
            <Avatar className="size-8 text-xs">
              <AvatarFallback>{getInitials(user.name, user.email)}</AvatarFallback>
            </Avatar>
            <div className="flex flex-col gap-0.5 min-w-0">
              <span className="font-medium truncate group-hover:underline" title={user.name ?? user.email}>
                {user.name ?? user.email}
              </span>
              {user.username && (
                <span className="text-xs text-muted-foreground truncate" title={`@${user.username}`}>
                  @{user.username}
                </span>
              )}
            </div>
          </Link>
        </TableCell>
        <TableCell className="hidden sm:table-cell">
          <span className="text-sm text-muted-foreground">{user.email}</span>
        </TableCell>
        <TableCell className="hidden sm:table-cell">
          {user.isSuperuser ? (
            <Badge variant="outline" className="gap-1 border-amber-300 bg-amber-500/10 text-amber-700 dark:border-amber-700 dark:text-amber-400">
              <Shield className="h-3 w-3" />
              Superuser
            </Badge>
          ) : (
            <Badge variant="secondary" className="gap-1">
              Member
            </Badge>
          )}
        </TableCell>
        <TableCell>
          <div className="flex items-center gap-2">
            <ActiveStatusIndicator isActive={user.isActive} />
            {user.isVerified ? (
              <Badge variant="outline" className="border-emerald-300 bg-emerald-500/10 text-emerald-700 dark:border-emerald-800 dark:text-emerald-400 text-[10px]">
                Verified
              </Badge>
            ) : (
              <Badge variant="outline" className="bg-muted text-muted-foreground text-[10px]">
                Unverified
              </Badge>
            )}
          </div>
        </TableCell>
        <TableCell className="hidden md:table-cell">
          <span className="text-sm tabular-nums text-muted-foreground">
            {user.loginCount ?? 0}
          </span>
        </TableCell>
        <TableCell className="hidden md:table-cell">
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="cursor-default text-xs text-muted-foreground">
                {formatRelativeTimeShort(user.createdAt)}
              </span>
            </TooltipTrigger>
            <TooltipContent>{formatDateTime(user.createdAt)}</TooltipContent>
          </Tooltip>
        </TableCell>
        <TableCell className="text-right">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8"
                data-slot="dropdown"
                onClick={(e) => e.stopPropagation()}
              >
                <MoreVertical className="h-4 w-4" />
                <span className="sr-only">Actions for {user.name ?? user.email}</span>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem asChild>
                <Link to="/admin/users/$userId" params={{ userId: user.id }}>
                  <Eye className="mr-2 h-4 w-4" />
                  View details
                </Link>
              </DropdownMenuItem>
              <DropdownMenuItem onSelect={() => setEditOpen(true)}>
                <Pencil className="mr-2 h-4 w-4" />
                Edit user
              </DropdownMenuItem>
              <DropdownMenuItem onSelect={() => setRolesOpen(true)}>
                <Shield className="mr-2 h-4 w-4" />
                Manage roles
              </DropdownMenuItem>
              <DropdownMenuItem onSelect={() => setJoinTeamOpen(true)}>
                <UserPlus className="mr-2 h-4 w-4" />
                Join team
              </DropdownMenuItem>
              <DropdownMenuItem onSelect={() => setPermissionsOpen(true)}>
                <Lock className="mr-2 h-4 w-4" />
                Manage permissions
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem onSelect={() => setStatusOpen(true)}>
                {user.isActive ? (
                  <>
                    <UserX className="mr-2 h-4 w-4" />
                    Deactivate
                  </>
                ) : (
                  <>
                    <UserCheck className="mr-2 h-4 w-4" />
                    Activate
                  </>
                )}
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem className="text-destructive" onSelect={() => setDeleteOpen(true)}>
                <Trash2 className="mr-2 h-4 w-4" />
                Delete user
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </TableCell>
      </TableRow>

      <EditUserDialog user={user} open={editOpen} onOpenChange={setEditOpen} />
      <ManageRolesDialog userId={user.id} userEmail={user.email} open={rolesOpen} onOpenChange={setRolesOpen} />
      <JoinTeamDialog userId={user.id} userName={user.name ?? user.email} open={joinTeamOpen} onOpenChange={setJoinTeamOpen} />
      <ManagePermissionsDialog userId={user.id} open={permissionsOpen} onOpenChange={setPermissionsOpen} />
      <ToggleUserStatusDialog userId={user.id} userEmail={user.email} userName={user.name ?? undefined} isActive={user.isActive ?? true} open={statusOpen} onOpenChange={setStatusOpen} />
      <DeleteUserDialog userId={user.id} userEmail={user.email} open={deleteOpen} onOpenChange={setDeleteOpen} />
    </>
  )
}
