import { createFileRoute, Link } from "@tanstack/react-router"
import { AlertCircle, Download, Eye, Home, Loader2, MoreVertical, Pencil, Plus, Search, SlidersHorizontal, Tags, Trash2, X } from "lucide-react"
import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Badge } from "@/components/ui/badge"
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb"
import { BulkActionBar, createBulkDeleteAction, createExportAction } from "@/components/ui/bulk-action-bar"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import { nextSortDirection, SortableHeader, type SortDirection } from "@/components/ui/sortable-header"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useDebouncedValue } from "@/hooks/use-debounced-value"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { useDeleteTag, useTags } from "@/lib/api/hooks/tags"
import { type CsvHeader, exportToCsv } from "@/lib/csv-export"
import { formatDateTime } from "@/lib/date-utils"
import type { Tag } from "@/lib/generated/api"
import { useSettingsStore } from "@/lib/settings-store"
import { cn } from "@/lib/utils"

export const Route = createFileRoute("/_app/tags/")({
  validateSearch: (
    search: Record<string, unknown>,
  ): {
    q?: string
    page?: number
    sort?: string
    order?: string
  } => ({
    q: typeof search.q === "string" && search.q ? search.q : undefined,
    page: Number(search.page) > 1 ? Number(search.page) : undefined,
    sort: typeof search.sort === "string" && search.sort ? search.sort : undefined,
    order: typeof search.order === "string" && (search.order === "asc" || search.order === "desc") ? search.order : undefined,
  }),
  component: TagsPage,
})

const PAGE_SIZES = [10, 25, 50, 100] as const
const DEFAULT_PAGE_SIZE = 25
const PAGE_SIZE_STORAGE_KEY = "tags-page-size"

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

// -- Column visibility ---------------------------------------------------------

const COLUMN_VISIBILITY_KEY = "tags-columns"

const TOGGLEABLE_COLUMNS = [
  { key: "slug", label: "Slug" },
  { key: "created", label: "Created" },
  { key: "updated", label: "Updated" },
] as const

type ColumnVisibility = Record<string, boolean>

function loadColumnVisibility(): ColumnVisibility {
  try {
    return JSON.parse(localStorage.getItem(COLUMN_VISIBILITY_KEY) ?? "{}")
  } catch {
    return {}
  }
}

const csvHeaders: CsvHeader<Tag>[] = [
  { label: "Name", accessor: (t) => t.name },
  { label: "Slug", accessor: (t) => t.slug },
]

function TagsPage() {
  useDocumentTitle("Tags")
  const compactMode = useSettingsStore((s) => s.compactMode)
  const cellClass = compactMode ? "py-1 px-2 text-xs" : ""
  const { q: searchParam, page: pageParam, sort: sortParam, order: orderParam } = Route.useSearch()
  const navigate = Route.useNavigate()
  const searchInputRef = useRef<HTMLInputElement>(null)

  // Column visibility
  const [columnVisibility, setColumnVisibility] = useState<ColumnVisibility>(loadColumnVisibility)
  const isColumnVisible = useCallback((col: string) => columnVisibility[col] !== false, [columnVisibility])
  const toggleColumn = useCallback((col: string) => {
    setColumnVisibility((prev) => {
      const updated = { ...prev, [col]: prev[col] === false }
      localStorage.setItem(COLUMN_VISIBILITY_KEY, JSON.stringify(updated))
      return updated
    })
  }, [])

  // Derive filter state from URL search params
  const search = searchParam ?? ""
  const page = pageParam ?? 1
  const sortKey = sortParam ?? null
  const sortDir: SortDirection = (orderParam as SortDirection) ?? null

  // Local input state for search (so typing is smooth before debounce)
  const [searchInput, setSearchInput] = useState(search)
  const debouncedSearch = useDebouncedValue(searchInput)

  // Sync URL when debounced search value settles
  useEffect(() => {
    navigate({
      search: (prev) => ({
        ...prev,
        q: debouncedSearch || undefined,
        page: undefined,
      }),
      replace: true,
    })
  }, [debouncedSearch, navigate])

  // Keep local input in sync if URL search param changes externally (back/forward)
  useEffect(() => {
    setSearchInput(search)
  }, [search])

  const [tagToDelete, setTagToDelete] = useState<Tag | null>(null)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [pageSize, setPageSize] = useState(getStoredPageSize)

  // Keyboard shortcuts: "/" to focus search, "N" opens the create page
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement
      if (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable) return
      if (e.key === "/" && !e.ctrlKey && !e.metaKey) {
        e.preventDefault()
        searchInputRef.current?.focus()
      }
      if (e.key === "n" && !e.ctrlKey && !e.metaKey && !e.altKey) {
        e.preventDefault()
        navigate({ to: "/tags/new" })
      }
    }
    document.addEventListener("keydown", handleKeyDown)
    return () => document.removeEventListener("keydown", handleKeyDown)
  }, [navigate])

  // Persist page size preference
  const handlePageSizeChange = useCallback(
    (value: string) => {
      const size = Number(value)
      setPageSize(size)
      navigate({ search: (prev) => ({ ...prev, page: undefined }), replace: true })
      try {
        localStorage.setItem(PAGE_SIZE_STORAGE_KEY, value)
      } catch {
        // localStorage unavailable
      }
    },
    [navigate],
  )

  const handleSort = useCallback(
    (key: string) => {
      const next = nextSortDirection(sortKey, sortDir, key)
      navigate({
        search: (prev) => ({
          ...prev,
          sort: next.sort || undefined,
          order: next.direction || undefined,
        }),
      })
    },
    [sortKey, sortDir, navigate],
  )

  const { data, isLoading, isRefetching, isError, refetch } = useTags({
    search: debouncedSearch || undefined,
    page,
    pageSize,
    orderBy: sortKey ?? undefined,
    sortOrder: sortDir ?? undefined,
  })
  const deleteTag = useDeleteTag()

  const items = data?.items ?? []
  const totalCount = data?.total ?? items.length
  const totalPages = Math.max(1, Math.ceil(totalCount / pageSize))

  // Sort locally as a fallback (server may not support all sort options)
  const sortedItems = useMemo(() => {
    if (!sortKey || !sortDir) return items
    const copy = [...items]
    copy.sort((a, b) => {
      const aVal = sortKey === "name" ? a.name.toLowerCase() : a.slug.toLowerCase()
      const bVal = sortKey === "name" ? b.name.toLowerCase() : b.slug.toLowerCase()
      if (aVal < bVal) return sortDir === "asc" ? -1 : 1
      if (aVal > bVal) return sortDir === "asc" ? 1 : -1
      return 0
    })
    return copy
  }, [items, sortKey, sortDir])

  // Export all visible
  const handleExportAll = useCallback(() => {
    if (!sortedItems.length) return
    exportToCsv("tags", csvHeaders, sortedItems)
  }, [sortedItems])

  const allSelected = sortedItems.length > 0 && selected.size === sortedItems.length
  const someSelected = selected.size > 0 && selected.size < sortedItems.length

  const toggleAll = () => {
    if (allSelected) {
      setSelected(new Set())
    } else {
      setSelected(new Set(sortedItems.map((t) => t.id)))
    }
  }

  const toggleOne = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const handleDelete = () => {
    if (!tagToDelete) return
    deleteTag.mutate(tagToDelete.id, {
      onSuccess: () => {
        setTagToDelete(null)
        setSelected((prev) => {
          const next = new Set(prev)
          if (tagToDelete) next.delete(tagToDelete.id)
          return next
        })
        // The deleted row is gone, so restore focus to the search input
        setTimeout(() => {
          const searchInput = document.querySelector<HTMLInputElement>('input[placeholder*="Search"]')
          if (searchInput) {
            searchInput.focus()
          }
        }, 0)
      },
    })
  }

  const handleRowClick = useCallback(
    (tagId: string) => {
      void navigate({ to: "/tags/$tagId", params: { tagId } })
    },
    [navigate],
  )

  const bulkActions = useMemo(
    () => [
      createBulkDeleteAction(
        (id) => deleteTag.mutateAsync(id),
        () => refetch(),
        { label: "Delete Selected" },
      ),
      createExportAction<Tag>(
        "tags",
        [
          { label: "Name", accessor: (t) => t.name },
          { label: "Slug", accessor: (t) => t.slug },
        ],
        (ids) => sortedItems.filter((t) => ids.includes(t.id)),
      ),
    ],
    [deleteTag, refetch, sortedItems],
  )

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
          <BreadcrumbPage>Tags</BreadcrumbPage>
        </BreadcrumbItem>
      </BreadcrumbList>
    </Breadcrumb>
  )

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Administration"
        title="Tags"
        description={
          totalCount > 0 && !isLoading
            ? `Create and manage tags for organizing resources across the system. ${totalCount} tag${totalCount !== 1 ? "s" : ""}.`
            : "Create and manage tags for organizing resources across the system."
        }
        breadcrumbs={breadcrumbs}
        actions={
          <div className="flex items-center gap-2">
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm">
                  <SlidersHorizontal className="mr-1.5 h-3.5 w-3.5" />
                  Columns
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-44">
                <DropdownMenuLabel>Toggle columns</DropdownMenuLabel>
                <DropdownMenuSeparator />
                {TOGGLEABLE_COLUMNS.map((col) => (
                  <DropdownMenuCheckboxItem key={col.key} checked={isColumnVisible(col.key)} onCheckedChange={() => toggleColumn(col.key)}>
                    {col.label}
                  </DropdownMenuCheckboxItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
            <Button variant="outline" size="sm" onClick={handleExportAll} disabled={!sortedItems.length}>
              <Download className="mr-2 h-4 w-4" />
              Export
            </Button>
            <Button size="sm" asChild>
              <Link to="/tags/new">
                <Plus className="mr-2 h-4 w-4" /> New Tag
                <kbd className="ml-1.5 hidden rounded border border-border bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground sm:inline">N</kbd>
              </Link>
            </Button>
          </div>
        }
      />

      {/* Summary stats */}
      <SectionErrorBoundary name="Tags Summary">
        <div className="flex flex-wrap items-center gap-2">
          {isLoading ? (
            <Skeleton className="h-7 w-24 rounded-full" />
          ) : (
            <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-muted/50 px-3 py-1 text-xs font-medium text-muted-foreground">
              Total
              <span className="ml-0.5 font-semibold text-foreground">{totalCount}</span>
            </span>
          )}
        </div>
      </SectionErrorBoundary>

      <PageSection>
        <div className="flex items-center gap-3">
          <div className="relative max-w-sm flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input ref={searchInputRef} placeholder="Search tags..." value={searchInput} onChange={(e) => setSearchInput(e.target.value)} className="pl-9 pr-8" />
            {searchInput ? (
              <button
                type="button"
                onClick={() => setSearchInput("")}
                className="absolute right-2 top-1/2 -translate-y-1/2 rounded-sm p-0.5 text-muted-foreground hover:text-foreground"
              >
                <X className="h-3.5 w-3.5" />
                <span className="sr-only">Clear search</span>
              </button>
            ) : (
              <kbd className="pointer-events-none absolute right-8 top-1/2 -translate-y-1/2 hidden rounded border border-border bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground sm:inline">
                /
              </kbd>
            )}
          </div>
        </div>
      </PageSection>

      <PageSection delay={0.1}>
        <SectionErrorBoundary name="Tags Table">
          {isLoading ? (
            <div className="space-y-3">
              {Array.from({ length: 5 }).map((_, i) => (
                // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
                <Skeleton key={`tag-skeleton-${i}`} className="h-12 w-full rounded-lg" />
              ))}
            </div>
          ) : isError ? (
            <EmptyState
              icon={AlertCircle}
              title="Unable to load tags"
              description="Something went wrong while fetching tags. Please try again."
              action={
                <Button variant="outline" size="sm" onClick={() => refetch()}>
                  Try again
                </Button>
              }
            />
          ) : !sortedItems.length && !search ? (
            <EmptyState
              icon={Tags}
              title="No tags yet"
              description="Create your first tag to start organizing resources."
              action={
                <Button size="sm" asChild>
                  <Link to="/tags/new">
                    <Plus className="mr-2 h-4 w-4" /> New Tag
                  </Link>
                </Button>
              }
            />
          ) : !sortedItems.length ? (
            <EmptyState
              icon={Tags}
              variant="no-results"
              title="No results found"
              description="No tags match your search. Try a different search term."
              action={
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    setSearchInput("")
                    navigate({
                      search: {
                        q: undefined,
                        sort: undefined,
                        order: undefined,
                        page: undefined,
                      },
                    })
                  }}
                >
                  Clear search
                </Button>
              }
            />
          ) : (
            <div className="space-y-3">
              {/* Result count & pagination info */}
              <div className="flex items-center justify-between">
                <p className="text-sm text-muted-foreground">
                  {totalCount} tag{totalCount === 1 ? "" : "s"}
                  {search && " (filtered)"}
                </p>
                {totalPages > 1 && (
                  <p className="text-xs text-muted-foreground">
                    Page {page} of {totalPages}
                  </p>
                )}
              </div>

              <div className="overflow-x-auto rounded-lg border">
                <Table aria-label="Tags" aria-busy={isLoading || isRefetching}>
                  <TableHeader className="sticky top-0 z-10 bg-background">
                    <TableRow>
                      <TableHead className="w-[40px]">
                        <Checkbox checked={allSelected} indeterminate={someSelected} onChange={toggleAll} aria-label="Select all tags" />
                      </TableHead>
                      <SortableHeader label="Name" sortKey="name" currentSort={sortKey} currentDirection={sortDir} onSort={handleSort} />
                      {isColumnVisible("slug") && (
                        <SortableHeader label="Slug" sortKey="slug" currentSort={sortKey} currentDirection={sortDir} onSort={handleSort} className="hidden md:table-cell" />
                      )}
                      {isColumnVisible("created") && (
                        <SortableHeader
                          label="Created"
                          sortKey="created_at"
                          currentSort={sortKey}
                          currentDirection={sortDir}
                          onSort={handleSort}
                          className="hidden md:table-cell"
                        />
                      )}
                      {isColumnVisible("updated") && (
                        <SortableHeader
                          label="Updated"
                          sortKey="updated_at"
                          currentSort={sortKey}
                          currentDirection={sortDir}
                          onSort={handleSort}
                          className="hidden md:table-cell"
                        />
                      )}
                      <TableHead className="w-16 text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {sortedItems.map((tag, index) => (
                      <TagRow
                        key={tag.id}
                        tag={tag}
                        index={index}
                        selected={selected.has(tag.id)}
                        onToggle={() => toggleOne(tag.id)}
                        onRowClick={() => handleRowClick(tag.id)}
                        onDelete={() => setTagToDelete(tag)}
                        cellClass={cellClass}
                        isColumnVisible={isColumnVisible}
                      />
                    ))}
                  </TableBody>
                </Table>
              </div>
              <div className="sr-only" aria-live="polite" aria-atomic="true">
                {!isLoading && `Showing ${sortedItems.length} of ${totalCount} results, page ${page}`}
              </div>

              {/* Pagination */}
              <div className="flex items-center justify-end gap-4 pt-2">
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
                      onClick={() =>
                        navigate({
                          search: (prev) => ({
                            ...prev,
                            page: page - 1 > 1 ? page - 1 : undefined,
                          }),
                        })
                      }
                      disabled={page <= 1}
                    >
                      Previous
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() =>
                        navigate({
                          search: (prev) => ({ ...prev, page: page + 1 }),
                        })
                      }
                      disabled={page >= totalPages}
                    >
                      Next
                    </Button>
                  </div>
                )}
              </div>
            </div>
          )}
        </SectionErrorBoundary>
      </PageSection>

      {/* Delete single tag confirmation */}
      <AlertDialog open={!!tagToDelete} onOpenChange={(open) => !open && setTagToDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete tag '{tagToDelete?.name}'?</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete this tag? This action cannot be undone. Any resources currently using this tag will have it removed.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setTagToDelete(null)} disabled={deleteTag.isPending}>
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction onClick={handleDelete} disabled={deleteTag.isPending} className="bg-destructive text-destructive-foreground hover:bg-destructive/90">
              {deleteTag.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <BulkActionBar selectedCount={selected.size} selectedIds={Array.from(selected)} onClearSelection={() => setSelected(new Set())} actions={bulkActions} />
    </PageContainer>
  )
}

// ---------------------------------------------------------------------------
// Tag Row
// ---------------------------------------------------------------------------

function TagRow({
  tag,
  index,
  selected,
  onToggle,
  onRowClick,
  onDelete,
  cellClass,
  isColumnVisible,
}: {
  tag: Tag
  index: number
  selected: boolean
  onToggle: () => void
  onRowClick: () => void
  onDelete: () => void
  cellClass: string
  isColumnVisible: (col: string) => boolean
}) {
  return (
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
      <TableCell className={cellClass}>
        <Checkbox
          checked={selected}
          onChange={(e) => {
            e.stopPropagation()
            onToggle()
          }}
          aria-label={`Select ${tag.name}`}
        />
      </TableCell>
      <TableCell className={cn("font-medium", cellClass)}>
        <Link to="/tags/$tagId" params={{ tagId: tag.id }} onClick={(e) => e.stopPropagation()} className="hover:underline">
          <Badge variant="secondary">{tag.name}</Badge>
        </Link>
      </TableCell>
      {isColumnVisible("slug") && <TableCell className={cn("hidden md:table-cell font-mono text-xs text-muted-foreground", cellClass)}>{tag.slug}</TableCell>}
      {isColumnVisible("created") && (
        <TableCell className={cn("hidden md:table-cell text-xs text-muted-foreground", cellClass)}>{tag.createdAt ? formatDateTime(tag.createdAt) : "--"}</TableCell>
      )}
      {isColumnVisible("updated") && (
        <TableCell className={cn("hidden md:table-cell text-xs text-muted-foreground", cellClass)}>{tag.updatedAt ? formatDateTime(tag.updatedAt) : "--"}</TableCell>
      )}
      <TableCell className={cn("text-right", cellClass)}>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="sm" className="h-8 w-8 p-0" data-slot="dropdown" onClick={(e) => e.stopPropagation()}>
              <MoreVertical className="h-4 w-4" />
              <span className="sr-only">Actions for {tag.name}</span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem asChild>
              <Link to="/tags/$tagId" params={{ tagId: tag.id }}>
                <Eye className="mr-2 h-4 w-4" />
                View details
              </Link>
            </DropdownMenuItem>
            <DropdownMenuItem asChild>
              <Link to="/tags/$tagId/edit" params={{ tagId: tag.id }}>
                <Pencil className="mr-2 h-4 w-4" />
                Edit
              </Link>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem className="text-destructive focus:text-destructive" onClick={onDelete}>
              <Trash2 className="mr-2 h-4 w-4" />
              Delete
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </TableCell>
    </TableRow>
  )
}
