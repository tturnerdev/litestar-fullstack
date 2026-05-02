import { createFileRoute, Link, useNavigate } from "@tanstack/react-router"
import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { AlertCircle, Download, Eye, Home, Loader2, MoreVertical, Pencil, Plus, Search, Tags, Trash2, X } from "lucide-react"
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
import { BulkActionBar, createBulkDeleteAction, createExportAction } from "@/components/ui/bulk-action-bar"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { nextSortDirection, SortableHeader, type SortDirection } from "@/components/ui/sortable-header"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useTags, useDeleteTag } from "@/lib/api/hooks/tags"
import { exportToCsv, type CsvHeader } from "@/lib/csv-export"
import { useDebouncedValue } from "@/hooks/use-debounced-value"
import { useDocumentTitle } from "@/hooks/use-document-title"
import type { Tag } from "@/lib/generated/api"

export const Route = createFileRoute("/_app/tags/")({
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

const csvHeaders: CsvHeader<Tag>[] = [
  { label: "Name", accessor: (t) => t.name },
  { label: "Slug", accessor: (t) => t.slug },
]

function TagsPage() {
  useDocumentTitle("Tags")
  const navigate = useNavigate()
  const searchInputRef = useRef<HTMLInputElement>(null)
  const [search, setSearch] = useState("")
  const debouncedSearch = useDebouncedValue(search)
  const [tagToDelete, setTagToDelete] = useState<Tag | null>(null)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<SortDirection>(null)
  const [page, setPage] = useState(1)
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

  const handleSort = useCallback((key: string) => {
    const next = nextSortDirection(sortKey, sortDir, key)
    setSortKey(next.sort)
    setSortDir(next.direction)
  }, [sortKey, sortDir])

  const { data, isLoading, isError, refetch } = useTags({
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
      navigate({ to: "/tags/$tagId/edit", params: { tagId } })
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

      <PageSection>
        <div className="flex items-center gap-3">
          <div className="relative max-w-sm flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              ref={searchInputRef}
              placeholder="Search tags..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9 pr-8"
            />
            {search ? (
              <button
                type="button"
                onClick={() => setSearch("")}
                className="absolute right-2 top-1/2 -translate-y-1/2 rounded-sm p-0.5 text-muted-foreground hover:text-foreground"
              >
                <X className="h-3.5 w-3.5" />
                <span className="sr-only">Clear search</span>
              </button>
            ) : (
              <kbd className="pointer-events-none absolute right-8 top-1/2 -translate-y-1/2 hidden rounded border border-border bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground sm:inline">/</kbd>
            )}
          </div>
        </div>
      </PageSection>

      <PageSection delay={0.1}>
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
              <Button variant="outline" size="sm" onClick={() => setSearch("")}>
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
            <Table aria-label="Tags">
              <TableHeader className="sticky top-0 z-10 bg-background">
                <TableRow>
                  <TableHead className="w-[40px]">
                    <Checkbox
                      checked={allSelected}
                      indeterminate={someSelected}
                      onChange={toggleAll}
                      aria-label="Select all tags"
                    />
                  </TableHead>
                  <SortableHeader label="Name" sortKey="name" currentSort={sortKey} currentDirection={sortDir} onSort={handleSort} />
                  <SortableHeader label="Slug" sortKey="slug" currentSort={sortKey} currentDirection={sortDir} onSort={handleSort} className="hidden md:table-cell" />
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
                  />
                ))}
              </TableBody>
            </Table>
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
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                    disabled={page <= 1}
                  >
                    Previous
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                    disabled={page >= totalPages}
                  >
                    Next
                  </Button>
                </div>
              )}
            </div>
          </div>
        )}
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
            <AlertDialogAction
              onClick={handleDelete}
              disabled={deleteTag.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteTag.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <BulkActionBar
        selectedCount={selected.size}
        selectedIds={Array.from(selected)}
        onClearSelection={() => setSelected(new Set())}
        actions={bulkActions}
      />
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
}: {
  tag: Tag
  index: number
  selected: boolean
  onToggle: () => void
  onRowClick: () => void
  onDelete: () => void
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
      <TableCell>
        <Checkbox
          checked={selected}
          onChange={(e) => {
            e.stopPropagation()
            onToggle()
          }}
          aria-label={`Select ${tag.name}`}
        />
      </TableCell>
      <TableCell className="font-medium">
        <Link
          to="/tags/$tagId/edit"
          params={{ tagId: tag.id }}
          onClick={(e) => e.stopPropagation()}
        >
          <Badge variant="secondary">{tag.name}</Badge>
        </Link>
      </TableCell>
      <TableCell className="hidden md:table-cell font-mono text-xs text-muted-foreground">{tag.slug}</TableCell>
      <TableCell className="text-right">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="sm"
              className="h-8 w-8 p-0"
              data-slot="dropdown"
              onClick={(e) => e.stopPropagation()}
            >
              <MoreVertical className="h-4 w-4" />
              <span className="sr-only">Actions for {tag.name}</span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem asChild>
              <Link to="/tags/$tagId/edit" params={{ tagId: tag.id }}>
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
            <DropdownMenuItem
              className="text-destructive focus:text-destructive"
              onClick={onDelete}
            >
              <Trash2 className="mr-2 h-4 w-4" />
              Delete
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </TableCell>
    </TableRow>
  )
}
