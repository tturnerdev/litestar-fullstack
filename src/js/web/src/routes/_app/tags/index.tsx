import { createFileRoute, Link, useNavigate } from "@tanstack/react-router"
import { useCallback, useEffect, useMemo, useState } from "react"
import { AlertCircle, ArrowUpDown, Download, Eye, Home, Loader2, MoreVertical, Pencil, Plus, Search, Tags, Trash2, X } from "lucide-react"
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

type SortField = "name" | "slug"
type SortDir = "asc" | "desc"

const PAGE_SIZE = 25

const csvHeaders: CsvHeader<Tag>[] = [
  { label: "Name", accessor: (t) => t.name },
  { label: "Slug", accessor: (t) => t.slug },
]

function TagsPage() {
  useDocumentTitle("Tags")
  const navigate = useNavigate()
  const [search, setSearch] = useState("")
  const debouncedSearch = useDebouncedValue(search)
  const [deleteId, setDeleteId] = useState<string | null>(null)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [sortField, setSortField] = useState<SortField>("name")
  const [sortDir, setSortDir] = useState<SortDir>("asc")
  const [page, setPage] = useState(1)

  // Reset page when debounced search changes
  useEffect(() => {
    setPage(1)
  }, [debouncedSearch])

  const { data, isLoading, isError, refetch } = useTags({
    search: debouncedSearch || undefined,
    page,
    pageSize: PAGE_SIZE,
    orderBy: sortField,
    sortOrder: sortDir,
  })
  const deleteTag = useDeleteTag()

  const items = data?.items ?? []
  const totalCount = data?.total ?? items.length
  const totalPages = Math.max(1, Math.ceil(totalCount / PAGE_SIZE))

  // Sort locally as a fallback (server may not support all sort options)
  const sortedItems = useMemo(() => {
    const copy = [...items]
    copy.sort((a, b) => {
      const aVal = sortField === "name" ? a.name.toLowerCase() : a.slug.toLowerCase()
      const bVal = sortField === "name" ? b.name.toLowerCase() : b.slug.toLowerCase()
      if (aVal < bVal) return sortDir === "asc" ? -1 : 1
      if (aVal > bVal) return sortDir === "asc" ? 1 : -1
      return 0
    })
    return copy
  }, [items, sortField, sortDir])

  // Export all visible
  const handleExportAll = useCallback(() => {
    if (!sortedItems.length) return
    exportToCsv("tags", csvHeaders, sortedItems)
  }, [sortedItems])

  const allSelected = sortedItems.length > 0 && selected.size === sortedItems.length
  const someSelected = selected.size > 0 && selected.size < sortedItems.length

  const toggleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"))
    } else {
      setSortField(field)
      setSortDir("asc")
    }
  }

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
    if (!deleteId) return
    deleteTag.mutate(deleteId, {
      onSuccess: () => {
        setDeleteId(null)
        setSelected((prev) => {
          const next = new Set(prev)
          next.delete(deleteId)
          return next
        })
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
              placeholder="Search tags..."
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
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[40px]">
                    <Checkbox
                      checked={allSelected}
                      indeterminate={someSelected}
                      onChange={toggleAll}
                      aria-label="Select all tags"
                    />
                  </TableHead>
                  <TableHead>
                    <button
                      type="button"
                      className="inline-flex items-center gap-1 font-medium hover:text-foreground transition-colors"
                      onClick={() => toggleSort("name")}
                    >
                      Name
                      <ArrowUpDown className="h-3.5 w-3.5 text-muted-foreground" />
                    </button>
                  </TableHead>
                  <TableHead className="hidden md:table-cell">
                    <button
                      type="button"
                      className="inline-flex items-center gap-1 font-medium hover:text-foreground transition-colors"
                      onClick={() => toggleSort("slug")}
                    >
                      Slug
                      <ArrowUpDown className="h-3.5 w-3.5 text-muted-foreground" />
                    </button>
                  </TableHead>
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
                    onDelete={() => setDeleteId(tag.id)}
                  />
                ))}
              </TableBody>
            </Table>
          </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-end gap-2">
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
        )}
      </PageSection>

      {/* Delete single tag confirmation */}
      <AlertDialog open={!!deleteId} onOpenChange={(open) => !open && setDeleteId(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete tag</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete this tag? This action cannot be undone. Any resources currently using this tag will have it removed.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setDeleteId(null)} disabled={deleteTag.isPending}>
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
