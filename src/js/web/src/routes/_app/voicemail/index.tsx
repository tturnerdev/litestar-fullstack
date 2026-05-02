import { createFileRoute, Link, useNavigate } from "@tanstack/react-router"
import { useCallback, useEffect, useMemo, useState } from "react"
import { z } from "zod"
import {
  AlertCircle,
  AlertTriangle,
  CheckSquare,
  Download,
  Eye,
  Home,
  Inbox,
  Loader2,
  Mail,
  MailOpen,
  MoreVertical,
  Play,
  Search,
  Square,
  Trash2,
  Voicemail,
  X,
} from "lucide-react"
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
import { DataFreshness } from "@/components/ui/data-freshness"
import { Badge } from "@/components/ui/badge"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { EmptyState } from "@/components/ui/empty-state"
import { FilterDropdown, type FilterOption } from "@/components/ui/filter-dropdown"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Skeleton, SkeletonCard } from "@/components/ui/skeleton"
import { nextSortDirection, SortableHeader, type SortDirection } from "@/components/ui/sortable-header"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { VoicemailPlayer } from "@/components/voice/voicemail-player"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { useDebouncedValue } from "@/hooks/use-debounced-value"
import { exportToCsv, type CsvHeader } from "@/lib/csv-export"
import { formatDateTime, formatFullDateTime } from "@/lib/date-utils"
import { formatDuration } from "@/lib/format-utils"
import {
  useBulkDeleteVoicemailMessages,
  useBulkMarkVoicemailRead,
  useDeleteVoicemailBox,
  useDeleteVoicemailMessage,
  useToggleVoicemailRead,
  useVoicemailBoxes,
  useVoicemailMessages,
  type VoicemailBox,
  type VoicemailMessage,
} from "@/lib/api/hooks/voicemail"

const searchSchema = z.object({
  tab: z.string().optional(),
})

export const Route = createFileRoute("/_app/voicemail/")({
  component: VoicemailInboxPage,
  validateSearch: searchSchema,
})

// -- Constants ----------------------------------------------------------------

const PAGE_SIZES = [10, 25, 50, 100] as const
const DEFAULT_PAGE_SIZE = 25
const PAGE_SIZE_STORAGE_KEY = "voicemail-page-size"

function getStoredPageSize(): number {
  try {
    const stored = localStorage.getItem(PAGE_SIZE_STORAGE_KEY)
    if (stored) {
      const parsed = Number(stored)
      if ((PAGE_SIZES as readonly number[]).includes(parsed)) return parsed
    }
  } catch {
    /* localStorage unavailable */
  }
  return DEFAULT_PAGE_SIZE
}

const readFilterOptions: FilterOption[] = [
  { value: "unread", label: "Unread" },
  { value: "read", label: "Read" },
]

const csvHeaders: CsvHeader<VoicemailMessage>[] = [
  { label: "Caller", accessor: (m) => m.callerName ?? m.callerNumber },
  { label: "Caller Number", accessor: (m) => m.callerNumber },
  { label: "Duration", accessor: (m) => formatDuration(m.durationSeconds) },
  { label: "Date", accessor: (m) => m.receivedAt },
  { label: "Read", accessor: (m) => (m.isRead ? "Yes" : "No") },
  { label: "Urgent", accessor: (m) => (m.isUrgent ? "Yes" : "No") },
  { label: "Transcription", accessor: (m) => m.transcription ?? "" },
]

// -- Main page ----------------------------------------------------------------

function VoicemailInboxPage() {
  useDocumentTitle("Voicemail")
  const { tab = "messages" } = Route.useSearch()
  const navigate = Route.useNavigate()

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Communications"
        title="Voicemail"
        description="Manage voicemail messages and mailbox settings across all extensions."
        breadcrumbs={
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
                <BreadcrumbPage>Voicemail</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
      />

      <PageSection>
        <Tabs
          value={tab}
          onValueChange={(value) => navigate({ search: { tab: value }, replace: true })}
        >
          <TabsList>
            <TabsTrigger value="messages">All Messages</TabsTrigger>
            <TabsTrigger value="boxes">Voicemail Boxes</TabsTrigger>
          </TabsList>

          <TabsContent value="messages" className="mt-6">
            <MessagesTab />
          </TabsContent>

          <TabsContent value="boxes" className="mt-6">
            <BoxesTab />
          </TabsContent>
        </Tabs>
      </PageSection>
    </PageContainer>
  )
}

// -- Messages Tab -------------------------------------------------------------

function MessagesTab() {
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(getStoredPageSize)
  const [search, setSearch] = useState("")
  const debouncedSearch = useDebouncedValue(search)
  const [readFilter, setReadFilter] = useState<string[]>([])
  const [startDate, setStartDate] = useState("")
  const [endDate, setEndDate] = useState("")
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [detailMessage, setDetailMessage] = useState<VoicemailMessage | null>(null)
  const [bulkDeleteOpen, setBulkDeleteOpen] = useState(false)
  const [singleDeleteId, setSingleDeleteId] = useState<string | null>(null)

  const handlePageSizeChange = useCallback((value: string) => {
    const size = Number(value)
    setPageSize(size)
    setPage(1)
    try {
      localStorage.setItem(PAGE_SIZE_STORAGE_KEY, String(size))
    } catch {
      /* localStorage unavailable */
    }
  }, [])

  // Sort state
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<SortDirection>(null)

  const handleSort = useCallback(
    (key: string) => {
      const next = nextSortDirection(sortKey, sortDir, key)
      setSortKey(next.sort)
      setSortDir(next.direction)
    },
    [sortKey, sortDir],
  )

  const isReadParam =
    readFilter.length === 1
      ? readFilter[0] === "read"
        ? true
        : readFilter[0] === "unread"
          ? false
          : null
      : null

  const { data, isLoading, isError, refetch, dataUpdatedAt, isRefetching } = useVoicemailMessages({
    page,
    pageSize,
    isRead: isReadParam,
    startDate: startDate || undefined,
    endDate: endDate || undefined,
  })

  const toggleReadMutation = useToggleVoicemailRead()
  const deleteMutation = useDeleteVoicemailMessage()
  const bulkMarkReadMutation = useBulkMarkVoicemailRead()
  const bulkDeleteMutation = useBulkDeleteVoicemailMessages()

  const allItems = data?.items ?? []
  const filteredItems = debouncedSearch
    ? allItems.filter((m) => {
        const q = debouncedSearch.toLowerCase()
        return (
          m.callerNumber.toLowerCase().includes(q) ||
          (m.callerName && m.callerName.toLowerCase().includes(q)) ||
          (m.transcription && m.transcription.toLowerCase().includes(q))
        )
      })
    : allItems

  // Client-side sorting
  const sortedItems = useMemo(() => {
    if (!sortKey || !sortDir) return filteredItems
    const sorted = [...filteredItems]
    sorted.sort((a, b) => {
      let aVal: string | number
      let bVal: string | number
      switch (sortKey) {
        case "caller":
          aVal = (a.callerName ?? a.callerNumber).toLowerCase()
          bVal = (b.callerName ?? b.callerNumber).toLowerCase()
          break
        case "duration":
          aVal = a.durationSeconds
          bVal = b.durationSeconds
          break
        case "date":
          aVal = a.receivedAt
          bVal = b.receivedAt
          break
        default:
          return 0
      }
      if (aVal < bVal) return sortDir === "asc" ? -1 : 1
      if (aVal > bVal) return sortDir === "asc" ? 1 : -1
      return 0
    })
    return sorted
  }, [filteredItems, sortKey, sortDir])

  const items = sortedItems
  const totalPages = Math.max(1, Math.ceil((data?.total ?? 0) / pageSize))
  const allSelected = items.length > 0 && items.every((m) => selectedIds.has(m.id))
  const someSelected = selectedIds.size > 0

  const activeFilterCount = readFilter.length + (startDate || endDate ? 1 : 0) + (debouncedSearch ? 1 : 0)

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

  // Export all visible
  const handleExportAll = useCallback(() => {
    if (!items.length) return
    exportToCsv("voicemail-messages", csvHeaders, items)
  }, [items])

  function toggleSelectAll() {
    if (allSelected) {
      setSelectedIds(new Set())
    } else {
      setSelectedIds(new Set(items.map((m) => m.id)))
    }
  }

  function toggleSelect(id: string) {
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  function handleBulkMarkRead() {
    const ids = Array.from(selectedIds)
    bulkMarkReadMutation.mutate(ids, {
      onSuccess: () => setSelectedIds(new Set()),
    })
  }

  function handleBulkDeleteConfirm() {
    const ids = Array.from(selectedIds)
    bulkDeleteMutation.mutate(ids, {
      onSuccess: () => {
        setSelectedIds(new Set())
        setBulkDeleteOpen(false)
        if (detailMessage && ids.includes(detailMessage.id)) setDetailMessage(null)
      },
    })
  }

  function handleSingleDeleteConfirm() {
    if (!singleDeleteId) return
    const messageId = singleDeleteId
    deleteMutation.mutate(messageId, {
      onSuccess: () => {
        setSingleDeleteId(null)
        if (detailMessage?.id === messageId) setDetailMessage(null)
        setSelectedIds((prev) => {
          const next = new Set(prev)
          next.delete(messageId)
          return next
        })
      },
    })
  }

  function handleOpenDetail(message: VoicemailMessage) {
    setDetailMessage(message)
    if (!message.isRead) {
      toggleReadMutation.mutate({ messageId: message.id, isRead: true })
    }
  }

  if (isLoading) {
    return (
      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <SkeletonCard key={i} />
        ))}
      </div>
    )
  }

  if (isError) {
    return (
      <EmptyState
        icon={AlertCircle}
        title="Unable to load messages"
        description="Something went wrong while fetching voicemail messages. Please try again."
        action={
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            Try again
          </Button>
        }
      />
    )
  }

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative max-w-sm flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search by caller or transcription..."
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
          label="Status"
          options={readFilterOptions}
          selected={readFilter}
          onChange={(v) => {
            setReadFilter(v)
            setPage(1)
          }}
        />
        <div className="flex items-center gap-2">
          <Input
            type="date"
            placeholder="Start date"
            value={startDate}
            onChange={(e) => {
              setStartDate(e.target.value)
              setPage(1)
            }}
            className="h-9 w-36"
          />
          <span className="text-xs text-muted-foreground">to</span>
          <Input
            type="date"
            placeholder="End date"
            value={endDate}
            onChange={(e) => {
              setEndDate(e.target.value)
              setPage(1)
            }}
            className="h-9 w-36"
          />
        </div>
        {activeFilterCount > 0 && (
          <Button
            variant="ghost"
            size="sm"
            className="text-xs text-muted-foreground"
            onClick={() => {
              setSearch("")
              setReadFilter([])
              setStartDate("")
              setEndDate("")
              setPage(1)
            }}
          >
            Clear filters
          </Button>
        )}
        <div className="ml-auto flex items-center gap-2">
          <DataFreshness
            dataUpdatedAt={dataUpdatedAt}
            onRefresh={() => refetch()}
            isRefreshing={isRefetching}
          />
          <Button variant="outline" size="sm" onClick={handleExportAll} disabled={items.length === 0}>
            <Download className="mr-2 h-4 w-4" />
            Export
          </Button>
        </div>
      </div>

      {/* Bulk actions */}
      {someSelected && (
        <div className="flex items-center gap-2">
          <Badge variant="outline">{selectedIds.size} selected</Badge>
          <Button
            variant="outline"
            size="sm"
            onClick={handleBulkMarkRead}
            disabled={bulkMarkReadMutation.isPending}
          >
            <MailOpen className="mr-1 h-4 w-4" />
            Mark read
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setBulkDeleteOpen(true)}
            disabled={bulkDeleteMutation.isPending}
          >
            <Trash2 className="mr-1 h-4 w-4" />
            Delete
          </Button>
        </div>
      )}

      {items.length === 0 ? (
        <EmptyState
          icon={Inbox}
          title="No voicemail messages"
          description={
            activeFilterCount > 0
              ? "No messages match your current filters. Try adjusting your search."
              : "When callers leave voicemails, their messages will appear here."
          }
          action={
            activeFilterCount > 0 ? (
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setSearch("")
                  setReadFilter([])
                  setStartDate("")
                  setEndDate("")
                }}
              >
                Clear filters
              </Button>
            ) : undefined
          }
        />
      ) : (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-xs text-muted-foreground">
              {debouncedSearch
                ? `${items.length} of ${data?.total ?? allItems.length} message${(data?.total ?? allItems.length) === 1 ? "" : "s"}`
                : `${data?.total ?? items.length} message${(data?.total ?? items.length) === 1 ? "" : "s"}`}
              {activeFilterCount > 0 && " (filtered)"}
            </p>
            {totalPages > 1 && (
              <p className="text-xs text-muted-foreground">
                Page {page} of {totalPages}
              </p>
            )}
          </div>

          <div className="overflow-x-auto rounded-md border border-border/60 bg-card/80">
            <Table aria-label="Voicemail messages">
              <TableHeader className="sticky top-0 z-10 bg-background">
                <TableRow>
                  <TableHead className="w-10">
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-6 w-6 p-0"
                      onClick={toggleSelectAll}
                    >
                      {allSelected ? (
                        <CheckSquare className="h-4 w-4" />
                      ) : (
                        <Square className="h-4 w-4" />
                      )}
                    </Button>
                  </TableHead>
                  <TableHead className="w-10" />
                  <SortableHeader
                    label="Caller"
                    sortKey="caller"
                    currentSort={sortKey}
                    currentDirection={sortDir}
                    onSort={handleSort}
                  />
                  <SortableHeader
                    label="Duration"
                    sortKey="duration"
                    currentSort={sortKey}
                    currentDirection={sortDir}
                    onSort={handleSort}
                  />
                  <SortableHeader
                    label="Date/Time"
                    sortKey="date"
                    currentSort={sortKey}
                    currentDirection={sortDir}
                    onSort={handleSort}
                  />
                  <TableHead>Status</TableHead>
                  <TableHead className="w-16 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((msg) => (
                  <TableRow
                    key={msg.id}
                    className={`cursor-pointer transition-colors hover:bg-muted/50 ${!msg.isRead ? "bg-primary/5 font-medium" : ""} ${selectedIds.has(msg.id) ? "bg-primary/10" : ""}`}
                    onClick={() => handleOpenDetail(msg)}
                  >
                    <TableCell>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-6 w-6 p-0"
                        onClick={(e) => {
                          e.stopPropagation()
                          toggleSelect(msg.id)
                        }}
                      >
                        {selectedIds.has(msg.id) ? (
                          <CheckSquare className="h-4 w-4" />
                        ) : (
                          <Square className="h-4 w-4" />
                        )}
                      </Button>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1">
                        {!msg.isRead && (
                          <div className="h-2.5 w-2.5 animate-pulse rounded-full bg-primary" />
                        )}
                        {msg.isUrgent && (
                          <AlertTriangle className="h-3.5 w-3.5 text-destructive" />
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div>
                        <span className={!msg.isRead ? "font-semibold" : ""}>
                          {msg.callerName ?? msg.callerNumber}
                        </span>
                        {msg.callerName && (
                          <p className="font-mono text-xs text-muted-foreground">
                            {msg.callerNumber}
                          </p>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="tabular-nums">
                      {formatDuration(msg.durationSeconds)}
                    </TableCell>
                    <TableCell>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span className="text-sm">{formatDateTime(msg.receivedAt)}</span>
                        </TooltipTrigger>
                        <TooltipContent>
                          <p>{formatFullDateTime(msg.receivedAt)}</p>
                        </TooltipContent>
                      </Tooltip>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1.5">
                        {msg.isRead ? (
                          <Badge variant="outline" className="text-xs">
                            Read
                          </Badge>
                        ) : (
                          <Badge variant="secondary" className="text-xs">
                            Unread
                          </Badge>
                        )}
                        {msg.isUrgent && (
                          <Badge variant="destructive" className="text-xs">
                            Urgent
                          </Badge>
                        )}
                      </div>
                    </TableCell>
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
                            <span className="sr-only">Actions for message from {msg.callerName ?? msg.callerNumber}</span>
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem
                            onClick={() => handleOpenDetail(msg)}
                          >
                            <Play className="mr-2 h-4 w-4" />
                            Play message
                          </DropdownMenuItem>
                          <DropdownMenuItem
                            onClick={() =>
                              toggleReadMutation.mutate({
                                messageId: msg.id,
                                isRead: !msg.isRead,
                              })
                            }
                          >
                            {msg.isRead ? (
                              <>
                                <Mail className="mr-2 h-4 w-4" />
                                Mark as unread
                              </>
                            ) : (
                              <>
                                <MailOpen className="mr-2 h-4 w-4" />
                                Mark as read
                              </>
                            )}
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem
                            variant="destructive"
                            onClick={() => setSingleDeleteId(msg.id)}
                          >
                            <Trash2 className="mr-2 h-4 w-4" />
                            Delete
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>

          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="text-xs text-muted-foreground">Rows per page</span>
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
                  <kbd className="ml-1.5 hidden rounded border border-border bg-muted px-1 py-0.5 text-[10px] font-medium text-muted-foreground lg:inline">&larr;</kbd>
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
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

      {/* Message detail dialog */}
      <MessageDetailDialog
        message={detailMessage}
        open={detailMessage !== null}
        onOpenChange={(open) => {
          if (!open) setDetailMessage(null)
        }}
        onMarkRead={(isRead) => {
          if (detailMessage) {
            toggleReadMutation.mutate({ messageId: detailMessage.id, isRead })
          }
        }}
        onDelete={() => {
          if (detailMessage) {
            setSingleDeleteId(detailMessage.id)
          }
        }}
      />

      {/* Bulk delete confirmation */}
      <AlertDialog
        open={bulkDeleteOpen}
        onOpenChange={(open) => {
          if (!bulkDeleteMutation.isPending) setBulkDeleteOpen(open)
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2 text-destructive">
              <AlertTriangle className="size-5" />
              Delete voicemail messages
            </AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete {selectedIds.size} voicemail{" "}
              {selectedIds.size === 1 ? "message" : "messages"}. This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={bulkDeleteMutation.isPending}>
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={handleBulkDeleteConfirm}
              disabled={bulkDeleteMutation.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {bulkDeleteMutation.isPending ? (
                <>
                  <Loader2 className="mr-1 size-4 animate-spin" />
                  Deleting...
                </>
              ) : (
                <>
                  <Trash2 className="mr-1 size-4" />
                  Delete {selectedIds.size}{" "}
                  {selectedIds.size === 1 ? "message" : "messages"}
                </>
              )}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Single delete confirmation */}
      <AlertDialog
        open={singleDeleteId !== null}
        onOpenChange={(open) => {
          if (!open && !deleteMutation.isPending) setSingleDeleteId(null)
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2 text-destructive">
              <AlertTriangle className="size-5" />
              Delete voicemail
            </AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete this voicemail message. This action cannot be
              undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteMutation.isPending}>
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={handleSingleDeleteConfirm}
              disabled={deleteMutation.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteMutation.isPending ? (
                <>
                  <Loader2 className="mr-1 size-4 animate-spin" />
                  Deleting...
                </>
              ) : (
                <>
                  <Trash2 className="mr-1 size-4" />
                  Delete
                </>
              )}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

// -- Message Detail Dialog ----------------------------------------------------

function MessageDetailDialog({
  message,
  open,
  onOpenChange,
  onMarkRead,
  onDelete,
}: {
  message: VoicemailMessage | null
  open: boolean
  onOpenChange: (open: boolean) => void
  onMarkRead: (isRead: boolean) => void
  onDelete: () => void
}) {
  if (!message) return null

  const callerDisplay = message.callerName ?? message.callerNumber

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Voicemail className="h-5 w-5 text-muted-foreground" />
            Voicemail from {callerDisplay}
          </DialogTitle>
          <DialogDescription>
            {message.callerName && (
              <span className="font-mono text-xs">{message.callerNumber}</span>
            )}
            {message.callerName && " — "}
            {formatFullDateTime(message.receivedAt)} — {formatDuration(message.durationSeconds)}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {/* Status badges */}
          <div className="flex items-center gap-2">
            {message.isRead ? (
              <Badge variant="outline">Read</Badge>
            ) : (
              <Badge variant="secondary">Unread</Badge>
            )}
            {message.isUrgent && <Badge variant="destructive">Urgent</Badge>}
          </div>

          {/* Audio player */}
          <VoicemailPlayer
            audioUrl={message.audioFilePath}
            durationSeconds={message.durationSeconds}
          />

          {/* Transcription */}
          {message.transcription && (
            <div className="space-y-1">
              <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Transcription
              </p>
              <div className="rounded-lg bg-muted/30 p-3">
                <p className="text-sm leading-relaxed">{message.transcription}</p>
              </div>
            </div>
          )}

          {/* Actions */}
          <div className="flex items-center gap-2 border-t pt-4">
            <Button
              variant="outline"
              size="sm"
              onClick={() => onMarkRead(!message.isRead)}
            >
              {message.isRead ? (
                <>
                  <Mail className="mr-1.5 h-4 w-4" />
                  Mark unread
                </>
              ) : (
                <>
                  <MailOpen className="mr-1.5 h-4 w-4" />
                  Mark read
                </>
              )}
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="text-destructive hover:bg-destructive hover:text-destructive-foreground"
              onClick={() => {
                onOpenChange(false)
                onDelete()
              }}
            >
              <Trash2 className="mr-1.5 h-4 w-4" />
              Delete
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}

// -- Boxes Tab ----------------------------------------------------------------

function BoxesTab() {
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(getStoredPageSize)
  const [search, setSearch] = useState("")
  const debouncedSearch = useDebouncedValue(search)

  const handlePageSizeChange = useCallback((value: string) => {
    const size = Number(value)
    setPageSize(size)
    setPage(1)
    try {
      localStorage.setItem(PAGE_SIZE_STORAGE_KEY, String(size))
    } catch {
      /* localStorage unavailable */
    }
  }, [])

  // Sort state
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<SortDirection>(null)

  const handleSort = useCallback(
    (key: string) => {
      const next = nextSortDirection(sortKey, sortDir, key)
      setSortKey(next.sort)
      setSortDir(next.direction)
    },
    [sortKey, sortDir],
  )

  useEffect(() => {
    setPage(1)
  }, [debouncedSearch])

  const { data, isLoading, isError, refetch } = useVoicemailBoxes({
    page,
    pageSize,
    search: debouncedSearch || undefined,
  })

  const rawItems = data?.items ?? []

  // Client-side sorting
  const items = useMemo(() => {
    if (!sortKey || !sortDir) return rawItems
    const sorted = [...rawItems]
    sorted.sort((a, b) => {
      let aVal: string | number
      let bVal: string | number
      switch (sortKey) {
        case "name":
          aVal = (a.extensionNumber ?? a.mailboxNumber).toLowerCase()
          bVal = (b.extensionNumber ?? b.mailboxNumber).toLowerCase()
          break
        case "unread":
          aVal = a.unreadCount
          bVal = b.unreadCount
          break
        default:
          return 0
      }
      if (aVal < bVal) return sortDir === "asc" ? -1 : 1
      if (aVal > bVal) return sortDir === "asc" ? 1 : -1
      return 0
    })
    return sorted
  }, [rawItems, sortKey, sortDir])

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

  if (isError) {
    return (
      <EmptyState
        icon={AlertCircle}
        title="Unable to load voicemail boxes"
        description="Something went wrong. Please try again."
        action={
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            Try again
          </Button>
        }
      />
    )
  }

  return (
    <div className="space-y-4">
      {/* Search */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative max-w-sm flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search by extension or email..."
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

      {isLoading ? (
        <div className="space-y-3">
          <Skeleton className="h-4 w-32" />
          <div className="overflow-x-auto rounded-md border border-border/60 bg-card/80">
            <Table aria-label="Loading voicemail boxes">
              <TableHeader>
                <TableRow>
                  <TableHead>Extension</TableHead>
                  <TableHead>Email</TableHead>
                  <TableHead>Enabled</TableHead>
                  <TableHead>Transcription</TableHead>
                  <TableHead>Unread</TableHead>
                  <TableHead className="w-16 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {Array.from({ length: 6 }).map((_, i) => (
                  // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
                  <TableRow key={`skeleton-box-${i}`}>
                    <TableCell>
                      <Skeleton className="h-4 w-16" />
                    </TableCell>
                    <TableCell>
                      <Skeleton className="h-4 w-36" />
                    </TableCell>
                    <TableCell>
                      <Skeleton className="h-5 w-16 rounded-full" />
                    </TableCell>
                    <TableCell>
                      <Skeleton className="h-5 w-10 rounded-full" />
                    </TableCell>
                    <TableCell>
                      <Skeleton className="h-5 w-8" />
                    </TableCell>
                    <TableCell>
                      <Skeleton className="h-8 w-8 ml-auto" />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </div>
      ) : items.length === 0 ? (
        <EmptyState
          icon={Voicemail}
          title="No voicemail boxes"
          description={
            search
              ? "No voicemail boxes match your search."
              : "Voicemail boxes will appear here once configured on extensions."
          }
          action={
            search ? (
              <Button variant="outline" size="sm" onClick={() => setSearch("")}>
                Clear search
              </Button>
            ) : undefined
          }
        />
      ) : (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-xs text-muted-foreground">
              {data?.total ?? items.length} voicemail box
              {(data?.total ?? items.length) === 1 ? "" : "es"}
            </p>
            {totalPages > 1 && (
              <p className="text-xs text-muted-foreground">
                Page {page} of {totalPages}
              </p>
            )}
          </div>

          <div className="overflow-x-auto rounded-md border border-border/60 bg-card/80">
            <Table aria-label="Voicemail boxes">
              <TableHeader className="sticky top-0 z-10 bg-background">
                <TableRow>
                  <SortableHeader
                    label="Extension"
                    sortKey="name"
                    currentSort={sortKey}
                    currentDirection={sortDir}
                    onSort={handleSort}
                  />
                  <TableHead>Email</TableHead>
                  <TableHead>Enabled</TableHead>
                  <TableHead>Transcription</TableHead>
                  <SortableHeader
                    label="Unread"
                    sortKey="unread"
                    currentSort={sortKey}
                    currentDirection={sortDir}
                    onSort={handleSort}
                  />
                  <TableHead className="w-16 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((box) => (
                  <BoxRow key={box.id} box={box} />
                ))}
              </TableBody>
            </Table>
          </div>

          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="text-xs text-muted-foreground">Rows per page</span>
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
                  <kbd className="ml-1.5 hidden rounded border border-border bg-muted px-1 py-0.5 text-[10px] font-medium text-muted-foreground lg:inline">&larr;</kbd>
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
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
    </div>
  )
}

function BoxRow({ box }: { box: VoicemailBox }) {
  const navigate = useNavigate()
  const deleteBoxMutation = useDeleteVoicemailBox()
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)

  return (
    <>
      <TableRow
        className="cursor-pointer transition-colors hover:bg-muted/50"
        onClick={(e) => {
          const target = e.target as HTMLElement
          if (target.closest("[data-slot=dropdown]") || target.closest("button") || target.closest("a")) {
            return
          }
          navigate({ to: "/voicemail/$boxId", params: { boxId: box.id } })
        }}
      >
        <TableCell>
          <Link
            to="/voicemail/$boxId"
            params={{ boxId: box.id }}
            className="group flex flex-col gap-0.5"
            onClick={(e) => e.stopPropagation()}
          >
            <span className="font-mono font-medium group-hover:underline">
              {box.extensionNumber ?? box.mailboxNumber}
            </span>
          </Link>
        </TableCell>
        <TableCell>
          <span className="text-sm text-muted-foreground">{box.email ?? "---"}</span>
        </TableCell>
        <TableCell>
          {box.isEnabled ? (
            <Badge variant="default" className="text-xs">
              Enabled
            </Badge>
          ) : (
            <Badge variant="outline" className="text-xs">
              Disabled
            </Badge>
          )}
        </TableCell>
        <TableCell>
          {box.transcriptionEnabled ? (
            <Badge variant="secondary" className="text-xs">
              On
            </Badge>
          ) : (
            <Badge variant="outline" className="text-xs">
              Off
            </Badge>
          )}
        </TableCell>
        <TableCell>
          {box.unreadCount > 0 ? (
            <Badge variant="secondary" className="gap-1">
              <Mail className="h-3 w-3" />
              {box.unreadCount}
            </Badge>
          ) : (
            <span className="text-xs text-muted-foreground">0</span>
          )}
        </TableCell>
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
                <span className="sr-only">Actions for {box.extensionNumber ?? box.mailboxNumber}</span>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem asChild>
                <Link to="/voicemail/$boxId" params={{ boxId: box.id }}>
                  <Eye className="mr-2 h-4 w-4" />
                  View details
                </Link>
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                variant="destructive"
                onClick={() => setShowDeleteConfirm(true)}
              >
                <Trash2 className="mr-2 h-4 w-4" />
                Delete
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </TableCell>
      </TableRow>

      <AlertDialog open={showDeleteConfirm} onOpenChange={setShowDeleteConfirm}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2 text-destructive">
              <AlertTriangle className="size-5" />
              Delete voicemail box
            </AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete the voicemail box for{" "}
              <span className="font-medium text-foreground">
                {box.extensionNumber ?? box.mailboxNumber}
              </span>
              {" "}and all associated messages. This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteBoxMutation.isPending}>
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={() => deleteBoxMutation.mutate(box.id, {
                onSuccess: () => setShowDeleteConfirm(false),
              })}
              disabled={deleteBoxMutation.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteBoxMutation.isPending ? (
                <>
                  <Loader2 className="mr-1 size-4 animate-spin" />
                  Deleting...
                </>
              ) : (
                <>
                  <Trash2 className="mr-1 size-4" />
                  Delete
                </>
              )}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
