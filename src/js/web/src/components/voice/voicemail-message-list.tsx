import { AlertCircle, AlertTriangle, Filter, Inbox, Loader2, Mail, MailOpen, Search, Trash2, X } from "lucide-react"
import { useCallback, useMemo, useState } from "react"
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
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { SkeletonTable } from "@/components/ui/skeleton"
import { nextSortDirection, SortableHeader, type SortDirection } from "@/components/ui/sortable-header"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { VoicemailPlayer } from "@/components/voice/voicemail-player"
import {
  useBulkDeleteVoicemailMessages,
  useBulkMarkVoicemailRead,
  useDeleteVoicemailMessage,
  useMarkVoicemailRead,
  useVoicemailMessages,
  type VoicemailMessage,
} from "@/lib/api/hooks/voice"
import { formatDateTime, formatFullDateTime } from "@/lib/date-utils"
import { formatDuration } from "@/lib/format-utils"
import { useDebouncedValue } from "@/hooks/use-debounced-value"

const PAGE_SIZE = 15

interface VoicemailMessageListProps {
  extensionId: string
}

export function VoicemailMessageList({ extensionId }: VoicemailMessageListProps) {
  const [page, setPage] = useState(1)
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [bulkDeleteOpen, setBulkDeleteOpen] = useState(false)
  const [singleDeleteId, setSingleDeleteId] = useState<string | null>(null)

  // Search state
  const [search, setSearch] = useState("")
  const debouncedSearch = useDebouncedValue(search)

  // Sort state
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<SortDirection>(null)

  // Filter state
  const [unreadOnly, setUnreadOnly] = useState(false)

  const { data, isLoading, isError, refetch } = useVoicemailMessages(extensionId, page, PAGE_SIZE)
  const deleteMutation = useDeleteVoicemailMessage(extensionId)
  const markReadMutation = useMarkVoicemailRead(extensionId)
  const bulkMarkReadMutation = useBulkMarkVoicemailRead(extensionId)
  const bulkDeleteMutation = useBulkDeleteVoicemailMessages(extensionId)

  // Client-side filtering
  const filteredItems = useMemo(() => {
    let items = data?.items ?? []

    // Filter by unread
    if (unreadOnly) {
      items = items.filter((m) => !m.isRead)
    }

    // Filter by search
    if (debouncedSearch) {
      const q = debouncedSearch.toLowerCase()
      items = items.filter(
        (m) =>
          (m.callerName && m.callerName.toLowerCase().includes(q)) ||
          m.callerNumber.toLowerCase().includes(q),
      )
    }

    return items
  }, [data?.items, debouncedSearch, unreadOnly])

  // Client-side sorting
  const sortedItems = useMemo(() => {
    if (!sortKey || !sortDir) return filteredItems

    const sorted = [...filteredItems]
    sorted.sort((a, b) => {
      let cmp = 0
      switch (sortKey) {
        case "caller": {
          const aVal = (a.callerName ?? a.callerNumber).toLowerCase()
          const bVal = (b.callerName ?? b.callerNumber).toLowerCase()
          cmp = aVal.localeCompare(bVal)
          break
        }
        case "duration":
          cmp = a.durationSeconds - b.durationSeconds
          break
        case "received":
          cmp = new Date(a.receivedAt).getTime() - new Date(b.receivedAt).getTime()
          break
      }
      return sortDir === "desc" ? -cmp : cmp
    })
    return sorted
  }, [filteredItems, sortKey, sortDir])

  // Sort handler
  const handleSort = useCallback(
    (key: string) => {
      const next = nextSortDirection(sortKey, sortDir, key)
      setSortKey(next.sort)
      setSortDir(next.direction)
    },
    [sortKey, sortDir],
  )

  // Selection helpers
  const allVisibleIds = useMemo(() => sortedItems.map((m) => m.id), [sortedItems])
  const allSelected = sortedItems.length > 0 && sortedItems.every((m) => selectedIds.has(m.id))
  const someSelected = sortedItems.some((m) => selectedIds.has(m.id))

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

  if (isLoading) return <SkeletonTable rows={5} />

  if (isError || !data) {
    return (
      <EmptyState
        icon={AlertCircle}
        title="Unable to load voicemail messages"
        description="Something went wrong. Please try again."
        action={<Button variant="outline" size="sm" onClick={() => refetch()}>Try again</Button>}
      />
    )
  }

  const totalPages = Math.max(1, Math.ceil(data.total / PAGE_SIZE))
  const totalCount = data.items.length
  const unreadCount = data.items.filter((m) => !m.isRead).length
  const displayCount = sortedItems.length
  const hasAnyMessages = data.items.length > 0
  const isFiltered = !!debouncedSearch || unreadOnly
  const selectedCount = selectedIds.size

  function handleBulkMarkRead() {
    const ids = Array.from(selectedIds)
    bulkMarkReadMutation.mutate(ids, {
      onSuccess: () => setSelectedIds(new Set()),
    })
  }

  function handleBulkMarkUnread() {
    const ids = Array.from(selectedIds)
    // Use individual mutations for mark-as-unread since the bulk hook only marks as read
    Promise.all(
      ids.map((messageId) => markReadMutation.mutateAsync({ messageId, isRead: false })),
    ).then(() => setSelectedIds(new Set()))
  }

  function handleBulkDeleteConfirm() {
    const ids = Array.from(selectedIds)
    bulkDeleteMutation.mutate(ids, {
      onSuccess: () => {
        setSelectedIds(new Set())
        setBulkDeleteOpen(false)
        if (expandedId && ids.includes(expandedId)) setExpandedId(null)
      },
    })
  }

  function handleDeleteConfirm() {
    if (!singleDeleteId) return
    const messageId = singleDeleteId
    deleteMutation.mutate(messageId, {
      onSuccess: () => {
        setSingleDeleteId(null)
        if (expandedId === messageId) setExpandedId(null)
        setSelectedIds((prev) => {
          const next = new Set(prev)
          next.delete(messageId)
          return next
        })
      },
    })
  }

  function handleToggleRead(message: VoicemailMessage) {
    markReadMutation.mutate({ messageId: message.id, isRead: !message.isRead })
  }

  function handleExpand(message: VoicemailMessage) {
    if (expandedId === message.id) {
      setExpandedId(null)
    } else {
      setExpandedId(message.id)
      if (!message.isRead) {
        markReadMutation.mutate({ messageId: message.id, isRead: true })
      }
    }
  }

  if (!hasAnyMessages) {
    return (
      <EmptyState
        icon={Inbox}
        title="No voicemail messages"
        description="When callers leave a voicemail for this extension, their messages will appear here. You can listen, read transcriptions, and manage messages."
      />
    )
  }

  return (
    <Card>
      <CardHeader className="flex flex-col gap-4">
        {/* Title row */}
        <div className="flex flex-row items-center justify-between">
          <div className="flex items-center gap-3">
            <CardTitle>Messages ({data.total})</CardTitle>
            {unreadCount > 0 && (
              <Badge variant="secondary">{unreadCount} unread</Badge>
            )}
          </div>
        </div>

        {/* Search and filter row */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative max-w-sm flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search by caller name or number..."
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
          <Button
            variant={unreadOnly ? "default" : "outline"}
            size="sm"
            onClick={() => {
              setUnreadOnly((prev) => !prev)
              setSelectedIds(new Set())
            }}
          >
            <Filter className="mr-1 h-4 w-4" />
            {unreadOnly ? "Unread only" : "All messages"}
          </Button>
        </div>

        {/* Bulk action bar */}
        {someSelected && (
          <div className="flex items-center gap-2 rounded-md border border-border/60 bg-muted/30 px-3 py-2">
            <Badge variant="outline">{selectedCount} selected</Badge>
            <div className="ml-auto flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={handleBulkMarkRead}
                disabled={bulkMarkReadMutation.isPending}
              >
                <MailOpen className="mr-1 h-4 w-4" />
                Mark as read
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={handleBulkMarkUnread}
                disabled={markReadMutation.isPending}
              >
                <Mail className="mr-1 h-4 w-4" />
                Mark as unread
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setBulkDeleteOpen(true)}
                disabled={bulkDeleteMutation.isPending}
              >
                <Trash2 className="mr-1 h-4 w-4" />
                Delete selected
              </Button>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setSelectedIds(new Set())}
              >
                <X className="mr-1 h-3.5 w-3.5" />
                Clear
              </Button>
            </div>
          </div>
        )}
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Result count */}
        <p className="text-sm text-muted-foreground">
          Showing {displayCount} of {totalCount} message{totalCount === 1 ? "" : "s"}
          {isFiltered && " (filtered)"}
        </p>

        {displayCount === 0 && isFiltered ? (
          <EmptyState
            icon={Search}
            variant="no-results"
            title="No matching messages"
            description={
              debouncedSearch
                ? `No messages match "${debouncedSearch}". Try a different search term.`
                : "No unread messages found."
            }
            action={
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setSearch("")
                  setUnreadOnly(false)
                }}
              >
                Clear filters
              </Button>
            }
          />
        ) : (
          <>
            <div className="overflow-x-auto">
              <Table aria-label="Voicemail messages">
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-10">
                      <Checkbox
                        checked={allSelected}
                        indeterminate={someSelected && !allSelected}
                        onChange={toggleAll}
                        aria-label="Select all messages"
                      />
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
                      label="Received"
                      sortKey="received"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <TableHead>Transcription</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {sortedItems.map((msg, index) => (
                    <MessageRow
                      key={msg.id}
                      message={msg}
                      isExpanded={expandedId === msg.id}
                      isSelected={selectedIds.has(msg.id)}
                      isEvenRow={index % 2 === 0}
                      onExpand={() => handleExpand(msg)}
                      onDelete={() => setSingleDeleteId(msg.id)}
                      onToggleRead={() => handleToggleRead(msg)}
                      onToggleSelect={() => toggleOne(msg.id)}
                    />
                  ))}
                </TableBody>
              </Table>
            </div>

            {totalPages > 1 && (
              <div className="flex items-center justify-between">
                <p className="text-sm text-muted-foreground">
                  Page {page} of {totalPages}
                </p>
                <div className="flex items-center gap-2">
                  <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page <= 1}>
                    Previous
                  </Button>
                  <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page >= totalPages}>
                    Next
                  </Button>
                </div>
              </div>
            )}
          </>
        )}
      </CardContent>

      {/* Bulk delete confirmation */}
      <AlertDialog open={bulkDeleteOpen} onOpenChange={(open) => { if (!bulkDeleteMutation.isPending) setBulkDeleteOpen(open) }}>
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
            <AlertDialogCancel disabled={bulkDeleteMutation.isPending}>Cancel</AlertDialogCancel>
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
                  Delete {selectedIds.size} {selectedIds.size === 1 ? "message" : "messages"}
                </>
              )}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Single delete confirmation */}
      <AlertDialog open={singleDeleteId !== null} onOpenChange={(open) => { if (!open && !deleteMutation.isPending) setSingleDeleteId(null) }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2 text-destructive">
              <AlertTriangle className="size-5" />
              Delete voicemail
            </AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete this voicemail message. This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteMutation.isPending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDeleteConfirm}
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
    </Card>
  )
}

interface MessageRowProps {
  message: VoicemailMessage
  isExpanded: boolean
  isSelected: boolean
  isEvenRow: boolean
  onExpand: () => void
  onDelete: () => void
  onToggleRead: () => void
  onToggleSelect: () => void
}

function MessageRow({ message, isExpanded, isSelected, isEvenRow, onExpand, onDelete, onToggleRead, onToggleSelect }: MessageRowProps) {
  const callerDisplay = message.callerName ?? message.callerNumber
  const transcriptionPreview = message.transcription
    ? message.transcription.length > 60
      ? `${message.transcription.slice(0, 60)}...`
      : message.transcription
    : null

  return (
    <>
      <TableRow
        className={`cursor-pointer transition-colors hover:bg-muted/50 ${isEvenRow ? "bg-muted/20" : ""} ${!message.isRead ? "bg-primary/5 font-medium" : ""} ${isSelected ? "bg-primary/10" : ""}`}
        onClick={onExpand}
      >
        <TableCell>
          <Checkbox
            checked={isSelected}
            onChange={(e) => {
              e.stopPropagation()
              onToggleSelect()
            }}
            onClick={(e) => e.stopPropagation()}
            aria-label={`Select message from ${callerDisplay}`}
          />
        </TableCell>
        <TableCell>
          <div className="flex items-center gap-1">
            {!message.isRead && <div className="h-2.5 w-2.5 animate-pulse rounded-full bg-primary" />}
            {message.isUrgent && <AlertTriangle className="h-3.5 w-3.5 text-destructive" />}
          </div>
        </TableCell>
        <TableCell>
          <div>
            <span className={!message.isRead ? "font-semibold" : ""}>{callerDisplay}</span>
            {message.callerName && (
              <p className="font-mono text-xs text-muted-foreground">{message.callerNumber}</p>
            )}
          </div>
        </TableCell>
        <TableCell className="tabular-nums">{formatDuration(message.durationSeconds)}</TableCell>
        <TableCell>
          <div className="flex items-center gap-2">
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <span className="text-sm">{formatDateTime(message.receivedAt)}</span>
                </TooltipTrigger>
                <TooltipContent>
                  <p>{formatFullDateTime(message.receivedAt)}</p>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
            {message.isUrgent && <Badge variant="destructive" className="text-xs">Urgent</Badge>}
          </div>
        </TableCell>
        <TableCell className="max-w-xs text-sm text-muted-foreground">
          {transcriptionPreview ? (
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <span className="block truncate">{transcriptionPreview}</span>
                </TooltipTrigger>
                <TooltipContent side="top" className="max-w-sm">
                  <p>{transcriptionPreview}</p>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
          ) : (
            <span className="italic">No transcription</span>
          )}
        </TableCell>
        <TableCell className="text-right">
          <div className="flex items-center justify-end gap-1">
            <Button
              variant="ghost"
              size="sm"
              onClick={(e) => {
                e.stopPropagation()
                onToggleRead()
              }}
              title={message.isRead ? "Mark as unread" : "Mark as read"}
            >
              {message.isRead ? <MailOpen className="h-4 w-4" /> : <Mail className="h-4 w-4" />}
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={(e) => {
                e.stopPropagation()
                onDelete()
              }}
              aria-label="Delete message"
            >
              <Trash2 className="h-4 w-4" />
            </Button>
          </div>
        </TableCell>
      </TableRow>
      {isExpanded && (
        <TableRow>
          <TableCell colSpan={7} className="bg-muted/30 px-6 py-4">
            <div className="space-y-4">
              <VoicemailPlayer
                audioUrl={message.audioFilePath}
                durationSeconds={message.durationSeconds}
              />
              {message.transcription && (
                <div className="space-y-1">
                  <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Transcription</p>
                  <p className="text-sm leading-relaxed">{message.transcription}</p>
                </div>
              )}
            </div>
          </TableCell>
        </TableRow>
      )}
    </>
  )
}
