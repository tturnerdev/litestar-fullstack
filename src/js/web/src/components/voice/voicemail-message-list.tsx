import { AlertTriangle, CheckSquare, Inbox, Loader2, Mail, MailOpen, Square, Trash2 } from "lucide-react"
import { useState } from "react"
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
import { EmptyState } from "@/components/ui/empty-state"
import { SkeletonTable } from "@/components/ui/skeleton"
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
import { formatFullDateTime } from "@/lib/date-utils"

const PAGE_SIZE = 15

function formatDuration(seconds: number): string {
  const mins = Math.floor(seconds / 60)
  const secs = seconds % 60
  return `${mins}:${secs.toString().padStart(2, "0")}`
}

function formatReceivedAt(dateStr: string): string {
  const date = new Date(dateStr)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffHours = diffMs / (1000 * 60 * 60)

  if (diffHours < 1) {
    const mins = Math.floor(diffMs / (1000 * 60))
    return `${mins}m ago`
  }
  if (diffHours < 24) {
    return `${Math.floor(diffHours)}h ago`
  }

  return date.toLocaleDateString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" })
}

interface VoicemailMessageListProps {
  extensionId: string
}

export function VoicemailMessageList({ extensionId }: VoicemailMessageListProps) {
  const [page, setPage] = useState(1)
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [bulkDeleteOpen, setBulkDeleteOpen] = useState(false)
  const [singleDeleteId, setSingleDeleteId] = useState<string | null>(null)
  const { data, isLoading, isError } = useVoicemailMessages(extensionId, page, PAGE_SIZE)
  const deleteMutation = useDeleteVoicemailMessage(extensionId)
  const markReadMutation = useMarkVoicemailRead(extensionId)
  const bulkMarkReadMutation = useBulkMarkVoicemailRead(extensionId)
  const bulkDeleteMutation = useBulkDeleteVoicemailMessages(extensionId)

  if (isLoading) return <SkeletonTable rows={5} />

  if (isError || !data) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Voicemail Messages</CardTitle>
        </CardHeader>
        <CardContent className="text-muted-foreground">Unable to load voicemail messages.</CardContent>
      </Card>
    )
  }

  const totalPages = Math.max(1, Math.ceil(data.total / PAGE_SIZE))
  const unreadCount = data.items.filter((m) => !m.isRead).length
  const allSelected = data.items.length > 0 && selectedIds.size === data.items.length
  const someSelected = selectedIds.size > 0

  function toggleSelectAll() {
    if (allSelected) {
      setSelectedIds(new Set())
    } else {
      setSelectedIds(new Set(data?.items.map((m) => m.id) ?? []))
    }
  }

  function toggleSelect(id: string) {
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) {
        next.delete(id)
      } else {
        next.add(id)
      }
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

  if (data.items.length === 0) {
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
      <CardHeader className="flex flex-row items-center justify-between">
        <div className="flex items-center gap-3">
          <CardTitle>Messages ({data.total})</CardTitle>
          {unreadCount > 0 && (
            <Badge variant="secondary">{unreadCount} unread</Badge>
          )}
          {someSelected && (
            <Badge variant="outline">{selectedIds.size} selected</Badge>
          )}
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={handleBulkMarkRead}
            disabled={!someSelected || bulkMarkReadMutation.isPending}
          >
            <MailOpen className="mr-1 h-4 w-4" />
            Mark read
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setBulkDeleteOpen(true)}
            disabled={!someSelected || bulkDeleteMutation.isPending}
          >
            <Trash2 className="mr-1 h-4 w-4" />
            Delete
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-10">
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-6 w-6 p-0"
                  onClick={toggleSelectAll}
                >
                  {allSelected ? <CheckSquare className="h-4 w-4" /> : <Square className="h-4 w-4" />}
                </Button>
              </TableHead>
              <TableHead className="w-10" />
              <TableHead>Caller</TableHead>
              <TableHead>Duration</TableHead>
              <TableHead>Received</TableHead>
              <TableHead>Transcription</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.items.map((msg, index) => (
              <MessageRow
                key={msg.id}
                message={msg}
                isExpanded={expandedId === msg.id}
                isSelected={selectedIds.has(msg.id)}
                isEvenRow={index % 2 === 0}
                onExpand={() => handleExpand(msg)}
                onDelete={() => setSingleDeleteId(msg.id)}
                onToggleRead={() => handleToggleRead(msg)}
                onToggleSelect={() => toggleSelect(msg.id)}
              />
            ))}
          </TableBody>
        </Table>

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
          <Button
            variant="ghost"
            size="sm"
            className="h-6 w-6 p-0"
            onClick={(e) => {
              e.stopPropagation()
              onToggleSelect()
            }}
          >
            {isSelected ? <CheckSquare className="h-4 w-4" /> : <Square className="h-4 w-4" />}
          </Button>
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
                  <span className="text-sm">{formatReceivedAt(message.receivedAt)}</span>
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
