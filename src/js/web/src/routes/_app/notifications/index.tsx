import { useQueryClient } from "@tanstack/react-query"
import { createFileRoute } from "@tanstack/react-router"
import { AnimatePresence, motion } from "framer-motion"
import {
  AlertTriangle,
  Bell,
  BellOff,
  CheckCheck,
  ChevronLeft,
  ChevronRight,
  Download,
  Laptop,
  Loader2,
  Mail,
  MessageSquare,
  Phone,
  Printer,
  Search,
  Settings,
  Trash2,
  Users,
  X,
} from "lucide-react"
import { type PointerEvent as ReactPointerEvent, useCallback, useEffect, useMemo, useRef, useState } from "react"
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
import { type BulkAction, BulkActionBar, createBulkDeleteAction } from "@/components/ui/bulk-action-bar"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { Skeleton, SkeletonCard } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useDebouncedValue } from "@/hooks/use-debounced-value"
import { useDocumentTitle } from "@/hooks/use-document-title"
import {
  type NotificationItem,
  useDeleteAllRead,
  useDeleteNotification,
  useMarkAllRead,
  useMarkRead,
  useNotificationPreferences,
  useNotifications,
  useUnreadCount,
  useUpdateNotificationPreferences,
} from "@/lib/api/hooks/notifications"
import { type CsvHeader, exportToCsv } from "@/lib/csv-export"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"
import { cn } from "@/lib/utils"

export const Route = createFileRoute("/_app/notifications/")({
  validateSearch: (
    search: Record<string, unknown>,
  ): {
    q?: string
    page?: number
    category?: string
    read?: string
  } => ({
    q: typeof search.q === "string" && search.q ? search.q : undefined,
    page: Number(search.page) > 1 ? Number(search.page) : undefined,
    category:
      typeof search.category === "string" && search.category && search.category !== "all"
        ? search.category
        : undefined,
    read:
      typeof search.read === "string" && (search.read === "unread" || search.read === "read")
        ? search.read
        : undefined,
  }),
  component: NotificationsPage,
})

const CATEGORIES = [
  { value: "all", label: "All" },
  { value: "system", label: "System" },
  { value: "team", label: "Team" },
  { value: "ticket", label: "Ticket" },
  { value: "device", label: "Device" },
  { value: "voice", label: "Voice" },
  { value: "fax", label: "Fax" },
] as const

const PAGE_SIZES = [10, 25, 50, 100] as const
const DEFAULT_PAGE_SIZE = 20
const PAGE_SIZE_STORAGE_KEY = "notifications-page-size"

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

const READ_STATUS_OPTIONS = [
  { value: "all", label: "All status" },
  { value: "unread", label: "Unread only" },
  { value: "read", label: "Read only" },
] as const

type ReadStatusFilter = (typeof READ_STATUS_OPTIONS)[number]["value"]

const categoryIcons: Record<string, typeof Bell> = {
  ticket: MessageSquare,
  team: Users,
  device: Laptop,
  system: Settings,
  voice: Phone,
  fax: Printer,
}

function getCategoryIcon(category: string) {
  return categoryIcons[category] ?? Bell
}

function getCategoryColor(category: string) {
  switch (category) {
    case "ticket":
    case "support":
      return "text-blue-500"
    case "team":
    case "teams":
      return "text-purple-500"
    case "device":
    case "devices":
      return "text-green-500"
    case "system":
      return "text-orange-500"
    case "voice":
      return "text-cyan-500"
    case "fax":
      return "text-amber-500"
    default:
      return "text-muted-foreground"
  }
}

// Minimum horizontal drag distance (px) to trigger a swipe action
const SWIPE_THRESHOLD = 100
// Maximum vertical movement (px) allowed during a swipe before we cancel it
const SWIPE_VERTICAL_LIMIT = 30

function NotificationCard({
  notification,
  onRequestDelete,
  onMarkRead,
  selected,
  onToggleSelect,
}: {
  notification: NotificationItem
  onRequestDelete: (id: string) => void
  onMarkRead: (id: string) => void
  selected: boolean
  onToggleSelect: () => void
}) {
  const navigate = Route.useNavigate()

  const Icon = getCategoryIcon(notification.category)
  const colorClass = getCategoryColor(notification.category)

  // --- Swipe-to-dismiss state ---
  const cardRef = useRef<HTMLDivElement>(null)
  const [swipeX, setSwipeX] = useState(0)
  const [isSwiping, setIsSwiping] = useState(false)
  const pointerStart = useRef<{ x: number; y: number } | null>(null)

  const handlePointerDown = useCallback((e: ReactPointerEvent) => {
    // Only track single-finger touch or mouse
    if (e.pointerType === "mouse" && e.button !== 0) return
    pointerStart.current = { x: e.clientX, y: e.clientY }
  }, [])

  const handlePointerMove = useCallback((e: ReactPointerEvent) => {
    if (!pointerStart.current) return
    const dx = e.clientX - pointerStart.current.x
    const dy = e.clientY - pointerStart.current.y

    // If vertical movement exceeds limit, cancel the swipe gesture
    if (Math.abs(dy) > SWIPE_VERTICAL_LIMIT) {
      pointerStart.current = null
      setSwipeX(0)
      setIsSwiping(false)
      return
    }

    // Only start tracking after a small horizontal threshold to avoid accidental swipes
    if (Math.abs(dx) > 10) {
      setIsSwiping(true)
      // Dampen the swipe with a square-root curve so it feels elastic
      const dampenedDx = Math.sign(dx) * Math.min(Math.sqrt(Math.abs(dx)) * 8, 200)
      setSwipeX(dampenedDx)
    }
  }, [])

  const handlePointerUp = useCallback(() => {
    if (!pointerStart.current) return
    pointerStart.current = null

    if (Math.abs(swipeX) >= SWIPE_THRESHOLD) {
      if (swipeX < 0) {
        // Swipe left -> delete
        onRequestDelete(notification.id)
      } else {
        // Swipe right -> mark as read (or no-op if already read)
        if (!notification.isRead) {
          onMarkRead(notification.id)
        }
      }
    }

    setSwipeX(0)
    setIsSwiping(false)
  }, [swipeX, notification.id, notification.isRead, onRequestDelete, onMarkRead])

  const handlePointerCancel = useCallback(() => {
    pointerStart.current = null
    setSwipeX(0)
    setIsSwiping(false)
  }, [])

  const handleClick = () => {
    // Don't fire click if we were swiping
    if (isSwiping) return
    if (!notification.isRead) {
      onMarkRead(notification.id)
    }
    if (notification.actionUrl) {
      navigate({ to: notification.actionUrl as "/" })
    }
  }

  const relativeTime = formatRelativeTimeShort(notification.createdAt)

  // Determine which swipe action is being revealed
  const swipeDirection = swipeX < -30 ? "delete" : swipeX > 30 ? "mark-read" : null

  return (
    <div className="relative overflow-hidden rounded-xl">
      {/* Swipe action reveal layer (behind the card) */}
      {swipeDirection && (
        <div
          className={cn(
            "absolute inset-0 flex items-center rounded-xl px-6 text-sm font-medium text-white transition-colors",
            swipeDirection === "delete" ? "justify-end bg-destructive/90" : "justify-start bg-primary/90",
          )}
        >
          {swipeDirection === "delete" ? (
            <div className="flex items-center gap-2">
              <Trash2 className="h-4 w-4" />
              <span>Delete</span>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <CheckCheck className="h-4 w-4" />
              <span>{notification.isRead ? "Already read" : "Mark read"}</span>
            </div>
          )}
        </div>
      )}

      <Card
        ref={cardRef}
        hover
        className={cn(
          "group/card relative transition-all",
          // Left border accent for unread -- a solid primary bar
          !notification.isRead && "border-l-[3px] border-l-primary border-primary/20 bg-accent/30",
          notification.isRead && "opacity-75",
          notification.actionUrl && "cursor-pointer",
        )}
        style={swipeX !== 0 ? { transform: `translateX(${swipeX}px)`, transition: isSwiping ? "none" : "transform 0.3s ease-out" } : undefined}
        onClick={handleClick}
        onPointerDown={handlePointerDown}
        onPointerMove={handlePointerMove}
        onPointerUp={handlePointerUp}
        onPointerCancel={handlePointerCancel}
        role={notification.actionUrl ? "button" : undefined}
        tabIndex={notification.actionUrl ? 0 : undefined}
        onKeyDown={
          notification.actionUrl
            ? (e: React.KeyboardEvent) => {
                if (e.key === "Enter") handleClick()
              }
            : undefined
        }
      >
        <CardContent className="flex items-start gap-4 py-4">
          <div className="flex shrink-0 items-center pt-1">
            <Checkbox
              checked={selected}
              onChange={(e) => {
                e.stopPropagation()
                onToggleSelect()
              }}
              aria-label={`Select notification: ${notification.title}`}
            />
          </div>
          <div className={cn("flex h-10 w-10 shrink-0 items-center justify-center rounded-full transition-colors", !notification.isRead ? "bg-muted" : "bg-muted/60", colorClass)}>
            <Icon className="h-5 w-5" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <p className={cn("text-sm transition-colors", !notification.isRead ? "font-semibold text-foreground" : "font-medium text-muted-foreground")}>{notification.title}</p>
              {!notification.isRead && <span className="h-2 w-2 shrink-0 rounded-full bg-primary animate-pulse" />}
              <Badge variant="outline" className="ml-auto shrink-0 text-[0.6rem] capitalize">
                {notification.category}
              </Badge>
            </div>
            <p className={cn("mt-0.5 text-sm transition-colors", !notification.isRead ? "text-muted-foreground" : "text-muted-foreground/70")}>{notification.message}</p>
            <Tooltip>
              <TooltipTrigger asChild>
                <p className="mt-1 cursor-default text-xs text-muted-foreground/70">{relativeTime}</p>
              </TooltipTrigger>
              <TooltipContent>{formatDateTime(notification.createdAt)}</TooltipContent>
            </Tooltip>
          </div>
          {notification.actionUrl && <ChevronRight className="mt-1 h-4 w-4 shrink-0 text-muted-foreground/0 transition-colors group-hover/card:text-muted-foreground" />}
          <div className="flex shrink-0 items-center gap-1">
            {!notification.isRead && (
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8 text-muted-foreground hover:text-foreground"
                onClick={(e) => {
                  e.stopPropagation()
                  onMarkRead(notification.id)
                }}
                title="Mark as read"
                aria-label="Mark as read"
              >
                <CheckCheck className="h-4 w-4" />
              </Button>
            )}
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8 text-muted-foreground hover:text-destructive"
              onClick={(e) => {
                e.stopPropagation()
                onRequestDelete(notification.id)
              }}
              title="Delete"
              aria-label="Delete notification"
            >
              <Trash2 className="h-4 w-4" />
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

const PREFERENCE_CATEGORIES = [
  { key: "system", label: "System", description: "System alerts and maintenance updates", icon: Settings },
  { key: "teams", label: "Teams", description: "Team invitations and membership changes", icon: Users },
  { key: "support", label: "Support", description: "Support ticket updates and replies", icon: MessageSquare },
  { key: "devices", label: "Devices", description: "Device status and provisioning alerts", icon: Laptop },
  { key: "voice", label: "Voice", description: "Call routing and voicemail notifications", icon: Phone },
  { key: "fax", label: "Fax", description: "Inbound and outbound fax notifications", icon: Printer },
] as const

function NotificationPreferences() {
  const { data: prefs, isLoading } = useNotificationPreferences()
  const updatePrefs = useUpdateNotificationPreferences()

  if (isLoading) {
    return <SkeletonCard />
  }

  if (!prefs) return null

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <Settings className="h-5 w-5 text-muted-foreground" />
          <div>
            <CardTitle className="text-lg">Notification Preferences</CardTitle>
            <CardDescription>Choose how and when you receive notifications</CardDescription>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="flex items-center justify-between rounded-lg border p-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-full bg-primary/10">
              <Mail className="h-4 w-4 text-primary" />
            </div>
            <div>
              <Label htmlFor="email-toggle" className="text-sm font-medium">
                Email Notifications
              </Label>
              <p className="text-xs text-muted-foreground">Receive notification summaries via email</p>
            </div>
          </div>
          <Switch id="email-toggle" checked={prefs.emailEnabled} onCheckedChange={(checked) => updatePrefs.mutate({ emailEnabled: checked })} />
        </div>

        <Separator />

        <div className="space-y-1">
          <h4 className="text-sm font-medium">Category Preferences</h4>
          <p className="text-xs text-muted-foreground">Enable or disable notifications by category</p>
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          {PREFERENCE_CATEGORIES.map(({ key, label, description, icon: Icon }) => (
            <div key={key} className="flex items-center justify-between rounded-lg border p-3 transition-colors hover:bg-accent/50">
              <div className="flex items-center gap-3">
                <div className={cn("flex h-8 w-8 items-center justify-center rounded-full bg-muted", getCategoryColor(key))}>
                  <Icon className="h-4 w-4" />
                </div>
                <div>
                  <Label htmlFor={`cat-${key}`} className="text-sm font-medium">
                    {label}
                  </Label>
                  <p className="text-xs text-muted-foreground">{description}</p>
                </div>
              </div>
              <Switch id={`cat-${key}`} checked={prefs.categories[key] ?? true} onCheckedChange={(checked) => updatePrefs.mutate({ categories: { [key]: checked } })} />
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}

function NotificationsPage() {
  useDocumentTitle("Notifications")
  const queryClient = useQueryClient()
  const searchInputRef = useRef<HTMLInputElement>(null)

  const {
    q: searchParam,
    page: pageParam,
    category: categoryParam,
    read: readParam,
  } = Route.useSearch()
  const navigate = Route.useNavigate()

  // Derive filter state from URL search params
  const search = searchParam ?? ""
  const page = pageParam ?? 1
  const activeCategory = categoryParam ?? "all"
  const readStatusFilter: ReadStatusFilter = (readParam as ReadStatusFilter) ?? "all"

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

  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false)
  const [deleteId, setDeleteId] = useState<string | null>(null)
  const [pageSize, setPageSize] = useState(getStoredPageSize)

  // Selection state
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())

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

  // Keyboard shortcut: "/" to focus search
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement
      if (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable) return
      if (e.key === "/" && !e.ctrlKey && !e.metaKey) {
        e.preventDefault()
        searchInputRef.current?.focus()
      }
    }
    document.addEventListener("keydown", handleKeyDown)
    return () => document.removeEventListener("keydown", handleKeyDown)
  }, [])

  const { data: unreadData } = useUnreadCount()
  const { data, isLoading } = useNotifications(page, pageSize)
  const markAllRead = useMarkAllRead()
  const markRead = useMarkRead()
  const deleteAllRead = useDeleteAllRead()
  const deleteNotification = useDeleteNotification()

  const unreadCount = unreadData?.count ?? 0
  const notifications = data?.items ?? []
  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  const readCount = notifications.filter((n) => n.isRead).length

  const filteredNotifications = useMemo(() => {
    return notifications.filter((n) => {
      if (activeCategory !== "all" && n.category !== activeCategory) return false
      if (readStatusFilter === "unread" && n.isRead) return false
      if (readStatusFilter === "read" && !n.isRead) return false
      if (debouncedSearch) {
        const query = debouncedSearch.toLowerCase()
        if (!n.title.toLowerCase().includes(query) && !n.message.toLowerCase().includes(query)) return false
      }
      return true
    })
  }, [notifications, activeCategory, readStatusFilter, debouncedSearch])

  const categoryCounts = notifications.reduce<Record<string, number>>((acc, n) => {
    acc[n.category] = (acc[n.category] ?? 0) + 1
    return acc
  }, {})

  // CSV export
  const csvHeaders = useMemo<CsvHeader<NotificationItem>[]>(
    () => [
      { label: "Title", accessor: (n) => n.title },
      { label: "Category", accessor: (n) => n.category },
      { label: "Message", accessor: (n) => n.message },
      { label: "Status", accessor: (n) => (n.isRead ? "Read" : "Unread") },
      { label: "Date", accessor: (n) => formatDateTime(n.createdAt) },
    ],
    [],
  )

  const handleExport = useCallback(() => {
    if (!filteredNotifications.length) return
    exportToCsv("notifications", csvHeaders, filteredNotifications)
  }, [filteredNotifications, csvHeaders])

  // Selection helpers
  const allVisibleIds = useMemo(() => filteredNotifications.map((n) => n.id), [filteredNotifications])
  const allSelected = filteredNotifications.length > 0 && filteredNotifications.every((n) => selectedIds.has(n.id))
  const someSelected = filteredNotifications.some((n) => selectedIds.has(n.id))

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

  // Bulk actions
  const bulkActions = useMemo<BulkAction[]>(
    () => [
      {
        key: "mark-read",
        label: "Mark as Read",
        icon: <CheckCheck className="h-4 w-4" />,
        variant: "outline",
        onExecute: async (ids) => {
          const errors: string[] = []
          for (const id of ids) {
            try {
              await markRead.mutateAsync(id)
            } catch {
              errors.push(id)
            }
          }
          queryClient.invalidateQueries({ queryKey: ["notifications"] })
          if (errors.length > 0) {
            const { toast } = await import("sonner")
            toast.error(`Failed to mark ${errors.length} of ${ids.length} as read`)
          } else {
            const { toast } = await import("sonner")
            toast.success(`Marked ${ids.length} notification${ids.length === 1 ? "" : "s"} as read`)
          }
        },
      },
      createBulkDeleteAction(
        async (id) => {
          await deleteNotification.mutateAsync(id)
        },
        () => {
          queryClient.invalidateQueries({ queryKey: ["notifications"] })
        },
      ),
    ],
    [markRead, deleteNotification, queryClient],
  )

  // Stable callback for marking a single notification as read (used by card click + swipe)
  const handleMarkRead = useCallback(
    (id: string) => {
      markRead.mutate(id)
    },
    [markRead],
  )

  const hasAnyNotifications = total > 0
  const hasActiveFilters = activeCategory !== "all" || readStatusFilter !== "all" || !!debouncedSearch
  const isEmptyUnfiltered = !isLoading && !hasAnyNotifications
  const isEmptyFiltered = !isLoading && hasAnyNotifications && filteredNotifications.length === 0

  return (
    <PageContainer>
      <PageHeader
        eyebrow="Account"
        title="Notifications"
        description={unreadCount > 0 ? `You have ${unreadCount} unread notification${unreadCount !== 1 ? "s" : ""}` : "You're all caught up"}
        actions={
          <div className="flex gap-2">
            <Tooltip>
              <TooltipTrigger asChild>
                <Button variant="outline" size="icon" onClick={handleExport} disabled={filteredNotifications.length === 0} aria-label="Export notifications to CSV">
                  <Download className="h-4 w-4" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Export to CSV</TooltipContent>
            </Tooltip>
            {readCount > 0 && (
              <Button variant="outline" size="sm" onClick={() => setDeleteConfirmOpen(true)} disabled={deleteAllRead.isPending} className="text-destructive hover:text-destructive">
                <Trash2 className="mr-2 h-4 w-4" />
                Delete all read
              </Button>
            )}
            {unreadCount > 0 && (
              <Button variant="outline" size="sm" onClick={() => markAllRead.mutate()} disabled={markAllRead.isPending}>
                <CheckCheck className="mr-2 h-4 w-4" />
                Mark all as read
              </Button>
            )}
          </div>
        }
      />

      <PageSection delay={0.1}>
        {isEmptyUnfiltered ? (
          <EmptyState
            icon={BellOff}
            title="No notifications yet"
            description="You'll see notifications here when events happen — like team updates, device alerts, or support ticket replies."
          />
        ) : (
          <>
            {/* Search & filters */}
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-3">
                <div className="relative max-w-sm flex-1">
                  <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                  <Input ref={searchInputRef} placeholder="Search notifications..." value={searchInput} onChange={(e) => setSearchInput(e.target.value)} className="pl-9 pr-8" />
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
                <Select
                  value={readStatusFilter}
                  onValueChange={(v) =>
                    navigate({
                      search: (prev) => ({
                        ...prev,
                        read: v !== "all" ? v : undefined,
                        page: undefined,
                      }),
                    })
                  }
                >
                  <SelectTrigger className="w-[150px]" aria-label="Filter by read status">
                    <SelectValue placeholder="All status" />
                  </SelectTrigger>
                  <SelectContent>
                    {READ_STATUS_OPTIONS.map((opt) => (
                      <SelectItem key={opt.value} value={opt.value}>
                        {opt.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {hasActiveFilters && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-xs text-muted-foreground"
                    onClick={() => {
                      setSearchInput("")
                      navigate({
                        search: {
                          q: undefined,
                          category: undefined,
                          read: undefined,
                          page: undefined,
                        },
                      })
                    }}
                  >
                    Clear all filters
                  </Button>
                )}
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <Checkbox checked={allSelected} indeterminate={someSelected && !allSelected} onChange={toggleAll} aria-label="Select all notifications" />
                {CATEGORIES.map(({ value, label }) => {
                  const count = value === "all" ? notifications.length : (categoryCounts[value] ?? 0)
                  const isActive = activeCategory === value
                  return (
                    <Button
                      key={value}
                      variant={isActive ? "default" : "outline"}
                      size="sm"
                      onClick={() =>
                        navigate({
                          search: (prev) => ({
                            ...prev,
                            category: value !== "all" ? value : undefined,
                            page: undefined,
                          }),
                        })
                      }
                      className="gap-1.5 text-xs"
                    >
                      {label}
                      {count > 0 && (
                        <Badge
                          variant={isActive ? "secondary" : "outline"}
                          className={cn("ml-0.5 h-5 min-w-5 justify-center px-1.5 text-[0.6rem]", isActive && "bg-primary-foreground/20 text-primary-foreground")}
                        >
                          {count}
                        </Badge>
                      )}
                    </Button>
                  )
                })}
              </div>
            </div>

            <div className="sr-only" aria-live="polite" aria-atomic="true">
              {!isLoading && `Showing ${filteredNotifications.length} of ${total} notifications, page ${page}`}
            </div>

            <div className="mt-4 space-y-3" aria-busy={isLoading}>
              {isLoading ? (
                <div className="space-y-3">
                  {Array.from({ length: 5 }).map((_, i) => (
                    <Skeleton key={i} className="h-16 w-full rounded-lg" />
                  ))}
                </div>
              ) : isEmptyFiltered ? (
                <EmptyState
                  icon={BellOff}
                  title="No notifications match your filters"
                  description="Try adjusting your search or filter criteria to find what you're looking for."
                  variant="no-results"
                  action={
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        setSearchInput("")
                        navigate({
                          search: {
                            q: undefined,
                            category: undefined,
                            read: undefined,
                            page: undefined,
                          },
                        })
                      }}
                    >
                      Clear filters
                    </Button>
                  }
                />
              ) : (
                <AnimatePresence mode="popLayout" initial={false}>
                  {filteredNotifications.map((notification) => (
                    <motion.div
                      key={notification.id}
                      layout
                      initial={{ opacity: 0, y: -8 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, x: -40, transition: { duration: 0.2 } }}
                      transition={{ duration: 0.2 }}
                    >
                      <NotificationCard
                        notification={notification}
                        onRequestDelete={setDeleteId}
                        onMarkRead={handleMarkRead}
                        selected={selectedIds.has(notification.id)}
                        onToggleSelect={() => toggleOne(notification.id)}
                      />
                    </motion.div>
                  ))}
                </AnimatePresence>
              )}
            </div>

            <div className="mt-6 flex items-center justify-center gap-4">
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
                <>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={page <= 1}
                    onClick={() =>
                      navigate({
                        search: (prev) => ({
                          ...prev,
                          page: page - 1 > 1 ? page - 1 : undefined,
                        }),
                      })
                    }
                  >
                    <ChevronLeft className="mr-1 h-4 w-4" />
                    Previous
                  </Button>
                  <span className="text-sm text-muted-foreground">
                    Page {page} of {totalPages}
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={page >= totalPages}
                    onClick={() =>
                      navigate({
                        search: (prev) => ({ ...prev, page: page + 1 }),
                      })
                    }
                  >
                    Next
                    <ChevronRight className="ml-1 h-4 w-4" />
                  </Button>
                </>
              )}
            </div>
          </>
        )}
      </PageSection>

      <PageSection delay={0.2}>
        <NotificationPreferences />
      </PageSection>

      <AlertDialog open={deleteConfirmOpen} onOpenChange={setDeleteConfirmOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-full bg-destructive/10">
                <AlertTriangle className="h-5 w-5 text-destructive" />
              </div>
              <AlertDialogTitle>Delete all read notifications</AlertDialogTitle>
            </div>
            <AlertDialogDescription>
              This will permanently delete {readCount} read notification{readCount !== 1 ? "s" : ""}. This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setDeleteConfirmOpen(false)} disabled={deleteAllRead.isPending}>
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                deleteAllRead.mutate(undefined, {
                  onSuccess: () => setDeleteConfirmOpen(false),
                })
              }}
              disabled={deleteAllRead.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteAllRead.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Delete {readCount} notification{readCount !== 1 ? "s" : ""}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Delete single notification confirmation */}
      <AlertDialog open={!!deleteId} onOpenChange={(open) => !open && setDeleteId(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete notification</AlertDialogTitle>
            <AlertDialogDescription>Are you sure you want to delete this notification? This action cannot be undone.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setDeleteId(null)} disabled={deleteNotification.isPending}>
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (!deleteId) return
                deleteNotification.mutate(deleteId, {
                  onSuccess: () => setDeleteId(null),
                })
              }}
              disabled={deleteNotification.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteNotification.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Bulk action bar */}
      <BulkActionBar selectedCount={selectedIds.size} selectedIds={Array.from(selectedIds)} onClearSelection={() => setSelectedIds(new Set())} actions={bulkActions} />
    </PageContainer>
  )
}
