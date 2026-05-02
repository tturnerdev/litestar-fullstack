import { createFileRoute, Link, useNavigate } from "@tanstack/react-router"
import { useQueryClient } from "@tanstack/react-query"
import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import {
  AlertCircle,
  ArrowDown,
  ArrowUp,
  Bookmark,
  CheckCircle,
  CheckCircle2,
  Download,
  Eye,
  Home,
  LifeBuoy,
  MoreVertical,
  Pencil,
  Plus,
  RotateCcw,
  Save,
  Search,
  Trash2,
  User,
  UserX,
  X,
} from "lucide-react"
import { toast } from "sonner"
import { DataFreshness } from "@/components/ui/data-freshness"
import { TicketPriorityBadge } from "@/components/support/ticket-priority-badge"
import { TicketStatusBadge } from "@/components/support/ticket-status-badge"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { Badge } from "@/components/ui/badge"
import { BulkActionBar, type BulkAction } from "@/components/ui/bulk-action-bar"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { DateRangeFilter, getPresetDates, isDateInRange } from "@/components/ui/date-range-filter"
import { EmptyState } from "@/components/ui/empty-state"
import { FilterDropdown, type FilterOption } from "@/components/ui/filter-dropdown"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { Skeleton, SkeletonTable } from "@/components/ui/skeleton"
import { nextSortDirection, SortableHeader, type SortDirection } from "@/components/ui/sortable-header"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useAuthStore } from "@/lib/auth"
import { type Ticket, useTickets } from "@/lib/api/hooks/support"
import { exportToCsv, type CsvHeader } from "@/lib/csv-export"
import { client } from "@/lib/generated/api/client.gen"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"
import { useDebouncedValue } from "@/hooks/use-debounced-value"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { cn } from "@/lib/utils"

export const Route = createFileRoute("/_app/support/")({
  component: SupportPage,
})

// ── Constants ────────────────────────────────────────────────────────────

const PAGE_SIZES = [10, 25, 50, 100] as const
const DEFAULT_PAGE_SIZE = 25
const PAGE_SIZE_STORAGE_KEY = "support-page-size"

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

const statusOptions: FilterOption[] = [
  { value: "open", label: "Open" },
  { value: "in_progress", label: "In Progress" },
  { value: "waiting_on_customer", label: "Waiting (Customer)" },
  { value: "waiting_on_support", label: "Waiting (Support)" },
  { value: "resolved", label: "Resolved" },
  { value: "closed", label: "Closed" },
]

const priorityOptions: FilterOption[] = [
  { value: "low", label: "Low" },
  { value: "medium", label: "Medium" },
  { value: "high", label: "High" },
  { value: "urgent", label: "Urgent" },
]

const categoryOptions: FilterOption[] = [
  { value: "general", label: "General" },
  { value: "billing", label: "Billing" },
  { value: "technical", label: "Technical" },
  { value: "account", label: "Account" },
  { value: "device", label: "Device" },
  { value: "voice", label: "Voice" },
  { value: "fax", label: "Fax" },
]

const csvHeaders: CsvHeader<Ticket>[] = [
  { label: "Ticket #", accessor: (t) => t.ticketNumber },
  { label: "Subject", accessor: (t) => t.subject },
  { label: "Status", accessor: (t) => t.status },
  { label: "Priority", accessor: (t) => t.priority },
  { label: "Category", accessor: (t) => t.category ?? "" },
  { label: "Created", accessor: (t) => (t.createdAt ? formatDateTime(t.createdAt) : "") },
  { label: "Updated", accessor: (t) => (t.updatedAt ? formatDateTime(t.updatedAt) : "") },
]

// ── Filter Presets ──────────────────────────────────────────────────────

interface FilterPresetFilters {
  status?: string[]
  priority?: string[]
  category?: string[]
  search?: string
}

interface FilterPreset {
  id: string
  name: string
  filters: FilterPresetFilters
  isBuiltin?: boolean
}

const PRESET_STORAGE_KEY = "support-filter-presets"

const BUILTIN_PRESETS: FilterPreset[] = [
  {
    id: "all",
    name: "All Tickets",
    filters: {},
    isBuiltin: true,
  },
  {
    id: "open",
    name: "Open Tickets",
    filters: { status: ["open"] },
    isBuiltin: true,
  },
  {
    id: "high-priority",
    name: "High Priority",
    filters: { priority: ["high", "urgent"] },
    isBuiltin: true,
  },
  {
    id: "unresolved",
    name: "Unresolved",
    filters: { status: ["open", "in_progress", "waiting_on_customer", "waiting_on_support"] },
    isBuiltin: true,
  },
]

function loadCustomPresets(): FilterPreset[] {
  try {
    const stored = localStorage.getItem(PRESET_STORAGE_KEY)
    if (stored) {
      const parsed = JSON.parse(stored) as FilterPreset[]
      if (Array.isArray(parsed)) return parsed
    }
  } catch {
    // localStorage unavailable or corrupt
  }
  return []
}

function saveCustomPresets(presets: FilterPreset[]): void {
  try {
    localStorage.setItem(PRESET_STORAGE_KEY, JSON.stringify(presets))
  } catch {
    // localStorage unavailable
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────

const priorityRowAccent: Record<string, string> = {
  urgent: "border-l-red-500",
  high: "border-l-amber-500",
  medium: "border-l-blue-300 dark:border-l-blue-500/50",
  low: "border-l-transparent",
}

function getInitials(name?: string | null, email?: string): string {
  if (name) {
    const parts = name.trim().split(/\s+/)
    return parts
      .slice(0, 2)
      .map((p) => p[0])
      .join("")
      .toUpperCase()
  }
  return email ? email[0].toUpperCase() : "?"
}

// ── Main page ────────────────────────────────────────────────────────────

function SupportPage() {
  useDocumentTitle("Support Tickets")
  const searchInputRef = useRef<HTMLInputElement>(null)
  // Filter & search state
  const [search, setSearch] = useState("")
  const debouncedSearch = useDebouncedValue(search)
  const [statusFilter, setStatusFilter] = useState<string[]>([])
  const [priorityFilter, setPriorityFilter] = useState<string[]>([])
  const [categoryFilter, setCategoryFilter] = useState<string[]>([])
  const [startDate, setStartDate] = useState("")
  const [endDate, setEndDate] = useState("")
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(getStoredPageSize)

  // Current user (for "My Tickets" quick filter)
  const currentUser = useAuthStore((state) => state.user)

  // Filter presets
  const [customPresets, setCustomPresets] = useState<FilterPreset[]>(loadCustomPresets)
  const [activePresetId, setActivePresetId] = useState<string | null>(null)
  const [isNamingPreset, setIsNamingPreset] = useState(false)
  const [presetName, setPresetName] = useState("")

  // Assignee quick filter: "my-tickets" | "unassigned" | null
  const [assigneeQuickFilter, setAssigneeQuickFilter] = useState<"my-tickets" | "unassigned" | null>(null)

  // Track manual filter changes to clear active preset
  const manualFilterChangeRef = useRef(false)

  useEffect(() => {
    if (manualFilterChangeRef.current) {
      setActivePresetId(null)
      manualFilterChangeRef.current = false
    }
  }, [statusFilter, priorityFilter, categoryFilter, search])

  const applyPreset = useCallback(
    (preset: FilterPreset) => {
      // Apply filters without triggering the manual-change detector
      setSearch(preset.filters.search ?? "")
      setStatusFilter(preset.filters.status ?? [])
      setPriorityFilter(preset.filters.priority ?? [])
      setCategoryFilter(preset.filters.category ?? [])
      setStartDate("")
      setEndDate("")
      setAssigneeQuickFilter(null)
      setPage(1)
      setActivePresetId(preset.id)
    },
    [],
  )

  const handleSavePreset = useCallback(() => {
    const trimmed = presetName.trim()
    if (!trimmed) return

    const newPreset: FilterPreset = {
      id: `custom-${Date.now()}`,
      name: trimmed,
      filters: {
        ...(statusFilter.length > 0 ? { status: statusFilter } : {}),
        ...(priorityFilter.length > 0 ? { priority: priorityFilter } : {}),
        ...(categoryFilter.length > 0 ? { category: categoryFilter } : {}),
        ...(search ? { search } : {}),
      },
    }

    const updated = [...customPresets, newPreset]
    setCustomPresets(updated)
    saveCustomPresets(updated)
    setActivePresetId(newPreset.id)
    setIsNamingPreset(false)
    setPresetName("")
    toast.success(`Filter preset "${trimmed}" saved`)
  }, [presetName, statusFilter, priorityFilter, categoryFilter, search, customPresets])

  const handleDeletePreset = useCallback(
    (presetId: string) => {
      const updated = customPresets.filter((p) => p.id !== presetId)
      setCustomPresets(updated)
      saveCustomPresets(updated)
      if (activePresetId === presetId) {
        setActivePresetId(null)
      }
      toast.success("Filter preset removed")
    },
    [customPresets, activePresetId],
  )

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

  const navigate = useNavigate()
  const queryClient = useQueryClient()

  // Build server-side filters (status/priority/category are single-value on backend,
  // so when multiple are selected we rely on client-side filtering)
  const serverFilters = useMemo(() => {
    return {
      search: debouncedSearch || undefined,
      status: statusFilter.length === 1 ? statusFilter[0] : undefined,
      priority: priorityFilter.length === 1 ? priorityFilter[0] : undefined,
      category: categoryFilter.length === 1 ? categoryFilter[0] : undefined,
      orderBy: sortKey ?? undefined,
      sortOrder: sortDir ?? undefined,
    }
  }, [debouncedSearch, statusFilter, priorityFilter, categoryFilter, sortKey, sortDir])

  const { data, isLoading, isError, refetch, dataUpdatedAt, isRefetching } = useTickets(page, pageSize, serverFilters)

  // Apply client-side multi-value filters
  const filteredItems = useMemo(() => {
    if (!data?.items) return []
    return data.items.filter((ticket) => {
      if (statusFilter.length > 1 && !statusFilter.includes(ticket.status)) return false
      if (priorityFilter.length > 1 && !priorityFilter.includes(ticket.priority)) return false
      if (categoryFilter.length > 1 && ticket.category && !categoryFilter.includes(ticket.category))
        return false
      if ((startDate || endDate) && !isDateInRange(ticket.createdAt, startDate, endDate))
        return false
      // Assignee quick filters
      if (assigneeQuickFilter === "my-tickets" && currentUser) {
        if (ticket.assignedTo?.id !== currentUser.id) return false
      }
      if (assigneeQuickFilter === "unassigned") {
        if (ticket.assignedTo != null) return false
      }
      return true
    })
  }, [data?.items, statusFilter, priorityFilter, categoryFilter, startDate, endDate, assigneeQuickFilter, currentUser])

  // Ticket summary stats (computed from ALL items on the current page)
  const ticketStats = useMemo(() => {
    const items = data?.items ?? []
    let open = 0
    let inProgress = 0
    let resolved = 0
    for (const ticket of items) {
      if (ticket.status === "open") open++
      else if (ticket.status === "in_progress") inProgress++
      else if (ticket.status === "resolved") resolved++
    }
    return { open, inProgress, resolved, total: data?.total ?? 0 }
  }, [data?.items, data?.total])

  // Selection helpers
  const allVisibleIds = useMemo(() => filteredItems.map((t) => t.id), [filteredItems])
  const allSelected = filteredItems.length > 0 && filteredItems.every((t) => selectedIds.has(t.id))
  const someSelected = filteredItems.some((t) => selectedIds.has(t.id))

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
      setPage(1)
    },
    [sortKey, sortDir],
  )

  // Date range handler
  const handleDatePreset = useCallback(
    (days: number) => {
      const { start, end } = getPresetDates(days)
      setStartDate(start)
      setEndDate(end)
      setPage(1)
    },
    [],
  )

  // Filter helpers
  const activeFilterCount =
    statusFilter.length + priorityFilter.length + categoryFilter.length + (startDate || endDate ? 1 : 0) + (assigneeQuickFilter ? 1 : 0)
  const hasAnyFilters = activeFilterCount > 0 || !!search

  const toggleAssigneeQuickFilter = useCallback(
    (filter: "my-tickets" | "unassigned") => {
      setAssigneeQuickFilter((prev) => (prev === filter ? null : filter))
      setActivePresetId(null)
      setPage(1)
    },
    [],
  )

  const clearAllFilters = useCallback(() => {
    setSearch("")
    setStatusFilter([])
    setPriorityFilter([])
    setCategoryFilter([])
    setStartDate("")
    setEndDate("")
    setAssigneeQuickFilter(null)
    setPage(1)
  }, [])

  const handleSearchChange = useCallback(
    (value: string) => {
      manualFilterChangeRef.current = true
      setSearch(value)
    },
    [],
  )

  // Export
  const handleExportAll = useCallback(() => {
    if (!filteredItems.length) return
    exportToCsv("tickets", csvHeaders, filteredItems)
    toast.success(`Exported ${filteredItems.length} ticket${filteredItems.length === 1 ? "" : "s"}`)
  }, [filteredItems])

  // Row click handler
  const handleRowClick = useCallback(
    (ticketId: string) => {
      navigate({ to: "/support/$ticketId", params: { ticketId } })
    },
    [navigate],
  )

  // Single-ticket delete handler
  const handleDeleteTicket = useCallback(
    async (ticketId: string) => {
      try {
        await client.delete({
          url: `/api/support/tickets/${ticketId}`,
          security: [{ scheme: "bearer", type: "http" }],
        } as never)
        queryClient.invalidateQueries({ queryKey: ["support", "tickets"] })
        toast.success("Ticket deleted")
        // The deleted row is gone, so restore focus to the search input
        setTimeout(() => {
          const searchInput = document.querySelector<HTMLInputElement>('input[placeholder*="Search"]')
          if (searchInput) {
            searchInput.focus()
          }
        }, 0)
      } catch {
        toast.error("Unable to delete ticket")
      }
    },
    [queryClient],
  )

  // Bulk actions
  const bulkActions: BulkAction[] = useMemo(
    () => [
      {
        key: "resolve",
        label: "Resolve Selected",
        icon: <CheckCircle2 className="h-4 w-4" />,
        variant: "outline",
        confirm: {
          title: "Resolve selected tickets?",
          description:
            "The selected tickets will be marked as resolved.",
        },
        onExecute: async (ids) => {
          const errors: string[] = []
          for (const id of ids) {
            try {
              await client.patch({
                url: `/api/support/tickets/${id}`,
                body: { status: "resolved" },
                security: [{ scheme: "bearer", type: "http" }],
              } as never)
            } catch {
              errors.push(id)
            }
          }
          queryClient.invalidateQueries({ queryKey: ["support", "tickets"] })
          setSelectedIds(new Set())
          if (errors.length > 0) {
            toast.error(`Failed to resolve ${errors.length} of ${ids.length} tickets`)
          } else {
            toast.success(`Resolved ${ids.length} ticket${ids.length === 1 ? "" : "s"}`)
          }
        },
      },
      {
        key: "close",
        label: "Close Selected",
        icon: <CheckCircle className="h-4 w-4" />,
        variant: "outline",
        confirm: {
          title: "Close selected tickets?",
          description:
            "The selected tickets will be marked as closed. You can reopen them later.",
        },
        onExecute: async (ids) => {
          const errors: string[] = []
          for (const id of ids) {
            try {
              await client.post({
                url: `/api/support/tickets/${id}/close`,
                security: [{ scheme: "bearer", type: "http" }],
              } as never)
            } catch {
              errors.push(id)
            }
          }
          queryClient.invalidateQueries({ queryKey: ["support", "tickets"] })
          setSelectedIds(new Set())
          if (errors.length > 0) {
            toast.error(`Failed to close ${errors.length} of ${ids.length} tickets`)
          } else {
            toast.success(`Closed ${ids.length} ticket${ids.length === 1 ? "" : "s"}`)
          }
        },
      },
      {
        key: "reopen",
        label: "Reopen Selected",
        icon: <RotateCcw className="h-4 w-4" />,
        variant: "outline",
        confirm: {
          title: "Reopen selected tickets?",
          description:
            "The selected tickets will be reopened and set back to an open status.",
        },
        onExecute: async (ids) => {
          const errors: string[] = []
          for (const id of ids) {
            try {
              await client.post({
                url: `/api/support/tickets/${id}/reopen`,
                security: [{ scheme: "bearer", type: "http" }],
              } as never)
            } catch {
              errors.push(id)
            }
          }
          queryClient.invalidateQueries({ queryKey: ["support", "tickets"] })
          setSelectedIds(new Set())
          if (errors.length > 0) {
            toast.error(`Failed to reopen ${errors.length} of ${ids.length} tickets`)
          } else {
            toast.success(`Reopened ${ids.length} ticket${ids.length === 1 ? "" : "s"}`)
          }
        },
      },
      {
        key: "set-high-priority",
        label: "Set High Priority",
        icon: <ArrowUp className="h-4 w-4" />,
        variant: "outline",
        onExecute: async (ids) => {
          const errors: string[] = []
          for (const id of ids) {
            try {
              await client.patch({
                url: `/api/support/tickets/${id}`,
                body: { priority: "high" },
                security: [{ scheme: "bearer", type: "http" }],
              } as never)
            } catch {
              errors.push(id)
            }
          }
          queryClient.invalidateQueries({ queryKey: ["support", "tickets"] })
          setSelectedIds(new Set())
          if (errors.length > 0) {
            toast.error(`Failed to update priority for ${errors.length} of ${ids.length} tickets`)
          } else {
            toast.success(`Set high priority on ${ids.length} ticket${ids.length === 1 ? "" : "s"}`)
          }
        },
      },
      {
        key: "set-low-priority",
        label: "Set Low Priority",
        icon: <ArrowDown className="h-4 w-4" />,
        variant: "outline",
        onExecute: async (ids) => {
          const errors: string[] = []
          for (const id of ids) {
            try {
              await client.patch({
                url: `/api/support/tickets/${id}`,
                body: { priority: "low" },
                security: [{ scheme: "bearer", type: "http" }],
              } as never)
            } catch {
              errors.push(id)
            }
          }
          queryClient.invalidateQueries({ queryKey: ["support", "tickets"] })
          setSelectedIds(new Set())
          if (errors.length > 0) {
            toast.error(`Failed to update priority for ${errors.length} of ${ids.length} tickets`)
          } else {
            toast.success(`Set low priority on ${ids.length} ticket${ids.length === 1 ? "" : "s"}`)
          }
        },
      },
      {
        key: "delete",
        label: "Delete Selected",
        icon: <Trash2 className="h-4 w-4" />,
        variant: "destructive",
        confirm: {
          title: "Delete selected tickets?",
          description:
            "This action cannot be undone. All selected tickets and their messages will be permanently deleted.",
        },
        onExecute: async (ids) => {
          const errors: string[] = []
          for (const id of ids) {
            try {
              await client.delete({
                url: `/api/support/tickets/${id}`,
                security: [{ scheme: "bearer", type: "http" }],
              } as never)
            } catch {
              errors.push(id)
            }
          }
          queryClient.invalidateQueries({ queryKey: ["support", "tickets"] })
          setSelectedIds(new Set())
          if (errors.length > 0) {
            toast.error(`Failed to delete ${errors.length} of ${ids.length} tickets`)
          } else {
            toast.success(`Deleted ${ids.length} ticket${ids.length === 1 ? "" : "s"}`)
          }
        },
      },
      {
        key: "export",
        label: "Export Selected",
        icon: <Download className="h-4 w-4" />,
        variant: "outline",
        onExecute: async (ids) => {
          const selected = filteredItems.filter((t) => ids.includes(t.id))
          exportToCsv("tickets-selected", csvHeaders, selected)
          toast.success(
            `Exported ${selected.length} ticket${selected.length === 1 ? "" : "s"}`,
          )
        },
      },
    ],
    [filteredItems, queryClient],
  )

  const hasData = filteredItems.length > 0
  const hasAnyTickets = (data?.items.length ?? 0) > 0
  const totalPages = Math.max(1, Math.ceil((data?.total ?? 0) / pageSize))

  // Keyboard shortcuts: "/" to focus search, ArrowLeft/ArrowRight for pagination
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement
      if (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable) return
      if (e.key === "/" && !e.ctrlKey && !e.metaKey) {
        e.preventDefault()
        searchInputRef.current?.focus()
      }
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
          <BreadcrumbPage>Support</BreadcrumbPage>
        </BreadcrumbItem>
      </BreadcrumbList>
    </Breadcrumb>
  )

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Helpdesk"
        title="Tickets"
        description="View and manage support tickets."
        breadcrumbs={breadcrumbs}
        actions={
          <div className="flex items-center gap-2">
            <DataFreshness
              dataUpdatedAt={dataUpdatedAt}
              onRefresh={() => refetch()}
              isRefreshing={isRefetching}
            />
            <Button variant="outline" size="sm" onClick={handleExportAll} disabled={!hasData}>
              <Download className="mr-1.5 h-3.5 w-3.5" />
              Export
            </Button>
            <Button size="sm" asChild>
              <Link to="/support/new">
                <Plus className="mr-2 h-4 w-4" /> New Ticket
              </Link>
            </Button>
          </div>
        }
      />

      {/* Filter presets */}
      <PageSection>
        <div className="flex flex-wrap items-center gap-2">
          <Bookmark className="h-4 w-4 text-muted-foreground shrink-0" />
          {BUILTIN_PRESETS.map((preset) => (
            <Button
              key={preset.id}
              variant={activePresetId === preset.id ? "default" : "outline"}
              size="sm"
              className="h-7 text-xs"
              onClick={() => applyPreset(preset)}
            >
              {preset.name}
            </Button>
          ))}

          <Separator orientation="vertical" className="mx-1 h-5" />

          <Button
            variant={assigneeQuickFilter === "my-tickets" ? "default" : "outline"}
            size="sm"
            className="h-7 text-xs"
            onClick={() => toggleAssigneeQuickFilter("my-tickets")}
          >
            <User className="mr-1.5 h-3.5 w-3.5" />
            My Tickets
          </Button>
          <Button
            variant={assigneeQuickFilter === "unassigned" ? "default" : "outline"}
            size="sm"
            className="h-7 text-xs"
            onClick={() => toggleAssigneeQuickFilter("unassigned")}
          >
            <UserX className="mr-1.5 h-3.5 w-3.5" />
            Unassigned
          </Button>

          {customPresets.length > 0 && (
            <Separator orientation="vertical" className="mx-1 h-5" />
          )}

          {customPresets.map((preset) => (
            <div key={preset.id} className="flex items-center gap-0">
              <Button
                variant={activePresetId === preset.id ? "default" : "outline"}
                size="sm"
                className="h-7 rounded-r-none text-xs"
                onClick={() => applyPreset(preset)}
              >
                {preset.name}
              </Button>
              <Button
                variant={activePresetId === preset.id ? "default" : "outline"}
                size="sm"
                className="h-7 rounded-l-none border-l-0 px-1.5"
                onClick={() => handleDeletePreset(preset.id)}
                aria-label={`Remove preset ${preset.name}`}
              >
                <X className="h-3 w-3" />
              </Button>
            </div>
          ))}

          <Separator orientation="vertical" className="mx-1 h-5" />

          {isNamingPreset ? (
            <div className="flex items-center gap-1.5">
              <Input
                autoFocus
                placeholder="Preset name..."
                value={presetName}
                onChange={(e) => setPresetName(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleSavePreset()
                  if (e.key === "Escape") {
                    setIsNamingPreset(false)
                    setPresetName("")
                  }
                }}
                className="h-7 w-40 text-xs"
              />
              <Button
                variant="default"
                size="sm"
                className="h-7 text-xs"
                onClick={handleSavePreset}
                disabled={!presetName.trim()}
              >
                Save
              </Button>
              <Button
                variant="ghost"
                size="sm"
                className="h-7 px-1.5"
                onClick={() => {
                  setIsNamingPreset(false)
                  setPresetName("")
                }}
                aria-label="Cancel saving preset"
              >
                <X className="h-3.5 w-3.5" />
              </Button>
            </div>
          ) : (
            <Button
              variant="ghost"
              size="sm"
              className="h-7 text-xs text-muted-foreground"
              onClick={() => setIsNamingPreset(true)}
            >
              <Save className="mr-1.5 h-3.5 w-3.5" />
              Save filters
            </Button>
          )}
        </div>
      </PageSection>

      {/* Summary stats */}
      <div className="flex flex-wrap items-center gap-2">
        {isLoading ? (
          <>
            <Skeleton className="h-7 w-28 rounded-full" />
            <Skeleton className="h-7 w-32 rounded-full" />
            <Skeleton className="h-7 w-28 rounded-full" />
            <Skeleton className="h-7 w-24 rounded-full" />
          </>
        ) : (
          <>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-blue-500/30 bg-blue-500/10 px-3 py-1 text-xs font-medium text-blue-700 dark:text-blue-400">
              <span className="h-1.5 w-1.5 rounded-full bg-blue-500" />
              Open
              <span className="ml-0.5 font-semibold">{ticketStats.open}</span>
            </span>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-amber-500/30 bg-amber-500/10 px-3 py-1 text-xs font-medium text-amber-700 dark:text-amber-400">
              <span className="h-1.5 w-1.5 rounded-full bg-amber-500" />
              In Progress
              <span className="ml-0.5 font-semibold">{ticketStats.inProgress}</span>
            </span>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-xs font-medium text-emerald-700 dark:text-emerald-400">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
              Resolved
              <span className="ml-0.5 font-semibold">{ticketStats.resolved}</span>
            </span>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-muted/50 px-3 py-1 text-xs font-medium text-muted-foreground">
              Total
              <span className="ml-0.5 font-semibold text-foreground">{ticketStats.total}</span>
            </span>
          </>
        )}
      </div>

      {/* Search & filters */}
      <PageSection>
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative max-w-sm flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              ref={searchInputRef}
              placeholder="Search by subject or description..."
              value={search}
              onChange={(e) => handleSearchChange(e.target.value)}
              className="pl-9 pr-8"
            />
            {search ? (
              <button
                type="button"
                onClick={() => handleSearchChange("")}
                className="absolute right-2 top-1/2 -translate-y-1/2 rounded-sm p-0.5 text-muted-foreground hover:text-foreground"
              >
                <X className="h-3.5 w-3.5" />
                <span className="sr-only">Clear search</span>
              </button>
            ) : (
              <kbd className="pointer-events-none absolute right-8 top-1/2 -translate-y-1/2 hidden rounded border border-border bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground sm:inline">/</kbd>
            )}
          </div>
          <FilterDropdown
            label="Status"
            options={statusOptions}
            selected={statusFilter}
            onChange={(v) => {
              manualFilterChangeRef.current = true
              setStatusFilter(v)
              setPage(1)
            }}
          />
          <FilterDropdown
            label="Priority"
            options={priorityOptions}
            selected={priorityFilter}
            onChange={(v) => {
              manualFilterChangeRef.current = true
              setPriorityFilter(v)
              setPage(1)
            }}
          />
          <FilterDropdown
            label="Category"
            options={categoryOptions}
            selected={categoryFilter}
            onChange={(v) => {
              manualFilterChangeRef.current = true
              setCategoryFilter(v)
              setPage(1)
            }}
          />
          <DateRangeFilter
            startDate={startDate}
            endDate={endDate}
            onStartDateChange={(v) => {
              setStartDate(v)
              setPage(1)
            }}
            onEndDateChange={(v) => {
              setEndDate(v)
              setPage(1)
            }}
            onPreset={handleDatePreset}
            label="Created"
          />
          {hasAnyFilters && (
            <Button
              variant="ghost"
              size="sm"
              className="text-xs text-muted-foreground"
              onClick={clearAllFilters}
            >
              Clear all filters
            </Button>
          )}
        </div>
      </PageSection>

      {/* Content */}
      <PageSection delay={0.1}>
        {isLoading ? (
          <SkeletonTable rows={6} />
        ) : isError ? (
          <EmptyState
            icon={AlertCircle}
            title="Unable to load tickets"
            description="Something went wrong while fetching your tickets. Please try again."
            action={
              <Button variant="outline" size="sm" onClick={() => refetch()}>
                Try again
              </Button>
            }
          />
        ) : !hasAnyTickets && !hasAnyFilters ? (
          <EmptyState
            icon={LifeBuoy}
            title="No tickets yet"
            description="Create your first support ticket to get help from our team. We're here to assist you with any questions or issues."
            action={
              <Button size="sm" asChild>
                <Link to="/support/new">
                  <Plus className="mr-2 h-4 w-4" /> Create your first ticket
                </Link>
              </Button>
            }
          />
        ) : !hasData ? (
          <EmptyState
            icon={LifeBuoy}
            variant="no-results"
            title="No results found"
            description="No tickets match your current filters. Try adjusting your search or filters."
            action={
              <Button variant="outline" size="sm" onClick={clearAllFilters}>
                Clear all filters
              </Button>
            }
          />
        ) : (
          <div className="space-y-3">
            {/* Result count & pagination info */}
            <div className="flex items-center justify-between">
              <p className="text-sm text-muted-foreground">
                {data ? data.total : filteredItems.length} ticket
                {(data?.total ?? filteredItems.length) === 1 ? "" : "s"}
                {activeFilterCount > 0 && " (filtered)"}
              </p>
              {totalPages > 1 && (
                <p className="text-xs text-muted-foreground">
                  Page {page} of {totalPages}
                </p>
              )}
            </div>

            {/* Table */}
            <div className="overflow-x-auto rounded-md border border-border/60 bg-card/80">
              <Table aria-label="Support tickets">
                <TableHeader className="sticky top-0 z-10 bg-background">
                  <TableRow>
                    <TableHead className="w-10">
                      <Checkbox
                        checked={allSelected}
                        indeterminate={someSelected && !allSelected}
                        onChange={toggleAll}
                        aria-label="Select all tickets"
                      />
                    </TableHead>
                    <TableHead className="w-[100px]">Ticket</TableHead>
                    <SortableHeader
                      label="Subject"
                      sortKey="subject"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <SortableHeader
                      label="Status"
                      sortKey="status"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                    />
                    <SortableHeader
                      label="Priority"
                      sortKey="priority"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                      className="hidden md:table-cell"
                    />
                    <TableHead className="hidden md:table-cell">Category</TableHead>
                    <SortableHeader
                      label="Created"
                      sortKey="created_at"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                      className="hidden md:table-cell"
                    />
                    <SortableHeader
                      label="Updated"
                      sortKey="updated_at"
                      currentSort={sortKey}
                      currentDirection={sortDir}
                      onSort={handleSort}
                      className="hidden md:table-cell"
                    />
                    <TableHead className="w-16 text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredItems.map((ticket, index) => (
                    <TicketRow
                      key={ticket.id}
                      ticket={ticket}
                      index={index}
                      selected={selectedIds.has(ticket.id)}
                      onToggle={() => toggleOne(ticket.id)}
                      onRowClick={() => handleRowClick(ticket.id)}
                      onDelete={() => handleDeleteTicket(ticket.id)}
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

function TicketRow({
  ticket,
  index,
  selected,
  onToggle,
  onRowClick,
  onDelete,
}: {
  ticket: Ticket
  index: number
  selected: boolean
  onToggle: () => void
  onRowClick: () => void
  onDelete: () => void
}) {
  return (
    <TableRow
      className={cn(
        "cursor-pointer hover:bg-muted/50 transition-colors border-l-2",
        priorityRowAccent[ticket.priority] ?? "border-l-transparent",
        index % 2 === 1 ? "bg-muted/20" : "",
        !ticket.isReadByUser && "bg-primary/[0.02]",
      )}
      data-state={selected ? "selected" : undefined}
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
          aria-label={`Select ticket ${ticket.ticketNumber}`}
        />
      </TableCell>
      <TableCell className="font-mono text-xs text-muted-foreground">
        <div className="flex items-center gap-1.5">
          {!ticket.isReadByUser && (
            <span className="h-1.5 w-1.5 rounded-full bg-primary" />
          )}
          {ticket.ticketNumber}
        </div>
      </TableCell>
      <TableCell>
        <Link
          to="/support/$ticketId"
          params={{ ticketId: ticket.id }}
          className={cn(
            "group flex flex-col gap-0.5",
          )}
          onClick={(e) => e.stopPropagation()}
        >
          <span className={cn(
            "group-hover:underline",
            ticket.isReadByUser ? "font-medium" : "font-semibold",
          )}>
            {ticket.subject}
          </span>
          {ticket.latestMessagePreview && (
            <span className="text-xs text-muted-foreground line-clamp-1">
              {ticket.latestMessagePreview}
            </span>
          )}
        </Link>
      </TableCell>
      <TableCell>
        <div className="flex flex-col gap-1.5">
          <TicketStatusBadge status={ticket.status} />
          {ticket.assignedTo && (
            <Tooltip>
              <TooltipTrigger asChild>
                <div className="flex items-center gap-1.5">
                  <Avatar className="size-4">
                    {ticket.assignedTo.avatarUrl ? (
                      <AvatarImage src={ticket.assignedTo.avatarUrl} alt={ticket.assignedTo.name ?? ticket.assignedTo.email} />
                    ) : null}
                    <AvatarFallback className="text-[8px] font-medium bg-muted">
                      {getInitials(ticket.assignedTo.name, ticket.assignedTo.email)}
                    </AvatarFallback>
                  </Avatar>
                  <span className="text-xs text-muted-foreground truncate max-w-[100px]">
                    {ticket.assignedTo.name ?? ticket.assignedTo.email}
                  </span>
                </div>
              </TooltipTrigger>
              <TooltipContent>
                Assigned to {ticket.assignedTo.name ?? ticket.assignedTo.email}
              </TooltipContent>
            </Tooltip>
          )}
        </div>
      </TableCell>
      <TableCell className="hidden md:table-cell">
        <TicketPriorityBadge priority={ticket.priority} />
      </TableCell>
      <TableCell className="hidden md:table-cell">
        {ticket.category ? (
          <Badge variant="outline" className="text-xs capitalize">
            {ticket.category}
          </Badge>
        ) : (
          <span className="text-xs text-muted-foreground">--</span>
        )}
      </TableCell>
      <TableCell className="hidden md:table-cell">
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="cursor-default text-xs text-muted-foreground">
              {formatRelativeTimeShort(ticket.createdAt)}
            </span>
          </TooltipTrigger>
          <TooltipContent>{formatDateTime(ticket.createdAt)}</TooltipContent>
        </Tooltip>
      </TableCell>
      <TableCell className="hidden md:table-cell">
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="cursor-default text-xs text-muted-foreground">
              {formatRelativeTimeShort(ticket.updatedAt)}
            </span>
          </TooltipTrigger>
          <TooltipContent>{formatDateTime(ticket.updatedAt)}</TooltipContent>
        </Tooltip>
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
              <span className="sr-only">Actions for {ticket.ticketNumber}</span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem asChild>
              <Link to="/support/$ticketId" params={{ ticketId: ticket.id }}>
                <Eye className="mr-2 h-4 w-4" />
                View details
              </Link>
            </DropdownMenuItem>
            <DropdownMenuItem asChild>
              <Link to="/support/$ticketId/edit" params={{ ticketId: ticket.id }}>
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
