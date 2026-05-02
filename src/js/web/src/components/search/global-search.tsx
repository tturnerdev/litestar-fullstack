import { useNavigate, useRouterState } from "@tanstack/react-router"
import {
  BarChart3,
  Bell,
  Building2,
  Cable,
  Clock,
  GitBranch,
  History,
  Home,
  LifeBuoy,
  Loader2,
  Mail,
  MapPin,
  Monitor,
  Phone,
  Plus,
  Printer,
  Search,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Tags,
  UserRound,
  Users,
  Voicemail,
  X,
} from "lucide-react"
import { useCallback, useEffect, useRef, useState } from "react"
import { Button } from "@/components/ui/button"
import { CommandDialog, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList, CommandSeparator } from "@/components/ui/command"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { type SearchResultItem, useGlobalSearch } from "@/lib/api/hooks/search"
import { useAuthStore } from "@/lib/auth"

// ---------------------------------------------------------------------------
// Type icon, label, and color mappings
// ---------------------------------------------------------------------------

const TYPE_META: Record<string, { icon: React.ElementType; label: string; color: string }> = {
  team: { icon: Users, label: "Teams", color: "text-blue-500" },
  device: { icon: Monitor, label: "Devices", color: "text-green-500" },
  ticket: { icon: LifeBuoy, label: "Tickets", color: "text-amber-500" },
  extension: { icon: Phone, label: "Extensions", color: "text-violet-500" },
  phone_number: { icon: Phone, label: "Phone Numbers", color: "text-indigo-500" },
  fax_number: { icon: Printer, label: "Fax Numbers", color: "text-rose-500" },
  location: { icon: MapPin, label: "Locations", color: "text-teal-500" },
  user: { icon: UserRound, label: "Users", color: "text-sky-500" },
}

function getTypeMeta(type: string) {
  return TYPE_META[type] ?? { icon: Search, label: type, color: "text-muted-foreground" }
}

// ---------------------------------------------------------------------------
// Quick actions
// ---------------------------------------------------------------------------

const QUICK_ACTIONS = [
  { label: "Create Team", url: "/teams/new", icon: Users, color: "text-blue-500" },
  { label: "New Device", url: "/devices/new", icon: Monitor, color: "text-green-500" },
  { label: "New Ticket", url: "/support/new", icon: LifeBuoy, color: "text-amber-500" },
]

// ---------------------------------------------------------------------------
// Navigation shortcuts
// ---------------------------------------------------------------------------

interface NavShortcut {
  label: string
  url: string
  icon: React.ElementType
  color: string
  keywords?: string[]
  adminOnly?: boolean
}

const NAV_SHORTCUTS: Record<string, NavShortcut[]> = {
  Navigation: [
    { label: "Home", url: "/home", icon: Home, color: "text-foreground" },
    { label: "Teams", url: "/teams", icon: Users, color: "text-blue-500" },
    { label: "Devices", url: "/devices", icon: Monitor, color: "text-green-500" },
    { label: "Locations", url: "/locations", icon: MapPin, color: "text-teal-500" },
    { label: "Support Tickets", url: "/support", icon: LifeBuoy, color: "text-amber-500", keywords: ["helpdesk", "tickets"] },
    { label: "Tags", url: "/tags", icon: Tags, color: "text-orange-500" },
    { label: "Connections", url: "/connections", icon: Cable, color: "text-cyan-500", adminOnly: true },
  ],
  Voice: [
    { label: "Voice Overview", url: "/voice", icon: Phone, color: "text-violet-500" },
    { label: "Extensions", url: "/voice/extensions", icon: Phone, color: "text-violet-500", keywords: ["ext", "dial"] },
    { label: "Phone Numbers", url: "/voice/phone-numbers", icon: Phone, color: "text-indigo-500", keywords: ["DID", "number"] },
    { label: "E911", url: "/e911", icon: ShieldAlert, color: "text-red-500", keywords: ["emergency", "911", "location"] },
    { label: "Call Routing", url: "/call-routing", icon: GitBranch, color: "text-purple-500", keywords: ["IVR", "queue", "ring group", "time condition"] },
    { label: "Voicemail", url: "/voicemail", icon: Voicemail, color: "text-fuchsia-500", keywords: ["mailbox", "messages"] },
    { label: "Schedules", url: "/schedules", icon: Clock, color: "text-yellow-500", keywords: ["time", "schedule"] },
  ],
  Fax: [
    { label: "Fax Overview", url: "/fax", icon: Printer, color: "text-rose-500" },
    { label: "Fax Numbers", url: "/fax/numbers", icon: Printer, color: "text-rose-500", keywords: ["fax DID"] },
    { label: "Fax Messages", url: "/fax/messages", icon: Printer, color: "text-rose-400", keywords: ["sent", "received"] },
    { label: "Send Fax", url: "/fax/send", icon: Printer, color: "text-rose-600" },
    { label: "Email Routes", url: "/fax/email-routes", icon: Mail, color: "text-rose-500", keywords: ["fax to email", "email to fax"] },
  ],
  Settings: [
    { label: "Settings", url: "/settings", icon: Settings, color: "text-muted-foreground", keywords: ["preferences", "account settings"] },
    { label: "Notifications", url: "/notifications", icon: Bell, color: "text-muted-foreground", keywords: ["alerts", "notify"] },
    { label: "Organization", url: "/organization", icon: Building2, color: "text-muted-foreground", adminOnly: true, keywords: ["org", "company"] },
  ],
  Analytics: [
    { label: "Analytics Dashboard", url: "/analytics", icon: BarChart3, color: "text-emerald-500", keywords: ["stats", "reports", "CDR"] },
    { label: "Call Records", url: "/analytics?tab=records", icon: BarChart3, color: "text-emerald-500", keywords: ["CDR", "call detail records", "history"] },
    { label: "Gateway", url: "/gateway", icon: Search, color: "text-gray-500", keywords: ["SIP", "trunk"] },
  ],
  Admin: [
    { label: "Admin Dashboard", url: "/admin", icon: ShieldCheck, color: "text-sky-500", adminOnly: true },
    { label: "System Health", url: "/admin/system", icon: ShieldCheck, color: "text-sky-500", adminOnly: true, keywords: ["status", "health check"] },
    { label: "Audit Logs", url: "/admin/audit", icon: ShieldCheck, color: "text-sky-500", adminOnly: true, keywords: ["audit", "log", "activity"] },
    { label: "Manage Users", url: "/admin/users", icon: UserRound, color: "text-sky-500", adminOnly: true },
    { label: "Gateway Settings", url: "/admin/gateway", icon: ShieldCheck, color: "text-sky-500", adminOnly: true, keywords: ["SIP", "trunk", "admin gateway"] },
  ],
}

// ---------------------------------------------------------------------------
// Recent searches (localStorage)
// ---------------------------------------------------------------------------

const RECENT_SEARCHES_KEY = "global-search-recent"
const MAX_RECENT = 5

function getRecentSearches(): string[] {
  try {
    const raw = localStorage.getItem(RECENT_SEARCHES_KEY)
    if (!raw) return []
    const parsed = JSON.parse(raw) as unknown
    return Array.isArray(parsed) ? (parsed as string[]).slice(0, MAX_RECENT) : []
  } catch {
    return []
  }
}

function addRecentSearch(query: string) {
  const trimmed = query.trim()
  if (trimmed.length < 2) return
  const existing = getRecentSearches()
  const updated = [trimmed, ...existing.filter((s) => s !== trimmed)].slice(0, MAX_RECENT)
  localStorage.setItem(RECENT_SEARCHES_KEY, JSON.stringify(updated))
}

// ---------------------------------------------------------------------------
// Recent pages (localStorage)
// ---------------------------------------------------------------------------

const RECENT_PAGES_KEY = "global-search-recent-pages"
const MAX_RECENT_PAGES = 5

interface RecentPage {
  label: string
  url: string
}

/** Path segments that should be excluded from recent page tracking. */
const IGNORED_PATHS = ["/login", "/signup", "/mfa", "/forgot-password"]

function labelFromPath(pathname: string): string {
  // Check nav shortcuts for a matching label first.
  for (const items of Object.values(NAV_SHORTCUTS)) {
    const match = items.find((s) => s.url === pathname)
    if (match) return match.label
  }
  // Fallback: build a human-readable label from the path.
  const segments = pathname.split("/").filter(Boolean)
  if (segments.length === 0) return "Home"
  return segments.map((s) => s.replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())).join(" / ")
}

function getRecentPages(): RecentPage[] {
  try {
    const raw = localStorage.getItem(RECENT_PAGES_KEY)
    if (!raw) return []
    const parsed = JSON.parse(raw) as unknown
    return Array.isArray(parsed) ? (parsed as RecentPage[]).slice(0, MAX_RECENT_PAGES) : []
  } catch {
    return []
  }
}

function addRecentPage(pathname: string) {
  if (IGNORED_PATHS.some((p) => pathname.startsWith(p))) return
  const label = labelFromPath(pathname)
  const entry: RecentPage = { label, url: pathname }
  const existing = getRecentPages()
  const updated = [entry, ...existing.filter((p) => p.url !== pathname)].slice(0, MAX_RECENT_PAGES)
  localStorage.setItem(RECENT_PAGES_KEY, JSON.stringify(updated))
}

// ---------------------------------------------------------------------------
// Highlight matching text
// ---------------------------------------------------------------------------

function HighlightMatch({ text, query }: { text: string; query: string }) {
  if (!query || query.length < 2) return <>{text}</>
  const idx = text.toLowerCase().indexOf(query.toLowerCase())
  if (idx === -1) return <>{text}</>
  return (
    <>
      {text.slice(0, idx)}
      <span className="font-bold text-foreground">{text.slice(idx, idx + query.length)}</span>
      {text.slice(idx + query.length)}
    </>
  )
}

// ---------------------------------------------------------------------------
// Group results by type
// ---------------------------------------------------------------------------

function groupResults(results: SearchResultItem[]): Record<string, SearchResultItem[]> {
  const groups: Record<string, SearchResultItem[]> = {}
  for (const item of results) {
    if (!groups[item.type]) {
      groups[item.type] = []
    }
    groups[item.type].push(item)
  }
  return groups
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function GlobalSearch() {
  const [open, setOpen] = useState(false)
  const [inputValue, setInputValue] = useState("")
  const [debouncedQuery, setDebouncedQuery] = useState("")
  const [recentSearches, setRecentSearches] = useState<string[]>([])
  const [recentPages, setRecentPages] = useState<RecentPage[]>([])
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const navigate = useNavigate()
  const user = useAuthStore((state) => state.user)
  const isSuperuser = user?.isSuperuser ?? false

  // Track page visits for "Recent Pages".
  const pathname = useRouterState({ select: (state) => state.location.pathname })
  const prevPathRef = useRef(pathname)
  useEffect(() => {
    if (pathname !== prevPathRef.current) {
      prevPathRef.current = pathname
      addRecentPage(pathname)
    }
  }, [pathname])

  // Debounce the search query (300ms).
  const handleInputChange = useCallback((value: string) => {
    setInputValue(value)
    if (debounceRef.current) {
      clearTimeout(debounceRef.current)
    }
    debounceRef.current = setTimeout(() => {
      setDebouncedQuery(value)
    }, 300)
  }, [])

  // Clear the search input.
  const handleClear = useCallback(() => {
    setInputValue("")
    setDebouncedQuery("")
  }, [])

  // Keyboard shortcut: Cmd+K / Ctrl+K.
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault()
        setOpen((prev) => !prev)
      }
    }
    document.addEventListener("keydown", onKeyDown)
    return () => document.removeEventListener("keydown", onKeyDown)
  }, [])

  // Load recent searches/pages when dialog opens; reset input when it closes.
  useEffect(() => {
    if (open) {
      setRecentSearches(getRecentSearches())
      setRecentPages(getRecentPages())
    } else {
      setInputValue("")
      setDebouncedQuery("")
    }
  }, [open])

  const { data, isLoading, isFetching } = useGlobalSearch(debouncedQuery)
  const grouped = data?.results ? groupResults(data.results) : {}
  const hasResults = data?.results && data.results.length > 0
  const resultCount = data?.results?.length ?? 0
  const showLoading = (isLoading || isFetching) && debouncedQuery.length >= 2
  const showIdleState = !showLoading && debouncedQuery.length < 2

  // Filter navigation shortcuts that match the current query (client-side).
  const filteredNavGroups = useFilteredNavShortcuts(inputValue, isSuperuser)
  const hasNavMatches = filteredNavGroups.length > 0
  const isNavFiltering = inputValue.length >= 1 && inputValue.length < 2

  function handleSelect(item: SearchResultItem) {
    addRecentSearch(inputValue)
    setOpen(false)
    navigate({ to: item.url })
  }

  function handleRecentSelect(query: string) {
    setInputValue(query)
    setDebouncedQuery(query)
  }

  function handleNavSelect(url: string) {
    setOpen(false)
    navigate({ to: url })
  }

  function handleQuickAction(url: string) {
    setOpen(false)
    navigate({ to: url })
  }

  return (
    <>
      <Tooltip>
        <TooltipTrigger asChild>
          <Button variant="ghost" size="icon" className="size-8 text-muted-foreground" onClick={() => setOpen(true)}>
            <Search className="size-5" />
            <span className="sr-only">Search</span>
          </Button>
        </TooltipTrigger>
        <TooltipContent side="bottom">
          Search
          <kbd className="ml-2 inline-flex h-5 items-center rounded border border-border/60 bg-muted px-1 font-mono text-[0.6rem] font-medium text-muted-foreground">
            {navigator.platform?.includes("Mac") ? "⌘" : "Ctrl"}K
          </kbd>
        </TooltipContent>
      </Tooltip>

      <CommandDialog open={open} onOpenChange={setOpen} title="Global Search">
        <div className="relative">
          <CommandInput placeholder="Search or jump to a page..." value={inputValue} onValueChange={handleInputChange} />
          {inputValue.length > 0 && (
            <button type="button" onClick={handleClear} className="absolute right-3 top-1/2 -translate-y-1/2 rounded-sm p-0.5 text-muted-foreground hover:text-foreground">
              <X className="size-4" />
              <span className="sr-only">Clear search</span>
            </button>
          )}
        </div>
        <CommandList>
          {showLoading && (
            <div className="flex items-center justify-center py-6">
              <Loader2 className="size-5 animate-spin text-muted-foreground" />
            </div>
          )}

          {!showLoading && debouncedQuery.length >= 2 && !hasResults && !hasNavMatches && <CommandEmpty>No results found.</CommandEmpty>}

          {/* Idle state: recent pages + recent searches + navigation + quick actions */}
          {showIdleState && (
            <>
              {recentPages.length > 0 && (
                <CommandGroup heading="Recent Pages">
                  {recentPages.map((page) => (
                    <CommandItem key={`recent-page-${page.url}`} value={`recent-page-${page.label}`} onSelect={() => handleNavSelect(page.url)} className="cursor-pointer">
                      <History className="size-4 shrink-0 text-muted-foreground" />
                      <span className="truncate text-sm">{page.label}</span>
                      <span className="ml-auto truncate text-xs text-muted-foreground">{page.url}</span>
                    </CommandItem>
                  ))}
                </CommandGroup>
              )}
              {recentSearches.length > 0 && (
                <CommandGroup heading="Recent Searches">
                  {recentSearches.map((query) => (
                    <CommandItem key={query} value={`recent-${query}`} onSelect={() => handleRecentSelect(query)} className="cursor-pointer">
                      <Clock className="size-4 shrink-0 text-muted-foreground" />
                      <span className="truncate text-sm">{query}</span>
                    </CommandItem>
                  ))}
                </CommandGroup>
              )}
              {Object.entries(NAV_SHORTCUTS).map(([category, items]) => {
                const visibleItems = items.filter((item) => !item.adminOnly || isSuperuser)
                if (visibleItems.length === 0) return null
                return (
                  <CommandGroup key={category} heading={category}>
                    {visibleItems.map((item) => {
                      const NavIcon = item.icon
                      return (
                        <CommandItem key={item.url} value={`nav-${category}-${item.label}`} onSelect={() => handleNavSelect(item.url)} className="cursor-pointer">
                          <NavIcon className={`size-4 shrink-0 ${item.color}`} />
                          <span className="text-sm">{item.label}</span>
                        </CommandItem>
                      )
                    })}
                  </CommandGroup>
                )
              })}
              <CommandGroup heading="Quick Actions">
                {QUICK_ACTIONS.map((action) => {
                  const ActionIcon = action.icon
                  return (
                    <CommandItem key={action.url} value={`action-${action.label}`} onSelect={() => handleQuickAction(action.url)} className="cursor-pointer">
                      <div className="flex size-5 items-center justify-center rounded bg-muted">
                        <Plus className="size-3 text-muted-foreground" />
                      </div>
                      <ActionIcon className={`size-4 shrink-0 ${action.color}`} />
                      <span className="text-sm">{action.label}</span>
                    </CommandItem>
                  )
                })}
              </CommandGroup>
            </>
          )}

          {/* Matching navigation shortcuts while typing (before server search kicks in at 2 chars) */}
          {isNavFiltering &&
            hasNavMatches &&
            filteredNavGroups.map(([category, items]) => (
              <CommandGroup key={`nav-filter-${category}`} heading={category}>
                {items.map((item) => {
                  const NavIcon = item.icon
                  return (
                    <CommandItem key={item.url} value={`nav-${category}-${item.label}`} onSelect={() => handleNavSelect(item.url)} className="cursor-pointer">
                      <NavIcon className={`size-4 shrink-0 ${item.color}`} />
                      <span className="text-sm">{item.label}</span>
                    </CommandItem>
                  )
                })}
              </CommandGroup>
            ))}

          {/* Matching navigation shortcuts alongside server results */}
          {!showLoading &&
            debouncedQuery.length >= 2 &&
            hasNavMatches &&
            filteredNavGroups.map(([category, items]) => (
              <CommandGroup key={`nav-result-${category}`} heading={`Go to - ${category}`}>
                {items.map((item) => {
                  const NavIcon = item.icon
                  return (
                    <CommandItem key={item.url} value={`nav-${category}-${item.label}`} onSelect={() => handleNavSelect(item.url)} className="cursor-pointer">
                      <NavIcon className={`size-4 shrink-0 ${item.color}`} />
                      <div className="flex min-w-0 flex-1 flex-col">
                        <span className="truncate text-sm font-medium">
                          <HighlightMatch text={item.label} query={inputValue} />
                        </span>
                      </div>
                    </CommandItem>
                  )
                })}
              </CommandGroup>
            ))}

          {/* Result count */}
          {!showLoading && hasResults && (
            <div className="px-3 py-1.5 text-xs text-muted-foreground">
              {resultCount} {resultCount === 1 ? "result" : "results"} found
            </div>
          )}

          {/* Grouped results */}
          {!showLoading &&
            Object.entries(grouped).map(([type, items]) => {
              const meta = getTypeMeta(type)
              const Icon = meta.icon
              return (
                <CommandGroup key={type} heading={meta.label}>
                  {items.map((item) => (
                    <CommandItem key={`${item.type}-${item.id}`} value={`${item.type}-${item.id}-${item.label}`} onSelect={() => handleSelect(item)} className="cursor-pointer">
                      <Icon className={`size-4 shrink-0 ${meta.color}`} />
                      <div className="flex min-w-0 flex-1 flex-col">
                        <span className="truncate text-sm font-medium">
                          <HighlightMatch text={item.label} query={debouncedQuery} />
                        </span>
                        {item.description && (
                          <span className="truncate text-xs text-muted-foreground">
                            <HighlightMatch text={item.description} query={debouncedQuery} />
                          </span>
                        )}
                      </div>
                    </CommandItem>
                  ))}
                </CommandGroup>
              )
            })}
        </CommandList>

        {/* Keyboard navigation hints */}
        <CommandSeparator />
        <div className="flex items-center justify-center gap-4 border-t px-3 py-2 text-xs text-muted-foreground">
          <span>
            <kbd className="rounded border bg-muted px-1 py-0.5 font-mono text-[0.65rem]">↑↓</kbd> Navigate
          </span>
          <span>
            <kbd className="rounded border bg-muted px-1 py-0.5 font-mono text-[0.65rem]">Enter</kbd> Select
          </span>
          <span>
            <kbd className="rounded border bg-muted px-1 py-0.5 font-mono text-[0.65rem]">Esc</kbd> Close
          </span>
        </div>
      </CommandDialog>
    </>
  )
}

// ---------------------------------------------------------------------------
// Hook: filter navigation shortcuts by query
// ---------------------------------------------------------------------------

function useFilteredNavShortcuts(query: string, isSuperuser: boolean): [string, NavShortcut[]][] {
  const q = query.trim().toLowerCase()
  if (q.length === 0) return []

  const results: [string, NavShortcut[]][] = []
  for (const [category, items] of Object.entries(NAV_SHORTCUTS)) {
    const matched = items.filter((item) => {
      if (item.adminOnly && !isSuperuser) return false
      if (item.label.toLowerCase().includes(q)) return true
      if (item.keywords?.some((kw) => kw.toLowerCase().includes(q))) return true
      return false
    })
    if (matched.length > 0) {
      results.push([category, matched])
    }
  }
  return results
}
