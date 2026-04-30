import { useNavigate } from "@tanstack/react-router"
import {
  Clock,
  LifeBuoy,
  Loader2,
  MapPin,
  Monitor,
  Phone,
  Plus,
  Printer,
  Search,
  Users,
  UserRound,
  X,
} from "lucide-react"
import { useCallback, useEffect, useRef, useState } from "react"
import { Button } from "@/components/ui/button"
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from "@/components/ui/command"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useGlobalSearch, type SearchResultItem } from "@/lib/api/hooks/search"

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
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const navigate = useNavigate()

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

  // Load recent searches when dialog opens; reset input when it closes.
  useEffect(() => {
    if (open) {
      setRecentSearches(getRecentSearches())
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

  function handleSelect(item: SearchResultItem) {
    addRecentSearch(inputValue)
    setOpen(false)
    navigate({ to: item.url })
  }

  function handleRecentSelect(query: string) {
    setInputValue(query)
    setDebouncedQuery(query)
  }

  function handleQuickAction(url: string) {
    setOpen(false)
    navigate({ to: url })
  }

  return (
    <>
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            variant="ghost"
            size="icon"
            className="size-8 text-muted-foreground"
            onClick={() => setOpen(true)}
          >
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
          <CommandInput
            placeholder="Search devices, teams, tickets, extensions..."
            value={inputValue}
            onValueChange={handleInputChange}
          />
          {inputValue.length > 0 && (
            <button
              type="button"
              onClick={handleClear}
              className="absolute right-3 top-1/2 -translate-y-1/2 rounded-sm p-0.5 text-muted-foreground hover:text-foreground"
            >
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

          {!showLoading && debouncedQuery.length >= 2 && !hasResults && (
            <CommandEmpty>No results found.</CommandEmpty>
          )}

          {/* Idle state: recent searches + quick actions */}
          {showIdleState && (
            <>
              {recentSearches.length > 0 && (
                <CommandGroup heading="Recent">
                  {recentSearches.map((query) => (
                    <CommandItem
                      key={query}
                      value={`recent-${query}`}
                      onSelect={() => handleRecentSelect(query)}
                      className="cursor-pointer"
                    >
                      <Clock className="size-4 shrink-0 text-muted-foreground" />
                      <span className="truncate text-sm">{query}</span>
                    </CommandItem>
                  ))}
                </CommandGroup>
              )}
              <CommandGroup heading="Quick Actions">
                {QUICK_ACTIONS.map((action) => {
                  const ActionIcon = action.icon
                  return (
                    <CommandItem
                      key={action.url}
                      value={`action-${action.label}`}
                      onSelect={() => handleQuickAction(action.url)}
                      className="cursor-pointer"
                    >
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
                    <CommandItem
                      key={`${item.type}-${item.id}`}
                      value={`${item.type}-${item.id}-${item.label}`}
                      onSelect={() => handleSelect(item)}
                      className="cursor-pointer"
                    >
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
          <span><kbd className="rounded border bg-muted px-1 py-0.5 font-mono text-[0.65rem]">↑↓</kbd> Navigate</span>
          <span><kbd className="rounded border bg-muted px-1 py-0.5 font-mono text-[0.65rem]">Enter</kbd> Select</span>
          <span><kbd className="rounded border bg-muted px-1 py-0.5 font-mono text-[0.65rem]">Esc</kbd> Close</span>
        </div>
      </CommandDialog>
    </>
  )
}
