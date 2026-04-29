import { useNavigate } from "@tanstack/react-router"
import {
  LifeBuoy,
  Loader2,
  MapPin,
  Monitor,
  Phone,
  Printer,
  Search,
  Users,
  UserRound,
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
} from "@/components/ui/command"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useGlobalSearch, type SearchResultItem } from "@/lib/api/hooks/search"

// ---------------------------------------------------------------------------
// Type icon & label mappings
// ---------------------------------------------------------------------------

const TYPE_META: Record<string, { icon: React.ElementType; label: string }> = {
  team: { icon: Users, label: "Teams" },
  device: { icon: Monitor, label: "Devices" },
  ticket: { icon: LifeBuoy, label: "Tickets" },
  extension: { icon: Phone, label: "Extensions" },
  phone_number: { icon: Phone, label: "Phone Numbers" },
  fax_number: { icon: Printer, label: "Fax Numbers" },
  location: { icon: MapPin, label: "Locations" },
  user: { icon: UserRound, label: "Users" },
}

function getTypeMeta(type: string) {
  return TYPE_META[type] ?? { icon: Search, label: type }
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

  // Reset input when dialog closes.
  useEffect(() => {
    if (!open) {
      setInputValue("")
      setDebouncedQuery("")
    }
  }, [open])

  const { data, isLoading, isFetching } = useGlobalSearch(debouncedQuery)
  const grouped = data?.results ? groupResults(data.results) : {}
  const hasResults = data?.results && data.results.length > 0
  const showLoading = (isLoading || isFetching) && debouncedQuery.length >= 2

  function handleSelect(item: SearchResultItem) {
    setOpen(false)
    navigate({ to: item.url })
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
        <CommandInput
          placeholder="Search devices, teams, tickets, extensions..."
          value={inputValue}
          onValueChange={handleInputChange}
        />
        <CommandList>
          {showLoading && (
            <div className="flex items-center justify-center py-6">
              <Loader2 className="size-5 animate-spin text-muted-foreground" />
            </div>
          )}

          {!showLoading && debouncedQuery.length >= 2 && !hasResults && (
            <CommandEmpty>No results found.</CommandEmpty>
          )}

          {!showLoading && debouncedQuery.length < 2 && (
            <div className="py-6 text-center text-sm text-muted-foreground">
              Type at least 2 characters to search...
            </div>
          )}

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
                      <Icon className="size-4 shrink-0 text-muted-foreground" />
                      <div className="flex min-w-0 flex-1 flex-col">
                        <span className="truncate text-sm font-medium">{item.label}</span>
                        {item.description && (
                          <span className="truncate text-xs text-muted-foreground">
                            {item.description}
                          </span>
                        )}
                      </div>
                    </CommandItem>
                  ))}
                </CommandGroup>
              )
            })}
        </CommandList>
      </CommandDialog>
    </>
  )
}
