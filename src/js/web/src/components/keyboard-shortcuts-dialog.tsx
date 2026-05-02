import type { LucideIcon } from "lucide-react"
import { CircleHelp, Compass, Keyboard, Layout, Search, Zap } from "lucide-react"
import { useMemo, useState } from "react"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { Separator } from "@/components/ui/separator"
import { cn } from "@/lib/utils"

interface ShortcutEntry {
  keys: string[]
  description: string
}

interface ShortcutGroup {
  category: string
  shortcuts: ShortcutEntry[]
}

interface KeyboardShortcutsDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  groups: ShortcutGroup[]
}

const CATEGORY_ICONS: Record<string, LucideIcon> = {
  Navigation: Compass,
  General: Layout,
  Actions: Zap,
  Help: CircleHelp,
}

function Kbd({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <kbd
      className={cn(
        "inline-flex h-5 min-w-5 items-center justify-center rounded border border-border bg-muted px-1.5 font-mono text-[0.6875rem] font-medium text-muted-foreground",
        className,
      )}
    >
      {children}
    </kbd>
  )
}

export function KeyboardShortcutsDialog({ open, onOpenChange, groups }: KeyboardShortcutsDialogProps) {
  const [search, setSearch] = useState("")

  const totalShortcuts = useMemo(() => groups.reduce((sum, g) => sum + g.shortcuts.length, 0), [groups])

  const filteredGroups = useMemo(() => {
    if (!search.trim()) return groups
    const query = search.toLowerCase()
    return groups
      .map((group) => ({
        ...group,
        shortcuts: group.shortcuts.filter((s) => s.description.toLowerCase().includes(query)),
      }))
      .filter((group) => group.shortcuts.length > 0)
  }, [groups, search])

  return (
    <Dialog
      open={open}
      onOpenChange={(v) => {
        onOpenChange(v)
        if (!v) setSearch("")
      }}
    >
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Keyboard className="size-4" />
            Keyboard shortcuts
          </DialogTitle>
          <DialogDescription>Navigate and take actions quickly. {totalShortcuts} shortcuts available.</DialogDescription>
        </DialogHeader>

        <div className="relative">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input placeholder="Search shortcuts..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-9 h-9" />
        </div>

        <div className="max-h-[60vh] overflow-y-auto space-y-4 py-2">
          {filteredGroups.length === 0 ? (
            <EmptyState
              icon={Keyboard}
              variant="no-results"
              title="No shortcuts found"
              description={`No shortcuts match "${search}". Try a different search term.`}
              className="border-0 py-8"
            />
          ) : (
            filteredGroups.map((group, groupIndex) => {
              const CategoryIcon = CATEGORY_ICONS[group.category]
              return (
                <div key={group.category}>
                  {groupIndex > 0 && <Separator className="mb-4" />}
                  <h4 className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    {CategoryIcon && <CategoryIcon className="size-3.5" />}
                    {group.category}
                  </h4>
                  <div className="space-y-1">
                    {group.shortcuts.map((shortcut, shortcutIndex) => (
                      <div
                        key={shortcut.description}
                        className={cn("flex items-center justify-between rounded-md px-2 py-1.5 text-sm hover:bg-muted/50", shortcutIndex % 2 === 1 && "bg-muted/30")}
                      >
                        <span className="text-foreground">{shortcut.description}</span>
                        <div className="flex items-center gap-1">
                          {shortcut.keys.map((key, i) => (
                            <span key={`${shortcut.description}-${key}-${i}`} className="flex items-center gap-1">
                              {i > 0 && <span className="text-xs text-muted-foreground">+</span>}
                              <Kbd>{key}</Kbd>
                            </span>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )
            })
          )}
        </div>

        <div className="flex justify-end">
          <span className="text-[0.6875rem] text-muted-foreground">Press Esc to close</span>
        </div>
      </DialogContent>
    </Dialog>
  )
}
