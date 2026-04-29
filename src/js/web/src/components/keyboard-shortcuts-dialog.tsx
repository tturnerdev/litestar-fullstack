import { Keyboard } from "lucide-react"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog"
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
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Keyboard className="size-4" />
            Keyboard shortcuts
          </DialogTitle>
          <DialogDescription>Navigate and take actions quickly with keyboard shortcuts.</DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-2">
          {groups.map((group) => (
            <div key={group.category}>
              <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">{group.category}</h4>
              <div className="space-y-1">
                {group.shortcuts.map((shortcut) => (
                  <div key={shortcut.description} className="flex items-center justify-between rounded-md px-2 py-1.5 text-sm hover:bg-muted/50">
                    <span className="text-foreground">{shortcut.description}</span>
                    <div className="flex items-center gap-1">
                      {shortcut.keys.map((key, i) => (
                        <span key={`${shortcut.description}-${key}-${i}`} className="flex items-center gap-1">
                          {i > 0 && <span className="text-xs text-muted-foreground">then</span>}
                          <Kbd>{key}</Kbd>
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </DialogContent>
    </Dialog>
  )
}
