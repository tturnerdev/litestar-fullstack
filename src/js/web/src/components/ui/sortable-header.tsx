import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react"
import { TableHead } from "@/components/ui/table"
import { cn } from "@/lib/utils"

export type SortDirection = "asc" | "desc" | null

interface SortableHeaderProps {
  label: string
  sortKey: string
  currentSort: string | null
  currentDirection: SortDirection
  onSort: (key: string) => void
  className?: string
}

export function SortableHeader({ label, sortKey, currentSort, currentDirection, onSort, className }: SortableHeaderProps) {
  const isActive = currentSort === sortKey

  return (
    <TableHead className={cn("cursor-pointer select-none", className)} onClick={() => onSort(sortKey)}>
      <div className="flex items-center gap-1">
        {label}
        {isActive && currentDirection === "asc" ? (
          <ArrowUp className="h-3.5 w-3.5 text-foreground" />
        ) : isActive && currentDirection === "desc" ? (
          <ArrowDown className="h-3.5 w-3.5 text-foreground" />
        ) : (
          <ArrowUpDown className="h-3.5 w-3.5 text-muted-foreground/50" />
        )}
      </div>
    </TableHead>
  )
}

/** Cycle sort direction: null -> asc -> desc -> null */
export function nextSortDirection(currentSort: string | null, currentDirection: SortDirection, key: string): { sort: string | null; direction: SortDirection } {
  if (currentSort !== key) {
    return { sort: key, direction: "asc" }
  }
  if (currentDirection === "asc") {
    return { sort: key, direction: "desc" }
  }
  return { sort: null, direction: null }
}
