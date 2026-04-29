import { useCallback, useMemo, useState } from "react"

export interface TableSelection<T> {
  /** Set of currently selected item IDs */
  selectedIds: Set<string>
  /** Number of selected items */
  selectedCount: number
  /** Check whether a specific item is selected */
  isSelected: (id: string) => boolean
  /** Toggle selection of a single item */
  toggle: (id: string) => void
  /** Select all visible items */
  selectAll: () => void
  /** Deselect every item */
  deselectAll: () => void
  /** Whether every visible item is currently selected */
  allSelected: boolean
  /** Whether some but not all visible items are selected (for indeterminate checkbox) */
  someSelected: boolean
  /** Return the subset of items whose IDs are selected */
  selectedItems: T[]
}

/**
 * Generic hook for managing row selection in a data table.
 *
 * @param items  - The visible (possibly filtered/paginated) list of items.
 * @param getId  - Accessor that returns the unique ID string for an item.
 */
export function useTableSelection<T>(items: T[], getId: (item: T) => string): TableSelection<T> {
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())

  const visibleIds = useMemo(() => new Set(items.map(getId)), [items, getId])

  const isSelected = useCallback((id: string) => selectedIds.has(id), [selectedIds])

  const toggle = useCallback((id: string) => {
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

  const selectAll = useCallback(() => {
    setSelectedIds((prev) => {
      const next = new Set(prev)
      for (const id of visibleIds) {
        next.add(id)
      }
      return next
    })
  }, [visibleIds])

  const deselectAll = useCallback(() => {
    setSelectedIds(new Set())
  }, [])

  const selectedCount = useMemo(() => {
    let count = 0
    for (const id of selectedIds) {
      if (visibleIds.has(id)) count++
    }
    return count
  }, [selectedIds, visibleIds])

  const allSelected = visibleIds.size > 0 && selectedCount === visibleIds.size
  const someSelected = selectedCount > 0 && !allSelected

  const selectedItems = useMemo(
    () => items.filter((item) => selectedIds.has(getId(item))),
    [items, selectedIds, getId],
  )

  return {
    selectedIds,
    selectedCount,
    isSelected,
    toggle,
    selectAll,
    deselectAll,
    allSelected,
    someSelected,
    selectedItems,
  }
}
