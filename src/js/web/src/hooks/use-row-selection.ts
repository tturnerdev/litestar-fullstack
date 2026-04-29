import { useCallback, useEffect, useState } from "react"

interface UseRowSelectionReturn {
  selectedIds: Set<string>
  isSelected: (id: string) => boolean
  toggle: (id: string) => void
  selectAll: (ids: string[]) => void
  deselectAll: () => void
  isAllSelected: (ids: string[]) => boolean
  isPartiallySelected: (ids: string[]) => boolean
  selectionCount: number
}

export function useRowSelection(page: number): UseRowSelectionReturn {
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())

  // Clear selection when page changes
  useEffect(() => {
    setSelectedIds(new Set())
  }, [page])

  const isSelected = useCallback(
    (id: string) => selectedIds.has(id),
    [selectedIds],
  )

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

  const selectAll = useCallback((ids: string[]) => {
    setSelectedIds(new Set(ids))
  }, [])

  const deselectAll = useCallback(() => {
    setSelectedIds(new Set())
  }, [])

  const isAllSelected = useCallback(
    (ids: string[]) => ids.length > 0 && ids.every((id) => selectedIds.has(id)),
    [selectedIds],
  )

  const isPartiallySelected = useCallback(
    (ids: string[]) => ids.some((id) => selectedIds.has(id)) && !ids.every((id) => selectedIds.has(id)),
    [selectedIds],
  )

  return {
    selectedIds,
    isSelected,
    toggle,
    selectAll,
    deselectAll,
    isAllSelected,
    isPartiallySelected,
    selectionCount: selectedIds.size,
  }
}
