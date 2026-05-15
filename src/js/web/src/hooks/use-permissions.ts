import { useQuery } from "@tanstack/react-query"
import { useCallback, useMemo } from "react"
import { useAuthStore } from "@/lib/auth"
import { listTeamPermissionsOptions } from "@/lib/generated/api/@tanstack/react-query.gen"
import type { FeatureArea } from "@/lib/generated/api"
import { buildDefaultPermissions, getParentArea, mergeServerPermissions } from "@/lib/permissions"

export function usePermissions() {
  const user = useAuthStore((s) => s.user)
  const currentTeam = useAuthStore((s) => s.currentTeam)

  const userTeam = useMemo(
    () => user?.teams?.find((t) => t.teamId === currentTeam?.id),
    [user?.teams, currentTeam?.id],
  )
  const userRole = userTeam?.role ?? "MEMBER"

  const { data, isLoading } = useQuery({
    ...listTeamPermissionsOptions({
      path: { team_id: currentTeam?.id ?? "" },
    }),
    enabled: !!currentTeam?.id && !user?.isSuperuser,
    staleTime: 5 * 60 * 1000,
  })

  const matrix = useMemo(() => {
    if (!data || user?.isSuperuser) return buildDefaultPermissions()
    return mergeServerPermissions(data)
  }, [data, user?.isSuperuser])

  const canEdit = useCallback(
    (area: FeatureArea): boolean => {
      if (user?.isSuperuser) return true
      if (!currentTeam) return false
      const perm = matrix[userRole]?.[area]
      if (perm !== undefined) return perm.canEdit
      const parent = getParentArea(area)
      if (parent) return matrix[userRole]?.[parent]?.canEdit ?? false
      return false
    },
    [user?.isSuperuser, currentTeam, userRole, matrix],
  )

  const canView = useCallback(
    (area: FeatureArea): boolean => {
      if (user?.isSuperuser) return true
      if (!currentTeam) return true
      const perm = matrix[userRole]?.[area]
      if (perm !== undefined) return perm.canView
      const parent = getParentArea(area)
      if (parent) return matrix[userRole]?.[parent]?.canView ?? true
      return true
    },
    [user?.isSuperuser, currentTeam, userRole, matrix],
  )

  return { canEdit, canView, isLoading }
}
