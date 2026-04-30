import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  deleteTeam,
  listTeams,
  type Team,
} from "@/lib/generated/api"

// ── Team List ─────────────────────────────────────────────────────────

export interface UseTeamsOptions {
  page?: number
  pageSize?: number
  search?: string
  orderBy?: string
  sortOrder?: "asc" | "desc" | null
}

export function useTeams(options: UseTeamsOptions = {}) {
  const { page = 1, pageSize = 50, search, orderBy, sortOrder } = options

  return useQuery({
    queryKey: ["teams", page, pageSize, search, orderBy, sortOrder],
    queryFn: async () => {
      const query: Record<string, unknown> = { currentPage: page, pageSize }
      if (search) {
        query.searchString = search
        query.searchIgnoreCase = true
      }
      if (orderBy) query.orderBy = orderBy
      if (sortOrder) query.sortOrder = sortOrder
      const response = await listTeams({ query } as never)
      const data = response.data
      if (Array.isArray(data)) return { items: data as Team[], total: data.length }
      return {
        items: (data as { items?: Team[] })?.items ?? [],
        total: (data as { total?: number })?.total ?? 0,
      }
    },
  })
}

// ── Delete Team ───────────────────────────────────────────────────────

export function useDeleteTeam() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (teamId: string) => {
      await deleteTeam({ path: { team_id: teamId } })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["teams"] })
      toast.success("Team deleted")
    },
    onError: (error) => {
      toast.error("Unable to delete team", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}
