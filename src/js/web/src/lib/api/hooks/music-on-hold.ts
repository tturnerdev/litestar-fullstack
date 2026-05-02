import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  type AdminListMusicOnHoldData,
  adminCreateMusicOnHold,
  adminDeleteMusicOnHold,
  adminGetMusicOnHold,
  adminListMusicOnHold,
  adminUpdateMusicOnHold,
  type MusicOnHoldCreate,
  type MusicOnHoldDetail,
  type MusicOnHoldList,
  type MusicOnHoldUpdate,
} from "@/lib/generated/api"

// ---------------------------------------------------------------------------
// Admin: List Music on Hold
// ---------------------------------------------------------------------------

export function useAdminMusicOnHold(page = 1, pageSize = 25, search?: string) {
  return useQuery({
    queryKey: ["admin", "music-on-hold", page, pageSize, search],
    queryFn: async () => {
      const query = {
        currentPage: page,
        pageSize,
        searchString: search,
        searchIgnoreCase: search ? true : undefined,
      } as unknown as AdminListMusicOnHoldData["query"]
      const response = await adminListMusicOnHold({ query })
      return response.data as { items: MusicOnHoldList[]; total: number }
    },
  })
}

// ---------------------------------------------------------------------------
// Admin: Get Music on Hold Detail
// ---------------------------------------------------------------------------

export function useAdminMusicOnHoldDetail(mohId: string) {
  return useQuery({
    queryKey: ["admin", "music-on-hold-detail", mohId],
    queryFn: async () => {
      const response = await adminGetMusicOnHold({
        path: { moh_id: mohId },
      })
      return response.data as MusicOnHoldDetail
    },
    enabled: !!mohId,
  })
}

// ---------------------------------------------------------------------------
// Admin: Create Music on Hold
// ---------------------------------------------------------------------------

export function useCreateMusicOnHold() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: MusicOnHoldCreate) => {
      const response = await adminCreateMusicOnHold({ body: payload })
      return response.data as MusicOnHoldDetail
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin", "music-on-hold"] })
      toast.success("Music on Hold class created")
    },
    onError: (error) => {
      toast.error("Unable to create Music on Hold class", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

// ---------------------------------------------------------------------------
// Admin: Update Music on Hold
// ---------------------------------------------------------------------------

export function useUpdateMusicOnHold(mohId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: MusicOnHoldUpdate) => {
      const response = await adminUpdateMusicOnHold({
        path: { moh_id: mohId },
        body: payload,
      })
      return response.data as MusicOnHoldDetail
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin", "music-on-hold"] })
      queryClient.invalidateQueries({ queryKey: ["admin", "music-on-hold-detail", mohId] })
      toast.success("Music on Hold class updated")
    },
    onError: (error) => {
      toast.error("Unable to update Music on Hold class", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

// ---------------------------------------------------------------------------
// Admin: Delete Music on Hold
// ---------------------------------------------------------------------------

export function useDeleteMusicOnHold() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (mohId: string) => {
      const response = await adminDeleteMusicOnHold({
        path: { moh_id: mohId },
      })
      return response.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin", "music-on-hold"] })
      toast.success("Music on Hold class deleted")
    },
    onError: (error) => {
      toast.error("Unable to delete Music on Hold class", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}
