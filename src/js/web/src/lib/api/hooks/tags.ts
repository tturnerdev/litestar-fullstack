import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { createTag as createTagApi, deleteTag as deleteTagApi, getTag, listTags, type Tag, type TagCreate, type TagUpdate, updateTag as updateTagApi } from "@/lib/generated/api"

export type { Tag, TagCreate, TagUpdate }

// ── Tag List ─────────────────────────────────────────────────────────

export interface UseTagsOptions {
  page?: number
  pageSize?: number
  search?: string
  orderBy?: string
  sortOrder?: "asc" | "desc"
}

export function useTags(pageOrOptions: number | UseTagsOptions = 1, pageSizeArg = 20) {
  const opts: UseTagsOptions = typeof pageOrOptions === "number" ? { page: pageOrOptions, pageSize: pageSizeArg } : pageOrOptions
  const { page = 1, pageSize = 20, search, orderBy, sortOrder } = opts

  return useQuery({
    queryKey: ["tags", page, pageSize, search, orderBy, sortOrder],
    queryFn: async () => {
      const response = await listTags({
        query: {
          currentPage: page,
          pageSize,
          searchString: search,
          searchIgnoreCase: search ? true : undefined,
          orderBy,
          sortOrder,
        },
      })
      return response.data as { items: Tag[]; total: number }
    },
    staleTime: 10 * 60 * 1000,
  })
}

// ── Tag Detail ───────────────────────────────────────────────────────

export function useTag(tagId: string) {
  return useQuery({
    queryKey: ["tag", tagId],
    queryFn: async () => {
      const response = await getTag({
        path: { tag_id: tagId },
      })
      return response.data as Tag
    },
    enabled: !!tagId,
  })
}

// ── Tag Mutations ────────────────────────────────────────────────────

export function useCreateTag() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: TagCreate) => {
      const response = await createTagApi({
        body: payload,
      })
      return response.data as Tag
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["tags"] })
      toast.success("Tag created")
    },
    onError: (error) => {
      toast.error("Unable to create tag", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useUpdateTag(tagId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: TagUpdate) => {
      const response = await updateTagApi({
        path: { tag_id: tagId },
        body: payload,
      })
      return response.data as Tag
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["tags"] })
      queryClient.invalidateQueries({ queryKey: ["tag", tagId] })
      toast.success("Tag updated")
    },
    onError: (error) => {
      toast.error("Unable to update tag", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useDeleteTag() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (tagId: string) => {
      await deleteTagApi({
        path: { tag_id: tagId },
      })
    },
    onSuccess: (_data, tagId) => {
      queryClient.invalidateQueries({ queryKey: ["tags"] })
      queryClient.invalidateQueries({ queryKey: ["tag", tagId] })
      toast.success("Tag deleted")
    },
    onError: (error) => {
      toast.error("Unable to delete tag", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}
