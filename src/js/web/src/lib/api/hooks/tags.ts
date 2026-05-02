import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { client } from "@/lib/generated/api/client.gen"

// ── Types ──────────────────────────────────────────────────────────────

export interface Tag {
  id: string
  name: string
  slug: string
  createdAt: string
  updatedAt: string
}

export interface TagCreate {
  name: string
}

export interface TagUpdate {
  name?: string | null
}

// ── Tag List ─────────────────────────────────────────────────────────

export interface UseTagsOptions {
  page?: number
  pageSize?: number
  search?: string
  orderBy?: string
  sortOrder?: "asc" | "desc"
}

export function useTags(pageOrOptions: number | UseTagsOptions = 1, pageSizeArg = 20) {
  const opts: UseTagsOptions =
    typeof pageOrOptions === "number" ? { page: pageOrOptions, pageSize: pageSizeArg } : pageOrOptions
  const { page = 1, pageSize = 20, search, orderBy, sortOrder } = opts

  return useQuery({
    queryKey: ["tags", page, pageSize, search, orderBy, sortOrder],
    queryFn: async () => {
      const query: Record<string, unknown> = { currentPage: page, pageSize }
      if (search) {
        query.searchString = search
        query.searchIgnoreCase = true
      }
      if (orderBy) query.orderBy = orderBy
      if (sortOrder) query.sortOrder = sortOrder
      const response = await client.get({
        url: "/api/tags",
        query,
        security: [{ scheme: "bearer", type: "http" }],
      } as never)
      return (response as { data: unknown }).data as { items: Tag[]; total: number }
    },
  })
}

// ── Tag Detail ───────────────────────────────────────────────────────

export function useTag(tagId: string) {
  return useQuery({
    queryKey: ["tag", tagId],
    queryFn: async () => {
      const response = await client.get({
        url: `/api/tags/${tagId}`,
        security: [{ scheme: "bearer", type: "http" }],
      } as never)
      return (response as { data: unknown }).data as Tag
    },
    enabled: !!tagId,
  })
}

// ── Tag Mutations ────────────────────────────────────────────────────

export function useCreateTag() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: TagCreate) => {
      const response = await client.post({
        url: "/api/tags",
        body: payload,
        security: [{ scheme: "bearer", type: "http" }],
      } as never)
      return (response as { data: unknown }).data as Tag
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
      const response = await client.patch({
        url: `/api/tags/${tagId}`,
        body: payload,
        security: [{ scheme: "bearer", type: "http" }],
      } as never)
      return (response as { data: unknown }).data as Tag
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
      await client.delete({
        url: `/api/tags/${tagId}`,
        security: [{ scheme: "bearer", type: "http" }],
      } as never)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["tags"] })
      toast.success("Tag deleted")
    },
    onError: (error) => {
      toast.error("Unable to delete tag", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}
