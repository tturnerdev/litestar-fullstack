import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { client } from "@/lib/generated/api/client.gen"

// ── Types ──────────────────────────────────────────────────────────────

export interface ConnectionList {
  id: string
  teamId: string
  name: string
  connectionType: string
  provider: string
  status: string
  isEnabled: boolean
  host?: string | null
  port?: number | null
  authType?: string | null
  description?: string | null
  lastHealthCheck?: string | null
  lastError?: string | null
  createdAt?: string | null
  updatedAt?: string | null
}

export interface ConnectionDetail {
  id: string
  teamId: string
  name: string
  connectionType: string
  provider: string
  status: string
  authType: string
  isEnabled: boolean
  host?: string | null
  port?: number | null
  description?: string | null
  credentialFields: string[]
  settings?: Record<string, unknown> | null
  lastHealthCheck?: string | null
  lastError?: string | null
  createdAt?: string | null
  updatedAt?: string | null
}

export interface ConnectionCreate {
  name: string
  connectionType: string
  provider: string
  teamId?: string | null
  host?: string | null
  port?: number | null
  authType?: string
  credentials?: Record<string, unknown> | null
  settings?: Record<string, unknown> | null
  description?: string | null
  isEnabled?: boolean
}

export interface ConnectionUpdate {
  name?: string
  connectionType?: string
  provider?: string
  host?: string | null
  port?: number | null
  authType?: string
  credentials?: Record<string, unknown> | null
  settings?: Record<string, unknown> | null
  description?: string | null
  isEnabled?: boolean
}

// ── Connection List ───────────────────────────────────────────────────

export interface UseConnectionsOptions {
  page?: number
  pageSize?: number
  search?: string
  teamId?: string
  orderBy?: string
  sortOrder?: "asc" | "desc"
}

export function useConnections(pageOrOptions: number | UseConnectionsOptions = 1, pageSizeArg = 20) {
  const opts: UseConnectionsOptions =
    typeof pageOrOptions === "number" ? { page: pageOrOptions, pageSize: pageSizeArg } : pageOrOptions
  const { page = 1, pageSize = 20, search, teamId, orderBy, sortOrder } = opts

  return useQuery({
    queryKey: ["connections", page, pageSize, search, teamId, orderBy, sortOrder],
    queryFn: async () => {
      const query: Record<string, unknown> = { currentPage: page, pageSize }
      if (search) {
        query.searchString = search
        query.searchIgnoreCase = true
      }
      if (teamId) query.teamId = teamId
      if (orderBy) query.orderBy = orderBy
      if (sortOrder) query.sortOrder = sortOrder
      const response = await client.get({
        url: "/api/connections",
        query,
        security: [{ scheme: "bearer", type: "http" }],
      } as never)
      return (response as { data: unknown }).data as { items: ConnectionList[]; total: number }
    },
  })
}

// ── Connection Detail ─────────────────────────────────────────────────

export function useConnection(connectionId: string) {
  return useQuery({
    queryKey: ["connection", connectionId],
    queryFn: async () => {
      const response = await client.get({
        url: `/api/connections/${connectionId}`,
        security: [{ scheme: "bearer", type: "http" }],
      } as never)
      return (response as { data: unknown }).data as ConnectionDetail
    },
    enabled: !!connectionId,
  })
}

// ── Connection Mutations ──────────────────────────────────────────────

export function useCreateConnection() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: ConnectionCreate) => {
      const response = await client.post({
        url: "/api/connections",
        body: payload,
        security: [{ scheme: "bearer", type: "http" }],
      } as never)
      return (response as { data: unknown }).data as ConnectionList
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["connections"] })
      toast.success("Connection created")
    },
    onError: (error) => {
      toast.error("Unable to create connection", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useUpdateConnection(connectionId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: ConnectionUpdate) => {
      const response = await client.patch({
        url: `/api/connections/${connectionId}`,
        body: payload,
        security: [{ scheme: "bearer", type: "http" }],
      } as never)
      return (response as { data: unknown }).data as ConnectionDetail
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["connections"] })
      queryClient.invalidateQueries({ queryKey: ["connection", connectionId] })
      toast.success("Connection updated")
    },
    onError: (error) => {
      toast.error("Unable to update connection", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useDeleteConnection() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (connectionId: string) => {
      await client.delete({
        url: `/api/connections/${connectionId}`,
        security: [{ scheme: "bearer", type: "http" }],
      } as never)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["connections"] })
      toast.success("Connection deleted")
    },
    onError: (error) => {
      toast.error("Unable to delete connection", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

/**
 * Update any connection by passing connectionId as part of the mutation argument.
 * Useful for bulk operations where the target connection is not known at hook call time.
 */
export function useUpdateAnyConnection() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({ connectionId, payload }: { connectionId: string; payload: ConnectionUpdate }) => {
      const response = await client.patch({
        url: `/api/connections/${connectionId}`,
        body: payload,
        security: [{ scheme: "bearer", type: "http" }],
      } as never)
      return (response as { data: unknown }).data as ConnectionDetail
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["connections"] })
    },
    onError: (error) => {
      toast.error("Unable to update connection", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useTestConnection(connectionId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async () => {
      const response = await client.post({
        url: `/api/connections/${connectionId}/test`,
        security: [{ scheme: "bearer", type: "http" }],
      } as never)
      return (response as { data: unknown }).data as { message: string }
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["connection", connectionId] })
      queryClient.invalidateQueries({ queryKey: ["connections"] })
      toast.success(data.message)
    },
    onError: (error) => {
      toast.error("Connection test failed", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

/**
 * Test any connection by passing connectionId as a mutation argument.
 * Useful for list pages where the target connection is not known at hook call time.
 */
export function useTestAnyConnection() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (connectionId: string) => {
      const response = await client.post({
        url: `/api/connections/${connectionId}/test`,
        security: [{ scheme: "bearer", type: "http" }],
      } as never)
      return (response as { data: unknown }).data as { message: string }
    },
    onSuccess: (data, connectionId) => {
      queryClient.invalidateQueries({ queryKey: ["connection", connectionId] })
      queryClient.invalidateQueries({ queryKey: ["connections"] })
      toast.success(data.message)
    },
    onError: (error) => {
      toast.error("Connection test failed", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}
