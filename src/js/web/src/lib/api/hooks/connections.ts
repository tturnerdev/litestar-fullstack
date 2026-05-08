import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  type ConnectionCreate,
  type ConnectionDetail,
  type ConnectionList,
  type ConnectionUpdate,
  createConnection as createConnectionApi,
  deleteConnection as deleteConnectionApi,
  getConnection,
  listConnections,
  type Message,
  testConnection as testConnectionApi,
  updateConnection as updateConnectionApi,
} from "@/lib/generated/api"

export type { ConnectionCreate, ConnectionDetail, ConnectionList, ConnectionUpdate }

// ── Connection List ───────────────────────────────────────────────────

export interface UseConnectionsOptions {
  page?: number
  pageSize?: number
  search?: string
  teamId?: string
  orderBy?: string
  sortOrder?: "asc" | "desc"
  refetchInterval?: number | false
}

export function useConnections(pageOrOptions: number | UseConnectionsOptions = 1, pageSizeArg = 20) {
  const opts: UseConnectionsOptions = typeof pageOrOptions === "number" ? { page: pageOrOptions, pageSize: pageSizeArg } : pageOrOptions
  const { page = 1, pageSize = 20, search, teamId, orderBy, sortOrder, refetchInterval } = opts

  return useQuery({
    queryKey: ["connections", page, pageSize, search, teamId, orderBy, sortOrder],
    queryFn: async () => {
      const response = await listConnections({
        query: {
          currentPage: page,
          pageSize,
          searchString: search,
          searchIgnoreCase: search ? true : undefined,
          teamId,
          orderBy,
          sortOrder,
        },
      })
      return response.data as { items: ConnectionList[]; total: number }
    },
    refetchInterval,
  })
}

// ── Connection Detail ─────────────────────────────────────────────────

export function useConnection(connectionId: string) {
  return useQuery({
    queryKey: ["connection", connectionId],
    queryFn: async () => {
      const response = await getConnection({
        path: { connection_id: connectionId },
      })
      return response.data as ConnectionDetail
    },
    enabled: !!connectionId,
  })
}

// ── Connection Mutations ──────────────────────────────────────────────

export function useCreateConnection() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: ConnectionCreate) => {
      const response = await createConnectionApi({ body: payload })
      return response.data as ConnectionList
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
      const response = await updateConnectionApi({
        path: { connection_id: connectionId },
        body: payload,
      })
      return response.data as ConnectionDetail
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
      await deleteConnectionApi({
        path: { connection_id: connectionId },
      })
    },
    onSuccess: (_data, connectionId) => {
      queryClient.invalidateQueries({ queryKey: ["connections"] })
      queryClient.invalidateQueries({ queryKey: ["connection", connectionId] })
      toast.success("Connection deleted")
    },
    onError: (error) => {
      toast.error("Unable to delete connection", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useUpdateAnyConnection() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({ connectionId, payload }: { connectionId: string; payload: ConnectionUpdate }) => {
      const response = await updateConnectionApi({
        path: { connection_id: connectionId },
        body: payload,
      })
      return response.data as ConnectionDetail
    },
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ["connections"] })
      queryClient.invalidateQueries({ queryKey: ["connection", variables.connectionId] })
      toast.success("Connection updated")
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
      const response = await testConnectionApi({
        path: { connection_id: connectionId },
      })
      return response.data as Message
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

export function useTestAnyConnection() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (connectionId: string) => {
      const response = await testConnectionApi({
        path: { connection_id: connectionId },
      })
      return response.data as Message
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
