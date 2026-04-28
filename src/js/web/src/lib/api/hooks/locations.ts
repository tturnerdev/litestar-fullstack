import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { client } from "@/lib/generated/api/client.gen"

// ---------------------------------------------------------------------------
// Helpers (for endpoints not yet in generated SDK)
// ---------------------------------------------------------------------------

async function apiFetch<T>(url: string, options?: RequestInit): Promise<T> {
  const config = client.getConfig()
  const baseUrl = config.baseUrl ?? ""
  const token = typeof window !== "undefined" ? window.localStorage.getItem("access_token") : null
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  }
  const response = await fetch(`${baseUrl}${url}`, {
    credentials: "include",
    ...options,
    headers: { ...headers, ...(options?.headers as Record<string, string>) },
  })
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new Error(body.detail ?? `Request failed (${response.status})`)
  }
  if (response.status === 204) return undefined as unknown as T
  return response.json()
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface LocationChild {
  id: string
  name: string
  description?: string | null
}

export interface Location {
  id: string
  name: string
  locationType: string
  teamId: string
  description?: string | null
  parentId?: string | null
  addressLine1?: string | null
  addressLine2?: string | null
  city?: string | null
  state?: string | null
  postalCode?: string | null
  country?: string | null
  children?: LocationChild[]
}

export interface LocationCreate {
  name: string
  locationType: string
  teamId: string
  description?: string | null
  parentId?: string | null
  addressLine1?: string | null
  addressLine2?: string | null
  city?: string | null
  state?: string | null
  postalCode?: string | null
  country?: string | null
}

export interface LocationUpdate {
  name?: string
  description?: string | null
  addressLine1?: string | null
  addressLine2?: string | null
  city?: string | null
  state?: string | null
  postalCode?: string | null
  country?: string | null
}

// ---------------------------------------------------------------------------
// Location List
// ---------------------------------------------------------------------------

export interface UseLocationsOptions {
  teamId: string
  page?: number
  pageSize?: number
  search?: string
  locationType?: string
  orderBy?: string
  sortOrder?: "asc" | "desc"
}

export function useLocations(options: UseLocationsOptions) {
  const { teamId, page = 1, pageSize = 20, search, locationType, orderBy, sortOrder } = options

  return useQuery({
    queryKey: ["locations", teamId, page, pageSize, search, locationType, orderBy, sortOrder],
    queryFn: async () => {
      const params = new URLSearchParams()
      params.set("currentPage", String(page))
      params.set("pageSize", String(pageSize))
      if (search) {
        params.set("searchString", search)
        params.set("searchIgnoreCase", "true")
      }
      if (locationType) params.set("locationType", locationType)
      if (orderBy) params.set("orderBy", orderBy)
      if (sortOrder) params.set("sortOrder", sortOrder)
      return apiFetch<{ items: Location[]; total: number }>(`/api/teams/${teamId}/locations?${params.toString()}`)
    },
    enabled: !!teamId,
  })
}

// ---------------------------------------------------------------------------
// Location Detail
// ---------------------------------------------------------------------------

export function useLocation(teamId: string, locationId: string) {
  return useQuery({
    queryKey: ["location", teamId, locationId],
    queryFn: async () => {
      return apiFetch<Location>(`/api/teams/${teamId}/locations/${locationId}`)
    },
    enabled: !!teamId && !!locationId,
  })
}

// ---------------------------------------------------------------------------
// Location Mutations
// ---------------------------------------------------------------------------

export function useCreateLocation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: LocationCreate) => {
      return apiFetch<Location>(`/api/teams/${payload.teamId}/locations`, {
        method: "POST",
        body: JSON.stringify(payload),
      })
    },
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ["locations", variables.teamId] })
      toast.success("Location created")
    },
    onError: (error) => {
      toast.error("Unable to create location", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useUpdateLocation(teamId: string, locationId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: LocationUpdate) => {
      return apiFetch<Location>(`/api/teams/${teamId}/locations/${locationId}`, {
        method: "PATCH",
        body: JSON.stringify(payload),
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["locations", teamId] })
      queryClient.invalidateQueries({ queryKey: ["location", teamId, locationId] })
      toast.success("Location updated")
    },
    onError: (error) => {
      toast.error("Unable to update location", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useDeleteLocation(teamId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (locationId: string) => {
      return apiFetch<void>(`/api/teams/${teamId}/locations/${locationId}`, {
        method: "DELETE",
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["locations", teamId] })
      toast.success("Location deleted")
    },
    onError: (error) => {
      toast.error("Unable to delete location", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}
