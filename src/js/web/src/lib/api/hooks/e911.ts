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

export interface E911Registration {
  id: string
  teamId: string
  phoneNumberId: string | null
  locationId: string | null
  addressLine1: string
  addressLine2: string | null
  city: string
  state: string
  postalCode: string
  country: string
  validated: boolean
  validatedAt: string | null
  carrierRegistrationId: string | null
  phoneNumberDisplay: string | null
  phoneNumberLabel: string | null
  locationName: string | null
  createdAt: string | null
  updatedAt: string | null
}

export interface E911RegistrationCreate {
  teamId: string
  phoneNumberId?: string | null
  locationId?: string | null
  addressLine1: string
  addressLine2?: string | null
  city: string
  state: string
  postalCode: string
  country?: string
}

export interface E911RegistrationUpdate {
  phoneNumberId?: string | null
  locationId?: string | null
  addressLine1?: string
  addressLine2?: string | null
  city?: string
  state?: string
  postalCode?: string
  country?: string
}

export interface UnregisteredPhoneNumber {
  id: string
  number: string
  label: string | null
  numberType: string
  userId: string
  teamId: string | null
}

interface PaginatedResponse<T> {
  items: T[]
  total: number
}

// ---------------------------------------------------------------------------
// E911 Registration List
// ---------------------------------------------------------------------------

export interface UseE911RegistrationsOptions {
  page?: number
  pageSize?: number
  search?: string
  teamId?: string
  orderBy?: string
  sortOrder?: "asc" | "desc"
}

export function useE911Registrations(options: UseE911RegistrationsOptions = {}) {
  const { page = 1, pageSize = 20, search, teamId, orderBy, sortOrder } = options

  return useQuery({
    queryKey: ["e911", "registrations", page, pageSize, search, teamId, orderBy, sortOrder],
    queryFn: async () => {
      const params = new URLSearchParams()
      params.set("currentPage", String(page))
      params.set("pageSize", String(pageSize))
      if (search) {
        params.set("searchString", search)
        params.set("searchIgnoreCase", "true")
      }
      if (teamId) params.set("teamId", teamId)
      if (orderBy) params.set("orderBy", orderBy)
      if (sortOrder) params.set("sortOrder", sortOrder)
      return apiFetch<PaginatedResponse<E911Registration>>(`/api/e911?${params.toString()}`)
    },
  })
}

// ---------------------------------------------------------------------------
// E911 Registration Detail
// ---------------------------------------------------------------------------

export function useE911Registration(registrationId: string) {
  return useQuery({
    queryKey: ["e911", "registration", registrationId],
    queryFn: () => apiFetch<E911Registration>(`/api/e911/${registrationId}`),
    enabled: !!registrationId,
  })
}

// ---------------------------------------------------------------------------
// E911 Mutations
// ---------------------------------------------------------------------------

export function useCreateE911Registration() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: E911RegistrationCreate) =>
      apiFetch<E911Registration>("/api/e911", {
        method: "POST",
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["e911"] })
      toast.success("E911 registration created")
    },
    onError: (error) => {
      toast.error("Unable to create E911 registration", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useUpdateE911Registration(registrationId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: E911RegistrationUpdate) =>
      apiFetch<E911Registration>(`/api/e911/${registrationId}`, {
        method: "PATCH",
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["e911"] })
      queryClient.invalidateQueries({ queryKey: ["e911", "registration", registrationId] })
      toast.success("E911 registration updated")
    },
    onError: (error) => {
      toast.error("Unable to update E911 registration", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useDeleteE911Registration() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (registrationId: string) =>
      apiFetch<void>(`/api/e911/${registrationId}`, {
        method: "DELETE",
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["e911"] })
      toast.success("E911 registration deleted")
    },
    onError: (error) => {
      toast.error("Unable to delete E911 registration", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useValidateE911Registration(registrationId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: () =>
      apiFetch<E911Registration>(`/api/e911/${registrationId}/validate`, {
        method: "POST",
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["e911"] })
      queryClient.invalidateQueries({ queryKey: ["e911", "registration", registrationId] })
      toast.success("E911 address validated")
    },
    onError: (error) => {
      toast.error("Unable to validate E911 address", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

// ---------------------------------------------------------------------------
// Unregistered Phone Numbers
// ---------------------------------------------------------------------------

export function useUnregisteredPhoneNumbers(teamId: string) {
  return useQuery({
    queryKey: ["e911", "unregistered", teamId],
    queryFn: () => apiFetch<UnregisteredPhoneNumber[]>(`/api/e911/unregistered?teamId=${teamId}`),
    enabled: !!teamId,
  })
}
