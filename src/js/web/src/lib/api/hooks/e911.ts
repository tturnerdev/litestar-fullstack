import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  createE911Registration as createE911Api,
  deleteE911Registration as deleteE911Api,
  type E911Registration,
  type E911RegistrationCreate,
  type E911RegistrationUpdate,
  getE911Registration,
  listE911Registrations,
  listUnregisteredPhoneNumbers,
  type UnregisteredPhoneNumber,
  updateE911Registration as updateE911Api,
  validateE911Registration as validateE911Api,
} from "@/lib/generated/api"

export type { E911Registration, E911RegistrationCreate, E911RegistrationUpdate, UnregisteredPhoneNumber }

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
      const response = await listE911Registrations({
        query: {
          currentPage: page,
          pageSize,
          searchString: search,
          searchIgnoreCase: search ? true : undefined,
          orderBy,
          sortOrder,
          teamId,
        },
      })
      return response.data as { items: E911Registration[]; total: number }
    },
  })
}

// ---------------------------------------------------------------------------
// E911 Registration Detail
// ---------------------------------------------------------------------------

export function useE911Registration(registrationId: string) {
  return useQuery({
    queryKey: ["e911", "registration", registrationId],
    queryFn: async () => {
      const response = await getE911Registration({
        path: { registration_id: registrationId },
      })
      return response.data as E911Registration
    },
    enabled: !!registrationId,
  })
}

// ---------------------------------------------------------------------------
// E911 Mutations
// ---------------------------------------------------------------------------

export function useCreateE911Registration() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: E911RegistrationCreate) => {
      const response = await createE911Api({ body: payload })
      return response.data as E911Registration
    },
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
    mutationFn: async (payload: E911RegistrationUpdate) => {
      const response = await updateE911Api({
        path: { registration_id: registrationId },
        body: payload,
      })
      return response.data as E911Registration
    },
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
    mutationFn: async (registrationId: string) => {
      await deleteE911Api({
        path: { registration_id: registrationId },
      })
    },
    onSuccess: (_data, registrationId) => {
      queryClient.invalidateQueries({ queryKey: ["e911"] })
      queryClient.invalidateQueries({ queryKey: ["e911", "registration", registrationId] })
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
    mutationFn: async () => {
      const response = await validateE911Api({
        path: { registration_id: registrationId },
      })
      return response.data as E911Registration
    },
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
    queryFn: async () => {
      const response = await listUnregisteredPhoneNumbers({
        query: { teamId },
      })
      return response.data as UnregisteredPhoneNumber[]
    },
    enabled: !!teamId,
  })
}
