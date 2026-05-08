import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  createLocation as createLocationApi,
  deleteLocation as deleteLocationApi,
  getLocation,
  type Location,
  type LocationChild,
  type LocationCreate,
  type LocationUpdate,
  listLocations,
  updateLocation as updateLocationApi,
} from "@/lib/generated/api"

export type { Location, LocationChild, LocationCreate, LocationUpdate }

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
      const response = await listLocations({
        path: { team_id: teamId },
        query: {
          currentPage: page,
          pageSize,
          searchString: search,
          searchIgnoreCase: search ? true : undefined,
          locationType,
          orderBy,
          sortOrder,
        },
      })
      return response.data as { items: Location[]; total: number }
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
      const response = await getLocation({
        path: { team_id: teamId, location_id: locationId },
      })
      return response.data as Location
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
      const response = await createLocationApi({
        path: { team_id: payload.teamId },
        body: payload,
      })
      return response.data as Location
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
      const response = await updateLocationApi({
        path: { team_id: teamId, location_id: locationId },
        body: payload,
      })
      return response.data as Location
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
      await deleteLocationApi({
        path: { team_id: teamId, location_id: locationId },
      })
    },
    onSuccess: (_data, locationId) => {
      queryClient.invalidateQueries({ queryKey: ["locations", teamId] })
      queryClient.invalidateQueries({ queryKey: ["location", teamId, locationId] })
      toast.success("Location deleted")
    },
    onError: (error) => {
      toast.error("Unable to delete location", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

// ---------------------------------------------------------------------------
// Bulk Delete
// ---------------------------------------------------------------------------

export function useBulkDeleteLocations(teamId: string) {
  const queryClient = useQueryClient()
  return {
    deleteOne: async (locationId: string) => {
      await deleteLocationApi({
        path: { team_id: teamId, location_id: locationId },
      })
    },
    invalidate: () => {
      queryClient.invalidateQueries({ queryKey: ["locations", teamId] })
    },
  }
}
