import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  getOrganization,
  updateOrganization,
  type Organization,
} from "@/lib/generated/api"

export function useOrganization() {
  return useQuery({
    queryKey: ["organization"],
    queryFn: async () => {
      const response = await getOrganization()
      return response.data as Organization
    },
  })
}

export function useUpdateOrganization() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: Record<string, unknown>) => {
      const response = await updateOrganization({
        body: payload,
      })
      return response.data as Organization
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["organization"] })
      toast.success("Organization settings updated")
    },
    onError: (error) => {
      toast.error("Unable to update organization settings", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}
