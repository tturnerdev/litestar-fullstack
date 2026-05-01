import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  type AdminDeviceStats,
  type AdminDeviceSummary,
  type AdminExtensionSummary,
  type AdminFaxMessageSummary,
  type AdminFaxNumberSummary,
  type AdminFaxStats,
  type AdminGetTargetAuditLogsData,
  type AdminGetUserAuditLogsData,
  type AdminListAuditLogsData,
  type AdminListDevicesData,
  type AdminListFaxNumbersData,
  type AdminListPhoneNumbersData,
  type AdminListTeamsData,
  type AdminListTicketsData,
  type AdminListUsersData,
  type AdminPhoneNumberSummary,
  type AdminTrends,
  type AdminSupportStats,
  type AdminSystemStatus,
  type AdminTeamDetail,
  type AdminTeamSummary,
  type AdminTicketSummary,
  type AdminUserDetail,
  type AdminUserSummary,
  type AdminVoiceStats,
  type AuditLogEntry,
  adminDeleteTeam,
  adminDeleteUser,
  adminGetDeviceStats,
  adminGetFaxStats,
  adminGetSupportStats,
  adminGetTargetAuditLogs,
  adminGetTeam,
  adminGetUser,
  adminGetUserAuditLogs,
  adminGetVoiceStats,
  adminListAuditLogs,
  adminListDevices,
  adminListExtensions,
  adminListFaxMessages,
  adminListFaxNumbers,
  adminListPhoneNumbers,
  adminListTeams,
  adminListTickets,
  adminListUsers,
  adminUpdateTeam,
  adminUpdateUser,
  assignRole,
  type DashboardStats,
  getAdminSystemStatus,
  getDashboardStats,
  getDashboardTrends,
  getRecentActivity,
  listRoles,
  type ListRolesData,
  type RecentActivity,
  revokeRole,
  type Role,
  type TeamRoles,
  updateTeamMember,
} from "@/lib/generated/api"

export function useAdminDashboardStats() {
  return useQuery({
    queryKey: ["admin", "stats"],
    queryFn: async () => {
      const response = await getDashboardStats()
      return response.data as DashboardStats
    },
  })
}

export function useAdminRecentActivity() {
  return useQuery({
    queryKey: ["admin", "activity"],
    queryFn: async () => {
      const response = await getRecentActivity()
      return response.data as RecentActivity
    },
  })
}

export function useAdminTrends() {
  return useQuery({
    queryKey: ["admin", "trends"],
    queryFn: async () => {
      const response = await getDashboardTrends()
      return response.data as AdminTrends
    },
  })
}

export function useAdminSystemStatus(options?: { refetchInterval?: number | false }) {
  return useQuery({
    queryKey: ["admin", "system", "status"],
    queryFn: async () => {
      const response = await getAdminSystemStatus()
      return response.data as AdminSystemStatus
    },
    refetchInterval: options?.refetchInterval,
  })
}

export function useAdminUsers(params?: {
  page?: number
  pageSize?: number
  search?: string
  orderBy?: string
  sortOrder?: "asc" | "desc"
}) {
  const { page = 1, pageSize = 25, search, orderBy, sortOrder } = params ?? {}
  return useQuery({
    queryKey: ["admin", "users", page, pageSize, search, orderBy, sortOrder],
    queryFn: async () => {
      const query = {
        currentPage: page,
        pageSize,
        searchString: search,
        searchIgnoreCase: search ? true : undefined,
        orderBy: orderBy ?? undefined,
        sortOrder: sortOrder ?? undefined,
      } as unknown as AdminListUsersData["query"]
      const response = await adminListUsers({ query })
      return response.data as { items: AdminUserSummary[]; total: number }
    },
  })
}

export function useAdminTeams(params?: {
  page?: number
  pageSize?: number
  search?: string
  orderBy?: string
  sortOrder?: "asc" | "desc"
}) {
  const { page = 1, pageSize = 25, search, orderBy, sortOrder } = params ?? {}
  return useQuery({
    queryKey: ["admin", "teams", page, pageSize, search, orderBy, sortOrder],
    queryFn: async () => {
      const query = {
        currentPage: page,
        pageSize,
        searchString: search,
        searchIgnoreCase: search ? true : undefined,
        orderBy: orderBy ?? undefined,
        sortOrder: sortOrder ?? undefined,
      } as unknown as AdminListTeamsData["query"]
      const response = await adminListTeams({ query })
      return response.data as { items: AdminTeamSummary[]; total: number }
    },
  })
}

export function useAdminAuditLogs(params: {
  page?: number
  pageSize?: number
  search?: string
  actions?: string[]
  actorEmail?: string
  targetTypes?: string[]
  startDate?: string
  endDate?: string
  orderBy?: string
  sortOrder?: "asc" | "desc"
}) {
  const {
    page = 1,
    pageSize = 50,
    search,
    actions,
    actorEmail,
    targetTypes,
    startDate,
    endDate,
    orderBy,
    sortOrder,
  } = params
  return useQuery({
    queryKey: [
      "admin",
      "audit",
      page,
      pageSize,
      search,
      actions,
      actorEmail,
      targetTypes,
      startDate,
      endDate,
      orderBy,
      sortOrder,
    ],
    queryFn: async () => {
      const query = {
        currentPage: page,
        pageSize,
        searchString: actorEmail || search || undefined,
        searchIgnoreCase: actorEmail || search ? true : undefined,
        actionIn: actions && actions.length > 0 ? actions : undefined,
        targetTypeIn: targetTypes && targetTypes.length > 0 ? targetTypes : undefined,
        createdAfter: startDate,
        createdBefore: endDate,
        orderBy: orderBy ?? undefined,
        sortOrder: sortOrder ?? undefined,
      } as unknown as AdminListAuditLogsData["query"]
      const response = await adminListAuditLogs({
        query,
      })
      return response.data as { items: AuditLogEntry[]; total: number }
    },
  })
}

export function useAdminAuditLogsExport(params: {
  search?: string
  actions?: string[]
  actorEmail?: string
  targetTypes?: string[]
  startDate?: string
  endDate?: string
  enabled?: boolean
}) {
  const { search, actions, actorEmail, targetTypes, startDate, endDate, enabled = false } = params
  return useQuery({
    queryKey: ["admin", "audit", "export", search, actions, actorEmail, targetTypes, startDate, endDate],
    queryFn: async () => {
      const query = {
        currentPage: 1,
        pageSize: 1000,
        searchString: actorEmail || search || undefined,
        searchIgnoreCase: actorEmail || search ? true : undefined,
        actionIn: actions && actions.length > 0 ? actions : undefined,
        targetTypeIn: targetTypes && targetTypes.length > 0 ? targetTypes : undefined,
        createdAfter: startDate,
        createdBefore: endDate,
      } as unknown as AdminListAuditLogsData["query"]
      const response = await adminListAuditLogs({
        query,
      })
      return response.data as { items: AuditLogEntry[]; total: number }
    },
    enabled,
  })
}

export function useAdminUser(userId: string) {
  return useQuery({
    queryKey: ["admin", "user", userId],
    queryFn: async () => {
      const response = await adminGetUser({ path: { user_id: userId } })
      return response.data as AdminUserDetail
    },
    enabled: !!userId,
  })
}

export function useAdminTeam(teamId: string) {
  return useQuery({
    queryKey: ["admin", "team", teamId],
    queryFn: async () => {
      const response = await adminGetTeam({ path: { team_id: teamId } })
      return response.data as AdminTeamDetail
    },
    enabled: !!teamId,
  })
}

export function useAdminUpdateUser(userId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: Record<string, unknown>) => {
      const response = await adminUpdateUser({
        path: { user_id: userId },
        body: payload,
      })
      return response.data as AdminUserDetail
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin", "users"] })
      queryClient.invalidateQueries({ queryKey: ["admin", "user", userId] })
      toast.success("User updated")
    },
    onError: (error) => {
      toast.error("Unable to update user", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useAdminUpdateTeam(teamId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (payload: Record<string, unknown>) => {
      const response = await adminUpdateTeam({
        path: { team_id: teamId },
        body: payload,
      })
      return response.data as AdminTeamDetail
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin", "teams"] })
      queryClient.invalidateQueries({ queryKey: ["admin", "team", teamId] })
      toast.success("Team updated")
    },
    onError: (error) => {
      toast.error("Unable to update team", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useAdminDeleteUser() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (userId: string) => {
      const response = await adminDeleteUser({ path: { user_id: userId } })
      return response.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin", "users"] })
      toast.success("User deleted")
    },
    onError: (error) => {
      toast.error("Unable to delete user", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useAdminDeleteTeam() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (teamId: string) => {
      const response = await adminDeleteTeam({ path: { team_id: teamId } })
      return response.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin", "teams"] })
      toast.success("Team deleted")
    },
    onError: (error) => {
      toast.error("Unable to delete team", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useAdminUserAuditLogs(userId: string, page = 1, pageSize = 10) {
  return useQuery({
    queryKey: ["admin", "user", userId, "audit", page, pageSize],
    queryFn: async () => {
      const query = {
        currentPage: page,
        pageSize,
      } as unknown as AdminGetUserAuditLogsData["query"]
      const response = await adminGetUserAuditLogs({
        path: { user_id: userId },
        query,
      })
      return response.data as { items: AuditLogEntry[]; total: number }
    },
    enabled: !!userId,
  })
}

export function useRoles() {
  return useQuery({
    queryKey: ["roles"],
    queryFn: async () => {
      const query = {
        pageSize: 100,
      } as unknown as ListRolesData["query"]
      const response = await listRoles({ query })
      return response.data as { items: Role[]; total: number }
    },
  })
}

export function useAssignRole() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({ roleSlug, userEmail }: { roleSlug: string; userEmail: string }) => {
      const response = await assignRole({
        path: { role_slug: roleSlug },
        body: { userName: userEmail },
      })
      return response.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin", "users"] })
      queryClient.invalidateQueries({ queryKey: ["admin", "user"] })
      toast.success("Role assigned")
    },
    onError: (error) => {
      toast.error("Unable to assign role", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useUpdateTeamMember(userId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({ teamId, role }: { teamId: string; role: TeamRoles }) => {
      const response = await updateTeamMember({
        path: { team_id: teamId, user_id: userId },
        body: { role },
      })
      return response.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin", "users"] })
      queryClient.invalidateQueries({ queryKey: ["admin", "user", userId] })
      toast.success("Team role updated")
    },
    onError: (error) => {
      toast.error("Unable to update team role", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useRevokeRole() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({ roleSlug, userEmail }: { roleSlug: string; userEmail: string }) => {
      const response = await revokeRole({
        path: { role_slug: roleSlug },
        body: { userName: userEmail },
      })
      return response.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin", "users"] })
      queryClient.invalidateQueries({ queryKey: ["admin", "user"] })
      toast.success("Role revoked")
    },
    onError: (error) => {
      toast.error("Unable to revoke role", {
        description: error instanceof Error ? error.message : "Try again later",
      })
    },
  })
}

export function useAdminDevices(page = 1, pageSize = 25, search?: string) {
  return useQuery({
    queryKey: ["admin", "devices", page, pageSize, search],
    queryFn: async () => {
      const query = {
        currentPage: page,
        pageSize,
        searchString: search,
        searchIgnoreCase: search ? true : undefined,
      } as unknown as AdminListDevicesData["query"]
      const response = await adminListDevices({ query })
      return response.data as { items: AdminDeviceSummary[]; total: number }
    },
  })
}

export function useAdminDeviceStats() {
  return useQuery({
    queryKey: ["admin", "devices", "stats"],
    queryFn: async () => {
      const response = await adminGetDeviceStats()
      return response.data as AdminDeviceStats
    },
  })
}

export function useAdminPhoneNumbers(page = 1, pageSize = 25, search?: string) {
  return useQuery({
    queryKey: ["admin", "voice", "phone-numbers", page, pageSize, search],
    queryFn: async () => {
      const query = {
        currentPage: page,
        pageSize,
        searchString: search,
        searchIgnoreCase: search ? true : undefined,
      } as unknown as AdminListPhoneNumbersData["query"]
      const response = await adminListPhoneNumbers({ query })
      return response.data as { items: AdminPhoneNumberSummary[]; total: number }
    },
  })
}

export function useAdminExtensions() {
  return useQuery({
    queryKey: ["admin", "voice", "extensions"],
    queryFn: async () => {
      const response = await adminListExtensions()
      return response.data as AdminExtensionSummary[]
    },
  })
}

export function useAdminVoiceStats() {
  return useQuery({
    queryKey: ["admin", "voice", "stats"],
    queryFn: async () => {
      const response = await adminGetVoiceStats()
      return response.data as AdminVoiceStats
    },
  })
}

export function useAdminFaxNumbers(page = 1, pageSize = 25, search?: string) {
  return useQuery({
    queryKey: ["admin", "fax", "numbers", page, pageSize, search],
    queryFn: async () => {
      const query = {
        currentPage: page,
        pageSize,
        searchString: search,
        searchIgnoreCase: search ? true : undefined,
      } as unknown as AdminListFaxNumbersData["query"]
      const response = await adminListFaxNumbers({ query })
      return response.data as { items: AdminFaxNumberSummary[]; total: number }
    },
  })
}

export function useAdminFaxMessages() {
  return useQuery({
    queryKey: ["admin", "fax", "messages"],
    queryFn: async () => {
      const response = await adminListFaxMessages()
      return response.data as AdminFaxMessageSummary[]
    },
  })
}

export function useAdminFaxStats() {
  return useQuery({
    queryKey: ["admin", "fax", "stats"],
    queryFn: async () => {
      const response = await adminGetFaxStats()
      return response.data as AdminFaxStats
    },
  })
}

export function useAdminTickets(page = 1, pageSize = 25, search?: string) {
  return useQuery({
    queryKey: ["admin", "support", "tickets", page, pageSize, search],
    queryFn: async () => {
      const query = {
        currentPage: page,
        pageSize,
        searchString: search,
        searchIgnoreCase: search ? true : undefined,
      } as unknown as AdminListTicketsData["query"]
      const response = await adminListTickets({ query })
      return response.data as { items: AdminTicketSummary[]; total: number }
    },
  })
}

export function useAdminSupportStats() {
  return useQuery({
    queryKey: ["admin", "support", "stats"],
    queryFn: async () => {
      const response = await adminGetSupportStats()
      return response.data as AdminSupportStats
    },
  })
}

export function useTargetAuditLogs(
  targetType: string,
  targetId: string,
  options?: { enabled?: boolean; page?: number; pageSize?: number },
) {
  const { enabled = true, page = 1, pageSize = 25 } = options ?? {}
  return useQuery({
    queryKey: ["admin", "audit", "target", targetType, targetId, page, pageSize],
    queryFn: async () => {
      const query = {
        currentPage: page,
        pageSize,
      } as unknown as AdminGetTargetAuditLogsData["query"]
      const response = await adminGetTargetAuditLogs({
        path: { target_type: targetType, target_id: targetId },
        query,
      })
      return response.data as { items: AuditLogEntry[]; total: number }
    },
    enabled: enabled && !!targetType && !!targetId,
    staleTime: 60_000,
  })
}
