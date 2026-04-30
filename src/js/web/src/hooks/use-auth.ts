import { useAuthStore } from "@/lib/auth"

export function useAuth() {
  const { user, currentTeam, teams, logout, checkAuth, isLoading, isAuthenticated } = useAuthStore()

  return {
    user,
    currentTeam,
    teams,
    logout,
    refetch: checkAuth,
    isLoading,
    isAuthenticated,
  }
}
