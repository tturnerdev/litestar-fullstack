import { createFileRoute, Outlet, useNavigate } from "@tanstack/react-router"
import { useAuthStore } from "@/lib/auth"

export const Route = createFileRoute("/_app/organization")({
  component: OrganizationLayout,
})

function OrganizationLayout() {
  const { user } = useAuthStore()
  const navigate = useNavigate()

  // Only admins (superusers) can access organization settings.
  // Regular members are redirected to home.
  if (!user?.isSuperuser) {
    navigate({ to: "/home" as const })
    return null
  }

  return <Outlet />
}

export default OrganizationLayout
