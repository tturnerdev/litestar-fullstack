import { createFileRoute, Outlet } from "@tanstack/react-router"

export const Route = createFileRoute("/_app/analytics")({
  component: AnalyticsLayout,
})

function AnalyticsLayout() {
  return <Outlet />
}
