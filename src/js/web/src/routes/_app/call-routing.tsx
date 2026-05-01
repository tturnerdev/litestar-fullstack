import { createFileRoute, Outlet } from "@tanstack/react-router"

export const Route = createFileRoute("/_app/call-routing")({
  component: CallRoutingLayout,
})

function CallRoutingLayout() {
  return <Outlet />
}
