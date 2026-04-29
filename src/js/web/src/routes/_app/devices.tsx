import { createFileRoute, Outlet } from "@tanstack/react-router"

export const Route = createFileRoute("/_app/devices")({
  component: DevicesLayout,
})

function DevicesLayout() {
  return <Outlet />
}
