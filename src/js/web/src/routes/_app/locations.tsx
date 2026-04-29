import { createFileRoute, Outlet } from "@tanstack/react-router"

export const Route = createFileRoute("/_app/locations")({
  component: LocationsLayout,
})

function LocationsLayout() {
  return <Outlet />
}
