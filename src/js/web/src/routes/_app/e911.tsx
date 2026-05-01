import { createFileRoute, Outlet } from "@tanstack/react-router"

export const Route = createFileRoute("/_app/e911")({
  component: E911Layout,
})

function E911Layout() {
  return <Outlet />
}
