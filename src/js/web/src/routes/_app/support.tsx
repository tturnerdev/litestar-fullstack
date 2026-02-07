import { createFileRoute, Outlet } from "@tanstack/react-router"

export const Route = createFileRoute("/_app/support")({
  component: SupportLayout,
})

function SupportLayout() {
  return <Outlet />
}

export default SupportLayout
