import { createFileRoute, Outlet } from "@tanstack/react-router"

export const Route = createFileRoute("/_app/schedules")({
  component: SchedulesLayout,
})

function SchedulesLayout() {
  return <Outlet />
}
