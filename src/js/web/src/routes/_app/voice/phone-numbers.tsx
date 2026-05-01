import { createFileRoute, Outlet } from "@tanstack/react-router"

export const Route = createFileRoute("/_app/voice/phone-numbers")({
  component: PhoneNumbersLayout,
})

function PhoneNumbersLayout() {
  return <Outlet />
}
