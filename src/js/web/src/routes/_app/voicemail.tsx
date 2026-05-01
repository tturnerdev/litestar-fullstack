import { createFileRoute, Outlet } from "@tanstack/react-router"

export const Route = createFileRoute("/_app/voicemail")({
  component: VoicemailLayout,
})

function VoicemailLayout() {
  return <Outlet />
}
