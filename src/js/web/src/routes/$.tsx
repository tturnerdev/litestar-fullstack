import { createFileRoute } from "@tanstack/react-router"
import { NotFoundPage } from "@/components/ui/not-found-page"

export const Route = createFileRoute("/$")({
  component: NotFoundPage,
})
