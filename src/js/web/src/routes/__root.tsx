import { createRootRoute, createRouter, Outlet } from "@tanstack/react-router"
import { Toaster } from "sonner"
import { ErrorBoundary } from "@/components/error-boundary"
import { NotFoundPage } from "@/components/ui/not-found-page"
import { useTheme } from "@/lib/theme-context"

export const Route = createRootRoute({
  component: RootRoute,
  errorComponent: ErrorBoundary,
  notFoundComponent: NotFoundPage,
})

export const router = createRouter({
  routeTree: Route,
})

function RootRoute() {
  const { theme } = useTheme()
  return (
    <>
      <Toaster richColors theme={theme} position="top-right" />
      <Outlet />
    </>
  )
}
