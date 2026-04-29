import type { ErrorComponentProps } from "@tanstack/react-router"
import { createFileRoute, Link, redirect, useRouter } from "@tanstack/react-router"
import { motion } from "framer-motion"
import { AlertCircle, ArrowLeft, Home, Loader2, RefreshCw, Search } from "lucide-react"
import { Button } from "@/components/ui/button"
import { AppLayout } from "@/layouts/app-layout"
import { useAuthStore } from "@/lib/auth"

export const Route = createFileRoute("/_app")({
  component: AppLayout,
  notFoundComponent: AppNotFound,
  errorComponent: AppError,
  pendingComponent: AppPending,
  beforeLoad: async ({ location }) => {
    const { isAuthenticated, checkAuth } = useAuthStore.getState()

    // Build redirect search params preserving current URL
    // Note: location.search is an object in TanStack Router, use href for full path
    const redirectSearch = { redirect: location.href }

    // If not authenticated according to persisted state, redirect immediately
    if (!isAuthenticated) {
      throw redirect({ to: "/login", search: redirectSearch })
    }

    // Verify the session is still valid by checking with the server
    try {
      await checkAuth()
      // Re-check after verification - checkAuth updates the store if session is invalid
      const { isAuthenticated: stillAuthenticated } = useAuthStore.getState()
      if (!stillAuthenticated) {
        throw redirect({ to: "/login", search: redirectSearch })
      }
    } catch {
      // If checkAuth fails, clear state and redirect
      useAuthStore.setState({
        isAuthenticated: false,
        user: null,
        currentTeam: null,
      })
      throw redirect({ to: "/login", search: redirectSearch })
    }
  },
})

function AppNotFound() {
  const router = useRouter()

  return (
    <div className="flex min-h-[calc(100vh-4rem)] flex-col items-center justify-center px-4">
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }} className="flex max-w-md flex-col items-center text-center">
        <div className="mb-6 flex h-14 w-14 items-center justify-center rounded-2xl bg-muted/60">
          <Search className="h-7 w-7 text-muted-foreground" />
        </div>
        <p className="font-heading text-6xl font-bold tracking-tighter text-foreground/10">404</p>
        <h1 className="-mt-1 font-heading text-xl font-semibold tracking-tight text-foreground">Page not found</h1>
        <p className="mt-3 text-sm leading-relaxed text-muted-foreground">This page does not exist or may have been moved. Check the URL or navigate back.</p>
        <div className="mt-6 flex flex-col gap-3 sm:flex-row">
          <Button onClick={() => router.history.back()} variant="outline" size="sm">
            <ArrowLeft className="mr-2 h-4 w-4" />
            Go back
          </Button>
          <Button asChild size="sm">
            <Link to="/home">
              <Home className="mr-2 h-4 w-4" />
              Go to dashboard
            </Link>
          </Button>
        </div>
      </motion.div>
    </div>
  )
}

function AppError({ error, reset }: ErrorComponentProps) {
  const router = useRouter()
  const errorMessage = error instanceof Error ? error.message : "An unexpected error occurred"
  const isDev = import.meta.env.DEV

  return (
    <div className="flex min-h-[calc(100vh-4rem)] flex-col items-center justify-center px-4">
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }} className="flex max-w-md flex-col items-center text-center">
        <div className="mb-6 flex h-14 w-14 items-center justify-center rounded-2xl bg-destructive/10">
          <AlertCircle className="h-7 w-7 text-destructive" />
        </div>
        <h1 className="font-heading text-xl font-semibold tracking-tight text-foreground">Something went wrong</h1>
        <p className="mt-3 text-sm leading-relaxed text-muted-foreground">An error occurred while loading this page. You can try again or return to the dashboard.</p>
        {isDev && (
          <div className="mt-4 w-full rounded-lg border border-destructive/20 bg-destructive/5 p-4 text-left">
            <p className="mb-1 text-xs font-semibold uppercase tracking-wider text-destructive">Error Details</p>
            <p className="break-words font-mono text-xs text-destructive/80">{errorMessage}</p>
            {error instanceof Error && error.stack && (
              <pre className="mt-2 max-h-32 overflow-auto whitespace-pre-wrap font-mono text-[0.65rem] leading-relaxed text-muted-foreground">{error.stack}</pre>
            )}
          </div>
        )}
        <div className="mt-6 flex flex-col gap-3 sm:flex-row">
          <Button onClick={reset} variant="outline" size="sm">
            <RefreshCw className="mr-2 h-4 w-4" />
            Try again
          </Button>
          <Button onClick={() => router.navigate({ to: "/home" })} size="sm">
            <Home className="mr-2 h-4 w-4" />
            Go to dashboard
          </Button>
        </div>
      </motion.div>
    </div>
  )
}

function AppPending() {
  return (
    <div className="flex min-h-[calc(100vh-4rem)] items-center justify-center">
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.2 }} className="flex flex-col items-center gap-3">
        <Loader2 className="h-6 w-6 animate-spin text-primary" />
        <p className="text-sm text-muted-foreground">Loading...</p>
      </motion.div>
    </div>
  )
}
