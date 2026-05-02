import type { ErrorComponentProps } from "@tanstack/react-router"
import { createFileRoute, Link, redirect, useRouter } from "@tanstack/react-router"
import { motion } from "framer-motion"
import { AlertCircle, ArrowLeft, Home, RefreshCw, Search } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { AppLayout } from "@/layouts/app-layout"
import { useAuthStore } from "@/lib/auth"

export const Route = createFileRoute("/_app")({
  component: AppLayout,
  notFoundComponent: AppNotFound,
  errorComponent: AppError,
  pendingComponent: AppPending,
  beforeLoad: ({ location }) => {
    const { isAuthenticated } = useAuthStore.getState()
    if (!isAuthenticated) {
      throw redirect({ to: "/login", search: { redirect: location.href } })
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
    <div className="flex min-h-screen animate-in fade-in duration-300">
      {/* Sidebar skeleton */}
      <div className="hidden w-64 shrink-0 border-r border-border/60 bg-muted/30 md:block">
        <div className="space-y-4 p-4">
          <Skeleton className="h-8 w-32" />
          <div className="space-y-1.5">
            <Skeleton className="h-4 w-full" />
            <Skeleton className="h-4 w-3/4" />
            <Skeleton className="h-4 w-5/6" />
          </div>
          <div className="space-y-1.5 pt-4">
            <Skeleton className="h-8 w-full rounded-md" />
            <Skeleton className="h-8 w-full rounded-md" />
            <Skeleton className="h-8 w-full rounded-md" />
            <Skeleton className="h-8 w-full rounded-md" />
            <Skeleton className="h-8 w-full rounded-md" />
          </div>
        </div>
      </div>
      {/* Main content skeleton */}
      <div className="flex flex-1 flex-col">
        <div className="flex h-16 shrink-0 items-center gap-4 border-b border-border/60 px-4">
          <Skeleton className="h-4 w-16" />
          <Skeleton className="h-5 w-32" />
          <div className="flex-1" />
          <Skeleton className="h-8 w-8 rounded-md" />
          <Skeleton className="h-8 w-8 rounded-md" />
        </div>
        <div className="space-y-6 p-6">
          <Skeleton className="h-8 w-64" />
          <div className="grid gap-4 md:grid-cols-3">
            <Skeleton className="h-32 rounded-lg" />
            <Skeleton className="h-32 rounded-lg" />
            <Skeleton className="h-32 rounded-lg" />
          </div>
          <Skeleton className="h-64 rounded-lg" />
        </div>
      </div>
    </div>
  )
}
