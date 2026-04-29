import type { ErrorComponentProps } from "@tanstack/react-router"
import { ErrorFallback } from "@/components/ui/error-boundary"

/**
 * TanStack Router error component.
 * Used as `defaultErrorComponent` on the router and can be set per-route via `errorComponent`.
 */
export function ErrorBoundary({ error, reset }: ErrorComponentProps) {
  const normalizedError = error instanceof Error ? error : new Error("An unexpected error occurred")

  console.error("[RouteErrorBoundary]", normalizedError)

  return <ErrorFallback error={normalizedError} resetError={reset} />
}
