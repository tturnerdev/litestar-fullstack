import * as Sentry from "@sentry/react"

/**
 * Initialize Sentry / GlitchTip error tracking.
 *
 * Reads configuration from Vite environment variables:
 *   - VITE_SENTRY_DSN         — required; skipped if empty
 *   - VITE_SENTRY_ENVIRONMENT — defaults to "development"
 *
 * Call this once in main.tsx before React renders.
 */
export function initSentry(): void {
  const dsn = import.meta.env.VITE_SENTRY_DSN
  if (!dsn) return

  Sentry.init({
    dsn,
    environment: import.meta.env.VITE_SENTRY_ENVIRONMENT || "development",
    tracesSampleRate: 0.1,
    replaysSessionSampleRate: 0,
    replaysOnErrorSampleRate: 1.0,
  })
}
