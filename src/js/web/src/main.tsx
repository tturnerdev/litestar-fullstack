import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { ReactQueryDevtools } from "@tanstack/react-query-devtools"
import { createRouter, RouterProvider } from "@tanstack/react-router"
import React from "react"
import ReactDOM from "react-dom/client"
import { ErrorBoundary } from "@/components/error-boundary"
import { RootErrorBoundary } from "@/components/ui/error-boundary"
import { NotFoundPage } from "@/components/ui/not-found-page"
import { client } from "@/lib/generated/api/client.gen"
import { ThemeProvider } from "@/lib/theme-context"

// Import the generated route tree
import { routeTree } from "./routeTree.gen"

import "./styles.css"
import reportWebVitals from "./reportWebVitals.ts"

// Extend Window type for CSRF token injected by litestar-vite
declare global {
  interface Window {
    __LITESTAR_CSRF__?: string
  }
}

const queryClient = new QueryClient()

const apiUrl = import.meta.env.VITE_API_URL ?? ""

client.setConfig({
  baseUrl: apiUrl,
  credentials: "include",
  auth: () => {
    if (typeof window === "undefined") {
      return undefined
    }
    return window.localStorage.getItem("access_token") ?? undefined
  },
})

// Add CSRF token to all non-GET requests
// litestar-vite injects the token into window.__LITESTAR_CSRF__
client.interceptors.request.use((request, _options) => {
  const method = request.method?.toUpperCase()
  // Only add CSRF header for unsafe methods (non-GET/HEAD/OPTIONS)
  if (method && !["GET", "HEAD", "OPTIONS"].includes(method)) {
    const csrfToken = window.__LITESTAR_CSRF__
    if (csrfToken) {
      request.headers.set("X-XSRF-TOKEN", csrfToken)
    }
  }
  return request
})

// Silent token refresh state
let isRefreshing = false
let failedQueue: Array<{
  resolve: () => void
  reject: (reason?: unknown) => void
}> = []

const processQueue = (error: Error | null) => {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error)
    } else {
      prom.resolve()
    }
  })
  failedQueue = []
}

function retryWithNewToken(request: Request, options: Record<string, unknown>): Promise<Response> {
  const headers = new Headers(request.headers)
  const token = window.localStorage.getItem("access_token")
  if (token) {
    headers.set("Authorization", `Bearer ${token}`)
  }
  return fetch(request.url, {
    method: request.method,
    headers,
    body: (options.serializedBody as BodyInit) ?? undefined,
    credentials: request.credentials,
    redirect: request.redirect,
  })
}

// Response interceptor for silent token refresh.
// Must be a response interceptor (not error) so the retried Response replaces
// the original 401 before the client's ok/error branching logic runs.
client.interceptors.response.use(async (response, request, options) => {
  if (response.status !== 401) {
    return response
  }

  const requestUrl = request.url
  if (requestUrl.includes("/api/access/refresh") || requestUrl.includes("/api/access/login")) {
    return response
  }

  const currentPath = window.location.pathname
  if (["/login", "/signup", "/forgot-password", "/reset-password"].some((p) => currentPath.startsWith(p))) {
    return response
  }

  const opts = options as unknown as Record<string, unknown>

  if (isRefreshing) {
    try {
      await new Promise<void>((resolve, reject) => {
        failedQueue.push({ resolve, reject })
      })
    } catch {
      return response
    }
    return retryWithNewToken(request, opts)
  }

  isRefreshing = true

  try {
    const refreshResult = await client.post({ url: "/api/access/refresh" })
    const refreshData = refreshResult.data as { access_token?: string } | undefined
    if (!refreshData?.access_token) {
      throw new Error("No access token in refresh response")
    }
    window.localStorage.setItem("access_token", refreshData.access_token)
    processQueue(null)
    return retryWithNewToken(request, opts)
  } catch (refreshError) {
    processQueue(refreshError as Error)
    window.localStorage.removeItem("access_token")
    const { useAuthStore } = await import("@/lib/auth")
    useAuthStore.setState({ user: null, currentTeam: null, isAuthenticated: false })
    queryClient.clear()
    if (window.location.pathname !== "/login") {
      window.location.href = "/login"
    }
    return response
  } finally {
    isRefreshing = false
  }
})

// Ensure non-OK responses throw so callers (React Query, checkAuth, etc.)
// see them as errors rather than successful responses with undefined data.
client.interceptors.error.use(async (error) => {
  throw error
})

// Create the router using the generated route tree
const router = createRouter({
  routeTree,
  context: {
    queryClient,
  },
  defaultPreload: "intent",
  scrollRestoration: true,
  defaultStructuralSharing: true,
  defaultPreloadStaleTime: 0,
  defaultErrorComponent: ErrorBoundary,
  defaultNotFoundComponent: NotFoundPage,
})

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router
  }
}

// Render the app
const rootElement = document.getElementById("root")
if (rootElement && !rootElement.innerHTML) {
  const root = ReactDOM.createRoot(rootElement)
  root.render(
    <React.StrictMode>
      <RootErrorBoundary>
        <ThemeProvider>
          <QueryClientProvider client={queryClient}>
            <RouterProvider router={router} />
            <ReactQueryDevtools />
          </QueryClientProvider>
        </ThemeProvider>
      </RootErrorBoundary>
    </React.StrictMode>,
  )
}

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals()
