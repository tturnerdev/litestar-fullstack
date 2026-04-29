import { Component, type ErrorInfo, type ReactNode } from "react"
import { AlertCircle, Home, RefreshCw } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"

const isDev = import.meta.env.DEV

interface ErrorFallbackProps {
  error: Error
  resetError?: () => void
}

/**
 * Shared error UI used by both the React class boundary and TanStack Router's errorComponent.
 */
function ErrorFallback({ error, resetError }: ErrorFallbackProps) {
  const message = isDev ? error.message : "Something unexpected happened. Please try again or return to the home page."

  return (
    <div className="flex min-h-screen w-full items-center justify-center px-4 py-12">
      <Card className="w-full max-w-md border-border/60 bg-card/80 shadow-xl shadow-destructive/10">
        <CardHeader className="text-center">
          <div className="mx-auto mb-2 flex h-14 w-14 items-center justify-center rounded-full bg-destructive/10">
            <AlertCircle className="h-7 w-7 text-destructive" />
          </div>
          <CardTitle className="text-xl">Something went wrong</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-center text-sm text-muted-foreground">{message}</p>
          {isDev && error.stack && (
            <pre className="max-h-40 overflow-auto rounded-md bg-muted/60 p-3 text-xs text-muted-foreground">
              {error.stack}
            </pre>
          )}
          <div className="flex flex-col gap-2">
            {resetError && (
              <Button onClick={resetError} variant="default" className="w-full">
                <RefreshCw className="mr-2 h-4 w-4" />
                Try again
              </Button>
            )}
            <Button
              onClick={() => {
                window.location.href = "/home"
              }}
              variant="outline"
              className="w-full"
            >
              <Home className="mr-2 h-4 w-4" />
              Go home
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

interface RootErrorBoundaryProps {
  children: ReactNode
}

interface RootErrorBoundaryState {
  hasError: boolean
  error: Error | null
}

/**
 * A React class-based error boundary that wraps the entire application.
 * Catches errors that occur outside of TanStack Router's own error handling.
 */
export class RootErrorBoundary extends Component<RootErrorBoundaryProps, RootErrorBoundaryState> {
  constructor(props: RootErrorBoundaryProps) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error: Error): RootErrorBoundaryState {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("[RootErrorBoundary] Uncaught error:", error, errorInfo)
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null })
  }

  render() {
    if (this.state.hasError && this.state.error) {
      return <ErrorFallback error={this.state.error} resetError={this.handleReset} />
    }
    return this.props.children
  }
}

export { ErrorFallback }
