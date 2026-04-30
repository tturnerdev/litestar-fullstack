import { Component, type ErrorInfo, type ReactNode, useState } from "react"
import { AlertCircle, ChevronDown, ChevronRight, ClipboardCopy, Home, RefreshCw } from "lucide-react"
import { motion } from "framer-motion"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"

const isDev = import.meta.env.DEV

function generateErrorCode(message: string): string {
  let hash = 0
  for (let i = 0; i < message.length; i++) {
    const char = message.charCodeAt(i)
    hash = ((hash << 5) - hash + char) | 0
  }
  return `ERR-${Math.abs(hash).toString(16).padStart(8, "0").slice(0, 8).toUpperCase()}`
}

interface ErrorFallbackProps {
  error: Error
  resetError?: () => void
}

/**
 * Shared error UI used by both the React class boundary and TanStack Router's errorComponent.
 */
function ErrorFallback({ error, resetError }: ErrorFallbackProps) {
  const [stackOpen, setStackOpen] = useState(false)

  const message = isDev ? error.message : "Something unexpected happened. Please try again or return to the home page."
  const errorCode = generateErrorCode(error.message)

  const handleCopyError = async () => {
    const details = [
      `Error Code: ${errorCode}`,
      `Message: ${error.message}`,
      error.stack ? `\nStack Trace:\n${error.stack}` : "",
    ]
      .filter(Boolean)
      .join("\n")

    try {
      await navigator.clipboard.writeText(details)
      toast.success("Error details copied to clipboard")
    } catch {
      toast.error("Failed to copy error details")
    }
  }

  return (
    <div className="flex min-h-screen w-full items-center justify-center bg-gradient-to-b from-destructive/5 to-transparent px-4 py-12">
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.3, ease: "easeOut" }}
        className="w-full max-w-md"
      >
        <Card className="border-border/60 bg-card/80 shadow-xl shadow-destructive/10">
          <CardHeader className="text-center">
            <div className="mx-auto mb-2 flex h-14 w-14 items-center justify-center rounded-full bg-destructive/10">
              <AlertCircle className="h-7 w-7 text-destructive" />
            </div>
            <CardTitle className="text-xl">Something went wrong</CardTitle>
            <p className="mt-1 font-mono text-xs text-muted-foreground">{errorCode}</p>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-center text-sm text-muted-foreground">{message}</p>
            {isDev && error.stack && (
              <Collapsible open={stackOpen} onOpenChange={setStackOpen}>
                <CollapsibleTrigger asChild>
                  <Button variant="ghost" size="sm" className="w-full justify-start gap-2 text-xs text-muted-foreground">
                    {stackOpen ? <ChevronDown className="size-3.5" /> : <ChevronRight className="size-3.5" />}
                    Show technical details
                  </Button>
                </CollapsibleTrigger>
                <CollapsibleContent>
                  <pre className="mt-2 max-h-40 overflow-auto rounded-md bg-muted/60 p-3 text-xs text-muted-foreground">
                    {error.stack}
                  </pre>
                </CollapsibleContent>
              </Collapsible>
            )}
            <div className="flex flex-col gap-2">
              {resetError && (
                <Button onClick={resetError} variant="default" className="w-full">
                  <RefreshCw className="mr-2 h-4 w-4" />
                  Try again
                </Button>
              )}
              <Button onClick={handleCopyError} variant="secondary" className="w-full">
                <ClipboardCopy className="mr-2 h-4 w-4" />
                Copy error details
              </Button>
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
      </motion.div>
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
