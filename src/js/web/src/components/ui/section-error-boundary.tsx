import * as Sentry from "@sentry/react"
import { AlertCircle, RefreshCw } from "lucide-react"
import { Component, type ErrorInfo, type ReactNode } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"

interface SectionErrorBoundaryProps {
  children: ReactNode
  /** Optional name shown in the fallback, e.g. "System Health" */
  name?: string
}

interface SectionErrorBoundaryState {
  hasError: boolean
  error: Error | null
}

/**
 * A lightweight error boundary for individual page sections.
 *
 * Unlike the root `RootErrorBoundary`, this renders a compact inline Card
 * so that a single failing section does not crash the rest of the page.
 */
export class SectionErrorBoundary extends Component<SectionErrorBoundaryProps, SectionErrorBoundaryState> {
  constructor(props: SectionErrorBoundaryProps) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error: Error): SectionErrorBoundaryState {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error(`[SectionErrorBoundary${this.props.name ? `: ${this.props.name}` : ""}]`, error, errorInfo)
    Sentry.captureException(error, {
      contexts: { react: { componentStack: errorInfo.componentStack ?? undefined } },
      tags: { boundary: "section", section: this.props.name },
    })
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null })
  }

  render() {
    if (this.state.hasError) {
      return (
        <Card>
          <CardContent className="flex items-center gap-3 px-4 py-4">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-destructive/10">
              <AlertCircle className="h-5 w-5 text-destructive" />
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-sm font-medium">This section couldn't load</p>
              <p className="text-xs text-muted-foreground">
                {this.props.name ? `Something went wrong loading ${this.props.name}.` : "An unexpected error occurred in this section."}
              </p>
            </div>
            <Button variant="outline" size="sm" onClick={this.handleReset}>
              <RefreshCw className="mr-1.5 h-3.5 w-3.5" />
              Try again
            </Button>
          </CardContent>
        </Card>
      )
    }

    return this.props.children
  }
}
