import { Component, type ErrorInfo, type ReactNode } from "react"
import { AlertTriangle, RefreshCcw } from "lucide-react"
import { Button } from "@/components/ui/button"

interface Props {
  children: ReactNode
  /** Rendered instead of the default panel; receives a reset callback. */
  fallback?: (error: Error, reset: () => void) => ReactNode
  onReset?: () => void
}

interface State {
  error: Error | null
}

/** Catches render errors (e.g. an unexpected report shape) so one bad result never blanks the app. */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error("UI error boundary caught:", error, info.componentStack)
  }

  reset = (): void => {
    this.setState({ error: null })
    this.props.onReset?.()
  }

  render(): ReactNode {
    const { error } = this.state
    if (!error) return this.props.children
    if (this.props.fallback) return this.props.fallback(error, this.reset)

    return (
      <div role="alert" className="mx-auto my-12 max-w-lg rounded-lg border border-destructive/40 bg-destructive/10 p-6 text-sm">
        <div className="mb-2 flex items-center gap-2 font-semibold text-destructive">
          <AlertTriangle className="h-4 w-4" />
          Something went wrong while rendering this view
        </div>
        <pre className="mb-4 whitespace-pre-wrap break-words font-mono text-xs text-muted-foreground">{error.message}</pre>
        <Button variant="outline" size="sm" onClick={this.reset}>
          <RefreshCcw className="mr-2 h-3.5 w-3.5" />
          Try again
        </Button>
      </div>
    )
  }
}
