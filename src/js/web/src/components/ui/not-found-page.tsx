import { Link } from "@tanstack/react-router"
import { ArrowLeft, FileQuestion } from "lucide-react"
import { Button } from "@/components/ui/button"

/**
 * A polished 404 page for unmatched routes.
 * Used as TanStack Router's `notFoundComponent` on the root route.
 */
export function NotFoundPage() {
  return (
    <div className="flex min-h-screen w-full items-center justify-center px-4 py-12">
      <div className="flex flex-col items-center text-center">
        <div className="mb-6 flex h-20 w-20 items-center justify-center rounded-full bg-muted/60">
          <FileQuestion className="h-10 w-10 text-muted-foreground/60" />
        </div>
        <h1 className="mb-2 font-heading text-7xl font-bold tracking-tighter text-foreground/15 select-none">
          404
        </h1>
        <h2 className="mb-2 text-xl font-semibold tracking-tight">Page not found</h2>
        <p className="mb-8 max-w-md text-sm text-muted-foreground">
          The page you are looking for does not exist or may have been moved.
        </p>
        <Button asChild variant="default">
          <Link to="/home">
            <ArrowLeft className="mr-2 h-4 w-4" />
            Go back home
          </Link>
        </Button>
      </div>
    </div>
  )
}
