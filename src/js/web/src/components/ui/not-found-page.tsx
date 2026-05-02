import { Link } from "@tanstack/react-router"
import { motion } from "framer-motion"
import { ArrowLeft, FileQuestion, Home, LifeBuoy, Settings } from "lucide-react"
import { Button } from "@/components/ui/button"

/**
 * A polished 404 page for unmatched routes.
 * Used as TanStack Router's `notFoundComponent` on the root route.
 */
export function NotFoundPage() {
  return (
    <div className="flex min-h-screen w-full items-center justify-center bg-gradient-to-b from-primary/5 to-transparent px-4 py-12">
      <motion.div className="flex flex-col items-center text-center" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4, ease: "easeOut" }}>
        <motion.div
          className="mb-6 flex h-20 w-20 items-center justify-center rounded-full bg-muted/60"
          animate={{ y: [0, -8, 0] }}
          transition={{ duration: 3, repeat: Infinity, ease: "easeInOut" }}
        >
          <FileQuestion className="h-10 w-10 text-muted-foreground/60" />
        </motion.div>
        <h1 className="mb-2 font-heading text-7xl font-bold tracking-tighter text-foreground/15 select-none">404</h1>
        <h2 className="mb-2 text-xl font-semibold tracking-tight">Page not found</h2>
        <p className="mb-6 max-w-md text-sm text-muted-foreground">The page you are looking for does not exist or may have been moved.</p>
        <div className="mb-6 flex items-center gap-2">
          <Button asChild variant="outline" size="sm">
            <Link to="/home">
              <Home className="mr-1.5 h-3.5 w-3.5" />
              Home
            </Link>
          </Button>
          <Button asChild variant="outline" size="sm">
            <Link to="/support">
              <LifeBuoy className="mr-1.5 h-3.5 w-3.5" />
              Support
            </Link>
          </Button>
          <Button asChild variant="outline" size="sm">
            <Link to="/settings">
              <Settings className="mr-1.5 h-3.5 w-3.5" />
              Settings
            </Link>
          </Button>
        </div>
        <Button asChild variant="default">
          <Link to="/home">
            <ArrowLeft className="mr-2 h-4 w-4" />
            Go back home
          </Link>
        </Button>
      </motion.div>
    </div>
  )
}
