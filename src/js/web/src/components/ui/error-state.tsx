import { motion } from "framer-motion"
import { AlertCircle } from "lucide-react"
import { Button } from "@/components/ui/button"
import { DURATION } from "@/components/ui/motion"
import { cn } from "@/lib/utils"

interface ErrorStateProps {
  title: string
  description: string
  onRetry?: () => void
  className?: string
}

export function ErrorState({ title, description, onRetry, className }: ErrorStateProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: DURATION.medium, ease: [0.25, 0.1, 0.25, 1] }}
      className={cn("flex flex-col items-center justify-center py-12 px-4 text-center", className)}
    >
      <motion.div
        initial={{ opacity: 0, scale: 0.8 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: DURATION.medium, delay: 0.05, ease: [0.25, 0.1, 0.25, 1] }}
        className="mb-4 rounded-full bg-destructive/10 p-3"
      >
        <AlertCircle className="size-6 text-destructive" />
      </motion.div>
      <h3 className="text-sm font-medium">{title}</h3>
      <p className="mt-1 max-w-sm text-sm text-muted-foreground">{description}</p>
      {onRetry && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: DURATION.normal, delay: 0.15 }} className="mt-4">
          <Button variant="outline" size="sm" onClick={onRetry}>
            Try again
          </Button>
        </motion.div>
      )}
    </motion.div>
  )
}
