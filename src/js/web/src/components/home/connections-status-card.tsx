import { Link } from "@tanstack/react-router"
import { motion } from "framer-motion"
import { ArrowRight, Cable, Plus } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useConnections, type ConnectionList } from "@/lib/api/hooks/connections"

const MAX_VISIBLE = 5

function getStatusColor(status: string): string {
  const lower = status.toLowerCase()
  if (lower === "connected" || lower === "healthy" || lower === "active") {
    return "bg-emerald-500"
  }
  if (lower === "error" || lower === "failed") {
    return "bg-red-500"
  }
  return "bg-muted-foreground/40"
}

function getStatusLabel(status: string): string {
  const lower = status.toLowerCase()
  if (lower === "connected" || lower === "healthy" || lower === "active") return "Connected"
  if (lower === "error" || lower === "failed") return "Error"
  if (lower === "disconnected") return "Disconnected"
  return "Unknown"
}

function ConnectionRow({ connection, index }: { connection: ConnectionList; index: number }) {
  return (
    <motion.div
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.25, delay: index * 0.05, ease: "easeOut" }}
    >
      <Link
        to="/connections/$connectionId"
        params={{ connectionId: connection.id }}
        className="group flex items-center gap-3 rounded-lg px-3 py-2.5 transition-colors hover:bg-muted/50"
      >
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="relative flex h-2.5 w-2.5 shrink-0">
              <span className={`absolute inline-flex h-full w-full rounded-full ${getStatusColor(connection.status)}`} />
            </span>
          </TooltipTrigger>
          <TooltipContent side="left">{getStatusLabel(connection.status)}</TooltipContent>
        </Tooltip>
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="min-w-0 flex-1 truncate text-sm font-medium">{connection.name}</span>
          </TooltipTrigger>
          <TooltipContent>{connection.name}</TooltipContent>
        </Tooltip>
        <Badge variant="secondary" className="h-5 shrink-0 px-1.5 py-0 text-[10px] font-medium">
          {connection.provider}
        </Badge>
      </Link>
    </motion.div>
  )
}

export function ConnectionsStatusCard() {
  const { data, isLoading } = useConnections({ page: 1, pageSize: MAX_VISIBLE + 1 })

  const connections = data?.items ?? []
  const total = data?.total ?? 0
  const healthyCount = connections.filter(
    (c) => ["connected", "healthy", "active"].includes(c.status.toLowerCase()),
  ).length

  if (isLoading) {
    return (
      <Card>
        <CardHeader className="space-y-1 pb-4">
          <div className="flex items-center gap-2">
            <Cable className="h-4 w-4 text-muted-foreground" />
            <CardTitle className="text-lg">Connections</CardTitle>
          </div>
          <CardDescription>External integration status</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {Array.from({ length: 3 }).map((_, i) => (
            // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
            <div key={`conn-skeleton-${i}`} className="flex items-center gap-3 px-3">
              <Skeleton className="h-2.5 w-2.5 shrink-0 rounded-full" />
              <Skeleton className="h-4 flex-1" />
              <Skeleton className="h-5 w-14 rounded-full" />
            </div>
          ))}
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader className="space-y-1 pb-4">
        <div className="flex items-center gap-2">
          <Cable className="h-4 w-4 text-muted-foreground" />
          <CardTitle className="text-lg">Connections</CardTitle>
        </div>
        <CardDescription>
          {total > 0
            ? `${healthyCount} of ${total} connected`
            : "External integration status"}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {connections.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-8 text-center">
            <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-muted">
              <Cable className="h-6 w-6 text-muted-foreground" />
            </div>
            <p className="text-sm font-medium text-muted-foreground">No connections configured</p>
            <p className="mt-1 text-xs text-muted-foreground/70">
              Add an integration to connect external services.
            </p>
            <Button asChild size="sm" variant="outline" className="mt-4">
              <Link to="/connections">
                <Plus className="mr-1.5 h-3.5 w-3.5" />
                Add connection
              </Link>
            </Button>
          </div>
        ) : (
          <>
            <div className="space-y-1">
              {connections.slice(0, MAX_VISIBLE).map((connection, index) => (
                <ConnectionRow key={connection.id} connection={connection} index={index} />
              ))}
            </div>
            {total > MAX_VISIBLE && (
              <div className="mt-4 border-t pt-3">
                <Link
                  to="/connections"
                  className="flex items-center justify-center gap-1.5 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground"
                >
                  View all {total} connections
                  <ArrowRight className="h-3.5 w-3.5" />
                </Link>
              </div>
            )}
          </>
        )}
      </CardContent>
    </Card>
  )
}
