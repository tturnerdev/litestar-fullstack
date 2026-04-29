import { createFileRoute, Link } from "@tanstack/react-router"
import { useState } from "react"
import { AlertCircle, Cable, CheckCircle2, Circle, Plus, Search, XCircle } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { PageCardGrid, PageCardGridItem, PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonCard } from "@/components/ui/skeleton"
import { useConnections } from "@/lib/api/hooks/connections"

export const Route = createFileRoute("/_app/connections/")({
  component: ConnectionsPage,
})

const typeLabels: Record<string, string> = {
  pbx: "PBX",
  helpdesk: "Helpdesk",
  carrier: "Carrier",
  other: "Other",
}

const typeBadgeVariant: Record<string, "default" | "secondary" | "outline" | "destructive"> = {
  pbx: "default",
  helpdesk: "secondary",
  carrier: "outline",
  other: "outline",
}

function StatusIndicator({ status }: { status: string }) {
  switch (status) {
    case "connected":
      return (
        <span className="flex items-center gap-1.5 text-xs text-emerald-600 dark:text-emerald-400">
          <CheckCircle2 className="h-3.5 w-3.5" />
          Connected
        </span>
      )
    case "disconnected":
      return (
        <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <XCircle className="h-3.5 w-3.5" />
          Disconnected
        </span>
      )
    case "error":
      return (
        <span className="flex items-center gap-1.5 text-xs text-destructive">
          <AlertCircle className="h-3.5 w-3.5" />
          Error
        </span>
      )
    default:
      return (
        <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <Circle className="h-3.5 w-3.5" />
          Unknown
        </span>
      )
  }
}

function formatDateTime(value: string | null | undefined): string {
  if (!value) return "Never"
  return new Date(value).toLocaleString()
}

function ConnectionsPage() {
  const [search, setSearch] = useState("")
  const { data, isLoading, isError } = useConnections({ search: search || undefined })

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Administration"
        title="Connections"
        description="Manage external data source integrations (PBX, helpdesk, carriers, and more)."
        actions={
          <Button size="sm" asChild>
            <Link to="/connections/new">
              <Plus className="mr-2 h-4 w-4" /> Add connection
            </Link>
          </Button>
        }
      />

      <PageSection>
        <div className="flex items-center gap-3">
          <div className="relative max-w-sm flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search connections..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9"
            />
          </div>
        </div>
      </PageSection>

      <PageSection delay={0.1}>
        {isLoading ? (
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            {Array.from({ length: 3 }).map((_, i) => (
              <SkeletonCard key={i} />
            ))}
          </div>
        ) : isError ? (
          <EmptyState
            icon={AlertCircle}
            title="Unable to load connections"
            description="Something went wrong while fetching your connections. Please try refreshing the page."
            action={
              <Button variant="outline" size="sm" onClick={() => window.location.reload()}>
                Refresh page
              </Button>
            }
          />
        ) : !data?.items.length && !search ? (
          <EmptyState
            icon={Cable}
            title="No connections yet"
            description="Add your first connection to integrate with an external data source."
            action={
              <Button size="sm" asChild>
                <Link to="/connections/new">
                  <Plus className="mr-2 h-4 w-4" /> Add connection
                </Link>
              </Button>
            }
          />
        ) : !data?.items.length ? (
          <EmptyState
            icon={Cable}
            variant="no-results"
            title="No results found"
            description="No connections match your search. Try a different search term."
            action={
              <Button variant="outline" size="sm" onClick={() => setSearch("")}>
                Clear search
              </Button>
            }
          />
        ) : (
          <PageCardGrid>
            {data.items.map((conn) => (
              <PageCardGridItem key={conn.id}>
                <Link to={`/connections/${conn.id}` as string} className="block">
                  <Card className="transition-colors hover:border-primary/30 hover:bg-muted/30">
                    <CardHeader className="pb-3">
                      <div className="flex items-start justify-between gap-2">
                        <div className="min-w-0 flex-1">
                          <CardTitle className="truncate text-base">{conn.name}</CardTitle>
                          <p className="mt-0.5 truncate text-sm text-muted-foreground">{conn.provider}</p>
                        </div>
                        <Badge variant={typeBadgeVariant[conn.connectionType] ?? "outline"}>
                          {typeLabels[conn.connectionType] ?? conn.connectionType}
                        </Badge>
                      </div>
                    </CardHeader>
                    <CardContent className="space-y-3 pt-0">
                      {conn.host && (
                        <p className="truncate font-mono text-xs text-muted-foreground">
                          {conn.host}
                          {conn.port ? `:${conn.port}` : ""}
                        </p>
                      )}
                      <div className="flex items-center justify-between">
                        <StatusIndicator status={conn.status} />
                        <span className="text-xs text-muted-foreground">
                          Checked: {formatDateTime(conn.lastHealthCheck)}
                        </span>
                      </div>
                      {!conn.isEnabled && (
                        <Badge variant="outline" className="border-muted-foreground/30 text-muted-foreground">
                          Disabled
                        </Badge>
                      )}
                    </CardContent>
                  </Card>
                </Link>
              </PageCardGridItem>
            ))}
          </PageCardGrid>
        )}
      </PageSection>
    </PageContainer>
  )
}
