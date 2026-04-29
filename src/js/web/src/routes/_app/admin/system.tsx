import { createFileRoute } from "@tanstack/react-router"
import { RefreshCw } from "lucide-react"
import { AdminBreadcrumbs } from "@/components/admin/admin-breadcrumbs"
import { AdminNav } from "@/components/admin/admin-nav"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonCard } from "@/components/ui/skeleton"
import { useAdminSystemStatus } from "@/lib/api/hooks/admin"

export const Route = createFileRoute("/_app/admin/system")({
  component: AdminSystemPage,
})

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  const secs = Math.floor(seconds % 60)

  const parts: string[] = []
  if (days > 0) parts.push(`${days}d`)
  if (hours > 0) parts.push(`${hours}h`)
  if (minutes > 0) parts.push(`${minutes}m`)
  parts.push(`${secs}s`)
  return parts.join(" ")
}

function AdminSystemPage() {
  const { data, isLoading, isError, refetch, isFetching } = useAdminSystemStatus()

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Administration"
        title="System Status"
        description="Monitor system health, application info, and worker queues."
        breadcrumbs={<AdminBreadcrumbs />}
        actions={
          <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={isFetching ? "animate-spin" : ""} />
            Refresh
          </Button>
        }
      />
      <AdminNav />
      <PageSection>
        {isLoading ? (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            {Array.from({ length: 4 }).map((_, index) => (
              // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
              <SkeletonCard key={`system-skeleton-${index}`} />
            ))}
          </div>
        ) : isError || !data ? (
          <Card>
            <CardHeader>
              <CardTitle>System Status</CardTitle>
            </CardHeader>
            <CardContent className="text-muted-foreground">Unable to load system status. The server may be unreachable.</CardContent>
          </Card>
        ) : (
          <div className="space-y-6">
            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm text-muted-foreground">Database</CardTitle>
                </CardHeader>
                <CardContent>
                  <Badge variant={data.databaseStatus === "online" ? "default" : "destructive"}>
                    {data.databaseStatus === "online" ? "Online" : "Offline"}
                  </Badge>
                </CardContent>
              </Card>
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm text-muted-foreground">Application</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-lg font-semibold">{data.appName}</div>
                  <div className="text-sm text-muted-foreground">{data.appVersion}</div>
                </CardContent>
              </Card>
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm text-muted-foreground">Python Version</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-lg font-semibold">{data.pythonVersion}</div>
                </CardContent>
              </Card>
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm text-muted-foreground">Uptime</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-lg font-semibold">{formatUptime(data.uptimeSeconds)}</div>
                  <div className="text-sm text-muted-foreground">
                    Since {new Date(data.startedAt).toLocaleString()}
                  </div>
                </CardContent>
              </Card>
            </div>

            {data.debugMode && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm text-muted-foreground">Debug Mode</CardTitle>
                </CardHeader>
                <CardContent>
                  <Badge variant="secondary">Debug mode is enabled</Badge>
                </CardContent>
              </Card>
            )}

            {data.workerQueues && data.workerQueues.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm font-semibold">Worker Queues</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                    {data.workerQueues.map((queue) => (
                      <div key={queue.name} className="rounded-lg border p-4">
                        <div className="mb-2 font-medium">{queue.name}</div>
                        <div className="grid grid-cols-3 gap-2 text-sm">
                          <div>
                            <div className="text-muted-foreground">Queued</div>
                            <div className="font-semibold">{queue.queued}</div>
                          </div>
                          <div>
                            <div className="text-muted-foreground">Active</div>
                            <div className="font-semibold">{queue.active}</div>
                          </div>
                          <div>
                            <div className="text-muted-foreground">Scheduled</div>
                            <div className="font-semibold">{queue.scheduled}</div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
        )}
      </PageSection>
    </PageContainer>
  )
}
