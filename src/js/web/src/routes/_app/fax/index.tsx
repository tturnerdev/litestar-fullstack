import { createFileRoute, Link } from "@tanstack/react-router"
import { ChevronRight, FileText, Hash, Send } from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonCard } from "@/components/ui/skeleton"
import { useFaxMessages, useFaxNumbers } from "@/lib/api/hooks/fax"

export const Route = createFileRoute("/_app/fax/")({
  component: FaxOverviewPage,
})

function FaxOverviewPage() {
  const { data: numbers, isLoading: numbersLoading } = useFaxNumbers(1, 100)
  const { data: messages, isLoading: messagesLoading } = useFaxMessages({ page: 1, pageSize: 5 })

  const isLoading = numbersLoading || messagesLoading

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Communications"
        title="Fax"
        description="Manage your fax numbers, view message history, and send faxes."
      />

      <PageSection delay={0.1}>
        {isLoading ? (
          <div className="grid gap-4 md:grid-cols-3">
            {Array.from({ length: 3 }).map((_, index) => (
              // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
              <SkeletonCard key={`fax-stats-skeleton-${index}`} />
            ))}
          </div>
        ) : (
          <div className="grid gap-4 md:grid-cols-3">
            <Card>
              <CardHeader>
                <CardTitle className="text-sm text-muted-foreground">Fax Numbers</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-semibold">{numbers?.total ?? 0}</div>
                <p className="text-xs text-muted-foreground mt-1">
                  {numbers?.items.filter((n) => n.isActive).length ?? 0} active
                </p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle className="text-sm text-muted-foreground">Recent Messages</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-semibold">{messages?.total ?? 0}</div>
                <p className="text-xs text-muted-foreground mt-1">total messages</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle className="text-sm text-muted-foreground">Failed Deliveries</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-semibold">
                  {messages?.items.filter((m) => m.status === "failed").length ?? 0}
                </div>
                <p className="text-xs text-muted-foreground mt-1">in recent messages</p>
              </CardContent>
            </Card>
          </div>
        )}
      </PageSection>

      <PageSection delay={0.2}>
        <Card className="border-border/40 bg-linear-to-br from-muted/30 to-muted/10">
          <CardHeader className="space-y-1 pb-3">
            <CardTitle className="text-lg">Quick Actions</CardTitle>
            <CardDescription>Common fax tasks</CardDescription>
          </CardHeader>
          <CardContent className="space-y-1.5">
            <Link to="/fax/numbers" className="group flex items-center gap-3 rounded-lg bg-background/60 p-3 transition-all hover:bg-background hover:shadow-sm">
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary transition-colors group-hover:bg-primary group-hover:text-primary-foreground">
                <Hash className="h-4 w-4" />
              </div>
              <div className="flex-1 min-w-0">
                <p className="font-medium text-sm">Fax Numbers</p>
                <p className="text-xs text-muted-foreground">Manage numbers and email routes</p>
              </div>
              <ChevronRight className="h-4 w-4 text-muted-foreground/50 transition-transform group-hover:translate-x-0.5 group-hover:text-foreground" />
            </Link>
            <Link to="/fax/messages" className="group flex items-center gap-3 rounded-lg bg-background/60 p-3 transition-all hover:bg-background hover:shadow-sm">
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-blue-500/10 text-blue-600 transition-colors group-hover:bg-blue-500 group-hover:text-white dark:text-blue-400">
                <FileText className="h-4 w-4" />
              </div>
              <div className="flex-1 min-w-0">
                <p className="font-medium text-sm">Message History</p>
                <p className="text-xs text-muted-foreground">View sent and received faxes</p>
              </div>
              <ChevronRight className="h-4 w-4 text-muted-foreground/50 transition-transform group-hover:translate-x-0.5 group-hover:text-foreground" />
            </Link>
            <Link to="/fax/send" className="group flex items-center gap-3 rounded-lg bg-background/60 p-3 transition-all hover:bg-background hover:shadow-sm">
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-600 transition-colors group-hover:bg-emerald-500 group-hover:text-white dark:text-emerald-400">
                <Send className="h-4 w-4" />
              </div>
              <div className="flex-1 min-w-0">
                <p className="font-medium text-sm">Send a Fax</p>
                <p className="text-xs text-muted-foreground">Upload a PDF and send</p>
              </div>
              <ChevronRight className="h-4 w-4 text-muted-foreground/50 transition-transform group-hover:translate-x-0.5 group-hover:text-foreground" />
            </Link>
          </CardContent>
        </Card>
      </PageSection>
    </PageContainer>
  )
}
