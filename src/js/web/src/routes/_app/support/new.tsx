import { createFileRoute, Link } from "@tanstack/react-router"
import { useDocumentTitle } from "@/hooks/use-document-title"
import {
  AlertTriangle,
  ArrowDown,
  ArrowRight,
  ArrowUp,
  Clock,
  FileText,
  Flame,
  MessageSquare,
  Shield,
} from "lucide-react"
import { CreateTicketForm } from "@/components/support/create-ticket-form"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { PageContainer, PageHeader } from "@/components/ui/page-layout"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { Separator } from "@/components/ui/separator"
import { cn } from "@/lib/utils"

export const Route = createFileRoute("/_app/support/new")({
  component: NewTicketPage,
})

const tips = [
  {
    icon: FileText,
    title: "Be specific",
    description: "Include details like error messages, steps to reproduce, and what you expected to happen.",
  },
  {
    icon: Shield,
    title: "Set priority correctly",
    description: "Accurate priority helps us allocate the right resources and respond within SLA.",
  },
  {
    icon: MessageSquare,
    title: "Stay in the loop",
    description: "You'll receive email notifications when our team responds to your ticket.",
  },
  {
    icon: Clock,
    title: "Track progress",
    description: "Monitor your ticket status and add follow-up messages from the Support page.",
  },
]

const responseTimes = [
  { priority: "Urgent", icon: Flame, time: "< 1 hour", dotClass: "bg-red-500" },
  { priority: "High", icon: ArrowUp, time: "< 4 hours", dotClass: "bg-amber-500" },
  { priority: "Medium", icon: ArrowRight, time: "< 1 business day", dotClass: "bg-blue-500" },
  { priority: "Low", icon: ArrowDown, time: "< 2 business days", dotClass: "bg-zinc-400" },
]

function NewTicketPage() {
  useDocumentTitle("New Ticket")
  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Helpdesk"
        title="New Ticket"
        description="Create a support ticket to get help from our team."
        breadcrumbs={
          <Breadcrumb>
            <BreadcrumbList>
              <BreadcrumbItem>
                <BreadcrumbLink asChild>
                  <Link to="/home">Home</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbLink asChild>
                  <Link to="/support">Support</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbPage>New Ticket</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
      />

      <div className="flex gap-6">
        {/* Main form */}
        <SectionErrorBoundary name="Create Ticket Form">
        <Card className="min-w-0 flex-1">
          <CardHeader>
            <CardTitle className="text-lg">Ticket Details</CardTitle>
            <CardDescription>
              Fields marked with <span className="text-destructive">*</span> are required.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <CreateTicketForm />
          </CardContent>
        </Card>
        </SectionErrorBoundary>

        {/* Sidebar */}
        <div className="flex h-fit w-72 shrink-0 flex-col gap-4">
          {/* Tips card */}
          <Card className="border-border/40 bg-linear-to-br from-muted/30 to-muted/10">
            <CardHeader className="space-y-1 pb-3">
              <CardTitle className="text-lg">Tips</CardTitle>
              <CardDescription>For a faster resolution</CardDescription>
            </CardHeader>
            <CardContent className="space-y-1.5">
              {tips.map((tip) => (
                <div key={tip.title} className="group flex items-start gap-3 rounded-lg bg-background/60 p-3">
                  <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
                    <tip.icon className="h-4 w-4" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="font-medium text-sm">{tip.title}</p>
                    <p className="text-xs leading-relaxed text-muted-foreground">{tip.description}</p>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>

          {/* Response times card */}
          <Card className="border-border/40 bg-linear-to-br from-muted/30 to-muted/10">
            <CardHeader className="space-y-1 pb-3">
              <CardTitle className="flex items-center gap-2 text-base">
                <Clock className="h-4 w-4 text-muted-foreground" />
                Response Times
              </CardTitle>
              <CardDescription>Expected first response by priority</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-2.5">
                {responseTimes.map((rt) => (
                  <div key={rt.priority} className="flex items-center gap-3">
                    <div className={cn("h-2 w-2 shrink-0 rounded-full", rt.dotClass)} />
                    <div className="flex flex-1 items-center justify-between">
                      <span className="text-sm font-medium">{rt.priority}</span>
                      <span className="text-xs text-muted-foreground">{rt.time}</span>
                    </div>
                  </div>
                ))}
              </div>
              <Separator className="my-3" />
              <div className="flex items-start gap-2 rounded-md bg-amber-500/5 px-2.5 py-2">
                <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-500" />
                <p className="text-[11px] leading-relaxed text-muted-foreground">
                  Response times are based on business hours (Mon-Fri, 9AM-6PM EST). Urgent tickets are monitored 24/7.
                </p>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </PageContainer>
  )
}
