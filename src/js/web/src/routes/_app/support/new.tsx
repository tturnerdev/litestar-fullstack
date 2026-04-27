import { createFileRoute } from "@tanstack/react-router"
import { ChevronRight, Clock, FileText, MessageSquare, Shield } from "lucide-react"
import { CreateTicketForm } from "@/components/support/create-ticket-form"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { PageContainer, PageHeader } from "@/components/ui/page-layout"

export const Route = createFileRoute("/_app/support/new")({
  component: NewTicketPage,
})

const tips = [
  {
    icon: FileText,
    title: "Be specific",
    description: "Include details about the issue",
  },
  {
    icon: Shield,
    title: "Set priority",
    description: "Helps us respond appropriately",
  },
  {
    icon: MessageSquare,
    title: "Stay in the loop",
    description: "You'll be notified of updates",
  },
  {
    icon: Clock,
    title: "Track progress",
    description: "Monitor your ticket status",
  },
]

function NewTicketPage() {
  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader eyebrow="Helpdesk" title="New Ticket" description="Create a support ticket to get help from our team." />

      <div className="flex gap-6">
        {/* Main form */}
        <Card className="min-w-0 flex-1">
          <CardHeader>
            <CardTitle className="text-lg">Ticket Details</CardTitle>
          </CardHeader>
          <CardContent>
            <CreateTicketForm />
          </CardContent>
        </Card>

        {/* Sidebar tips */}
        <Card className="h-fit w-72 shrink-0 border-border/40 bg-linear-to-br from-muted/30 to-muted/10">
          <CardHeader className="space-y-1 pb-3">
            <CardTitle className="text-lg">Tips</CardTitle>
            <CardDescription>For a faster resolution</CardDescription>
          </CardHeader>
          <CardContent className="space-y-1.5">
            {tips.map((tip) => (
              <div key={tip.title} className="group flex items-center gap-3 rounded-lg bg-background/60 p-3">
                <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
                  <tip.icon className="h-4 w-4" />
                </div>
                <div className="min-w-0 flex-1">
                  <p className="font-medium text-sm">{tip.title}</p>
                  <p className="text-xs text-muted-foreground">{tip.description}</p>
                </div>
                <ChevronRight className="h-4 w-4 text-muted-foreground/30" />
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </PageContainer>
  )
}
