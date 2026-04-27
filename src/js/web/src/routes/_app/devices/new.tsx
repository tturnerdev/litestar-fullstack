import { createFileRoute } from "@tanstack/react-router"
import { ChevronRight, Monitor, Phone, Radio, Settings } from "lucide-react"
import { CreateDeviceForm } from "@/components/devices/device-form"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { PageContainer, PageHeader } from "@/components/ui/page-layout"

export const Route = createFileRoute("/_app/devices/new")({
  component: NewDevicePage,
})

const tips = [
  {
    icon: Phone,
    title: "Desk phones",
    description: "Register physical SIP phones",
  },
  {
    icon: Monitor,
    title: "Softphones",
    description: "Add software-based phone clients",
  },
  {
    icon: Radio,
    title: "Auto-provisioning",
    description: "SIP credentials are generated automatically",
  },
  {
    icon: Settings,
    title: "Configure later",
    description: "Line assignments and settings come next",
  },
]

function NewDevicePage() {
  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader eyebrow="Devices" title="Add New Device" description="Register a new phone or SIP device to your account." />

      <div className="flex gap-6">
        {/* Main form */}
        <Card className="min-w-0 flex-1">
          <CardHeader>
            <CardTitle className="text-lg">Device Details</CardTitle>
          </CardHeader>
          <CardContent>
            <CreateDeviceForm />
          </CardContent>
        </Card>

        {/* Sidebar tips */}
        <Card className="h-fit w-72 shrink-0 border-border/40 bg-linear-to-br from-muted/30 to-muted/10">
          <CardHeader className="space-y-1 pb-3">
            <CardTitle className="text-lg">Getting Started</CardTitle>
            <CardDescription>Tips for adding devices</CardDescription>
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
