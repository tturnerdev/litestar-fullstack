import { createFileRoute, Link } from "@tanstack/react-router"
import { Plus } from "lucide-react"
import { DeviceTable } from "@/components/devices/device-table"
import { Button } from "@/components/ui/button"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"

export const Route = createFileRoute("/_app/devices/")({
  component: DevicesPage,
})

function DevicesPage() {
  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Workspace"
        title="Devices"
        description="Manage your phones, softphones, and other SIP devices."
        actions={
          <Button size="sm" asChild>
            <Link to="/devices/new">
              <Plus className="mr-2 h-4 w-4" /> Add device
            </Link>
          </Button>
        }
      />
      <PageSection>
        <DeviceTable />
      </PageSection>
    </PageContainer>
  )
}
