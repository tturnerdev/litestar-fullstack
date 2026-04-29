import { createFileRoute } from "@tanstack/react-router"
import { Plus } from "lucide-react"
import { Button } from "@/components/ui/button"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { CreateExtensionDialog } from "@/components/voice/create-extension-dialog"
import { ExtensionTable } from "@/components/voice/extension-table"

export const Route = createFileRoute("/_app/voice/extensions/")({
  component: ExtensionsPage,
})

function ExtensionsPage() {
  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Voice"
        title="Extensions"
        description="View and manage your extensions."
        actions={
          <CreateExtensionDialog
            trigger={
              <Button size="sm">
                <Plus className="mr-2 h-4 w-4" />
                Add Extension
              </Button>
            }
          />
        }
      />
      <PageSection>
        <ExtensionTable />
      </PageSection>
    </PageContainer>
  )
}
