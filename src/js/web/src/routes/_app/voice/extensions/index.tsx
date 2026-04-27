import { createFileRoute } from "@tanstack/react-router"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { ExtensionTable } from "@/components/voice/extension-table"

export const Route = createFileRoute("/_app/voice/extensions/")({
  component: ExtensionsPage,
})

function ExtensionsPage() {
  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader eyebrow="Voice" title="Extensions" description="View and manage your extensions." />
      <PageSection>
        <ExtensionTable />
      </PageSection>
    </PageContainer>
  )
}
