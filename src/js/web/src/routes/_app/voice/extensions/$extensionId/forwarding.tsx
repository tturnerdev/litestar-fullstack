import { createFileRoute, Link } from "@tanstack/react-router"
import { ArrowLeft } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { ForwardingRuleEditor } from "@/components/voice/forwarding-rule-editor"
import { useForwardingRules } from "@/lib/api/hooks/voice"

export const Route = createFileRoute("/_app/voice/extensions/$extensionId/forwarding")({
  component: ForwardingPage,
})

function ForwardingPage() {
  const { extensionId } = Route.useParams()
  const { data } = useForwardingRules(extensionId)

  const ruleCount = data?.items?.length ?? 0
  const activeCount = data?.items?.filter((r) => r.isActive).length ?? 0

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Voice"
        title="Call Forwarding"
        description="Configure how calls are routed when you are unavailable."
        actions={
          <div className="flex items-center gap-2">
            {ruleCount > 0 && (
              <Badge variant="secondary">
                {activeCount} of {ruleCount} rules active
              </Badge>
            )}
            <Button variant="outline" size="sm" asChild>
              <Link to="/voice/extensions/$extensionId" params={{ extensionId }}>
                <ArrowLeft className="mr-2 h-4 w-4" /> Back to Extension
              </Link>
            </Button>
          </div>
        }
      />
      <PageSection>
        <ForwardingRuleEditor extensionId={extensionId} />
      </PageSection>
    </PageContainer>
  )
}
