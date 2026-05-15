import { createFileRoute, Link } from "@tanstack/react-router"
import { ArrowLeft, ShieldAlert } from "lucide-react"
import { SendFaxForm } from "@/components/fax/send-fax-form"
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { usePermissions } from "@/hooks/use-permissions"

export const Route = createFileRoute("/_app/fax/send")({
  component: SendFaxPage,
})

function SendFaxPage() {
  useDocumentTitle("Send Fax")
  const { canEdit } = usePermissions()
  if (!canEdit("FAX_MESSAGES")) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader eyebrow="Communications" title="Send Fax" />
        <PageSection>
          <div className="flex flex-col items-center justify-center py-16 text-center">
            <ShieldAlert className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-semibold">Permission Denied</h3>
            <p className="text-sm text-muted-foreground mt-1">You don't have permission to perform this action. Contact your team administrator.</p>
          </div>
        </PageSection>
      </PageContainer>
    )
  }
  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Communications"
        title="Send Fax"
        description="Upload a PDF document and send it via fax."
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
                  <Link to="/fax">Fax</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbPage>Send Fax</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
        actions={
          <Button variant="outline" size="sm" asChild>
            <Link to="/fax">
              <ArrowLeft className="mr-2 h-4 w-4" /> Back to fax
            </Link>
          </Button>
        }
      />
      <PageSection>
        <SectionErrorBoundary name="Send Fax">
          <SendFaxForm />
        </SectionErrorBoundary>
      </PageSection>
    </PageContainer>
  )
}
