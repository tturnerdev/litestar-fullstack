import { createFileRoute, Link } from "@tanstack/react-router"
import { ArrowLeft } from "lucide-react"
import { SendFaxForm } from "@/components/fax/send-fax-form"
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { useDocumentTitle } from "@/hooks/use-document-title"

export const Route = createFileRoute("/_app/fax/send")({
  component: SendFaxPage,
})

function SendFaxPage() {
  useDocumentTitle("Send Fax")
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
        <SendFaxForm />
      </PageSection>
    </PageContainer>
  )
}
