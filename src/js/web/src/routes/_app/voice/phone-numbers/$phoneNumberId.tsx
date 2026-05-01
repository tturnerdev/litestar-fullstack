import { createFileRoute, Link, useNavigate } from "@tanstack/react-router"
import { ArrowLeft, Fingerprint, Home, Pencil, Phone, Trash2 } from "lucide-react"
import { useEffect, useState } from "react"
import { PhoneNumberDeleteDialog } from "@/components/voice/phone-number-delete-dialog"
import { PhoneNumberEditSheet } from "@/components/voice/phone-number-edit-sheet"
import { Badge } from "@/components/ui/badge"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { CopyButton } from "@/components/ui/copy-button"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Skeleton } from "@/components/ui/skeleton"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"
import { usePhoneNumber } from "@/lib/api/hooks/voice"
import { formatPhoneNumber } from "@/lib/format-utils"

type PhoneNumberDetailSearch = {
  edit?: boolean
}

export const Route = createFileRoute("/_app/voice/phone-numbers/$phoneNumberId")({
  component: PhoneNumberDetailPage,
  validateSearch: (search: Record<string, unknown>): PhoneNumberDetailSearch => ({
    edit: search.edit === true || search.edit === "true" || undefined,
  }),
})

const numberTypeLabel: Record<string, string> = {
  local: "Local",
  toll_free: "Toll-Free",
  international: "International",
}

const numberTypeBadgeVariant: Record<string, "default" | "secondary" | "outline"> = {
  local: "secondary",
  toll_free: "default",
  international: "outline",
}

function PhoneNumberDetailPage() {
  const { phoneNumberId } = Route.useParams()
  const { edit } = Route.useSearch()
  const navigate = useNavigate()

  const { data, isLoading, isError } = usePhoneNumber(phoneNumberId)
  useDocumentTitle(data ? formatPhoneNumber(data.number) : "Phone Number Details")
  const [editOpen, setEditOpen] = useState(false)
  const [deleteOpen, setDeleteOpen] = useState(false)

  useEffect(() => {
    if (edit && data && !editOpen) {
      setEditOpen(true)
      navigate({
        to: "/voice/phone-numbers/$phoneNumberId",
        params: { phoneNumberId },
        search: {},
        replace: true,
      })
    }
  }, [edit, data])

  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <div className="space-y-2">
          <Skeleton className="h-4 w-36" />
          <Skeleton className="h-8 w-48" />
        </div>
        <PageSection>
          <div className="rounded-xl border border-border/60 bg-card/80 p-6 space-y-4">
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {Array.from({ length: 6 }).map((_, i) => (
                <div key={i} className="space-y-1.5">
                  <Skeleton className="h-3.5 w-24" />
                  <Skeleton className="h-5 w-36" />
                </div>
              ))}
            </div>
          </div>
        </PageSection>
      </PageContainer>
    )
  }

  if (isError || !data) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader
          eyebrow="Voice"
          title="Phone Number Details"
          actions={
            <Button variant="outline" size="sm" asChild>
              <Link to="/voice/phone-numbers">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back to phone numbers
              </Link>
            </Button>
          }
        />
        <PageSection>
          <Card>
            <CardHeader>
              <CardTitle>Phone Number</CardTitle>
            </CardHeader>
            <CardContent className="text-muted-foreground">
              We could not load this phone number. It may have been deleted.
            </CardContent>
          </Card>
        </PageSection>
      </PageContainer>
    )
  }

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Voice"
        title={formatPhoneNumber(data.number)}
        description={data.label ?? undefined}
        breadcrumbs={
          <Breadcrumb>
            <BreadcrumbList>
              <BreadcrumbItem>
                <BreadcrumbLink asChild>
                  <Link to="/home"><Home className="h-4 w-4" /></Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbLink asChild>
                  <Link to="/voice">Voice</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbLink asChild>
                  <Link to="/voice/phone-numbers">Phone Numbers</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbPage>{data.label ?? data.number}</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
        actions={
          <div className="flex items-center gap-3">
            <Badge variant={data.isActive ? "default" : "secondary"}>
              {data.isActive ? "Active" : "Inactive"}
            </Badge>
            <Button variant="outline" size="sm" onClick={() => setEditOpen(true)}>
              <Pencil className="mr-2 h-4 w-4" /> Edit
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="text-destructive hover:bg-destructive/10"
              onClick={() => setDeleteOpen(true)}
            >
              <Trash2 className="mr-2 h-4 w-4" /> Delete
            </Button>
            <Button variant="outline" size="sm" asChild>
              <Link to="/voice/phone-numbers">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back
              </Link>
            </Button>
          </div>
        }
      />

      <PageSection>
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Phone className="h-5 w-5 text-muted-foreground" />
              <CardTitle>Number Info</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-3">
              <div>
                <p className="text-muted-foreground">Number</p>
                <p className="font-mono text-base font-medium">{formatPhoneNumber(data.number)}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Label</p>
                <p className="font-medium">{data.label ?? "---"}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Type</p>
                <Badge variant={numberTypeBadgeVariant[data.numberType] ?? "outline"}>
                  {numberTypeLabel[data.numberType] ?? data.numberType}
                </Badge>
              </div>
              <div>
                <p className="text-muted-foreground">Caller ID Name</p>
                <p className="font-medium">{data.callerIdName ?? "---"}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Status</p>
                <Badge variant={data.isActive ? "default" : "secondary"}>
                  {data.isActive ? "Active" : "Inactive"}
                </Badge>
              </div>
              <div>
                <p className="text-muted-foreground">Team</p>
                <p>{data.teamId ?? "Not assigned"}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </PageSection>

      <PageSection delay={0.1}>
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Fingerprint className="h-5 w-5 text-muted-foreground" />
              <CardTitle>Metadata</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-4">
              <div>
                <p className="text-muted-foreground">ID</p>
                <div className="flex items-center gap-1">
                  <p className="font-mono text-xs">{phoneNumberId}</p>
                  <CopyButton value={phoneNumberId} label="phone number ID" />
                </div>
              </div>
              <div>
                <p className="text-muted-foreground">Created</p>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <p className="cursor-default">{data.createdAt ? formatRelativeTimeShort(data.createdAt) : "---"}</p>
                  </TooltipTrigger>
                  <TooltipContent>{data.createdAt ? formatDateTime(data.createdAt) : "Unknown"}</TooltipContent>
                </Tooltip>
              </div>
              <div>
                <p className="text-muted-foreground">Updated</p>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <p className="cursor-default">{data.updatedAt ? formatRelativeTimeShort(data.updatedAt) : "---"}</p>
                  </TooltipTrigger>
                  <TooltipContent>{data.updatedAt ? formatDateTime(data.updatedAt) : "Unknown"}</TooltipContent>
                </Tooltip>
              </div>
              <div>
                <p className="text-muted-foreground">Extension</p>
                <p>{data.extensionId ?? "None"}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </PageSection>

      <PhoneNumberEditSheet phoneNumber={data} open={editOpen} onOpenChange={setEditOpen} />

      <PhoneNumberDeleteDialog
        phoneNumberId={data.id}
        phoneNumber={formatPhoneNumber(data.number)}
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        onDeleted={() => navigate({ to: "/voice/phone-numbers" })}
      />
    </PageContainer>
  )
}
