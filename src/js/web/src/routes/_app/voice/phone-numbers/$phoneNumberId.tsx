import { createFileRoute, Link, useNavigate } from "@tanstack/react-router"
import { AlertCircle, ArrowLeft, Fingerprint, Home, Pencil, Phone, Shield, Trash2 } from "lucide-react"
import { useEffect, useState } from "react"
import { EntityActivityPanel } from "@/components/shared/entity-activity-panel"
import { ExternalDataTab } from "@/components/gateway/external-data-tab"
import { E911StatusBadge } from "@/components/voice/e911-status-badge"
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
import { EmptyState } from "@/components/ui/empty-state"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Skeleton } from "@/components/ui/skeleton"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { formatDateTime, formatRelativeTimeShort } from "@/lib/date-utils"
import { usePhoneNumber } from "@/lib/api/hooks/voice"
import { useGatewayLookupNumber } from "@/lib/api/hooks/gateway"
import { formatPhoneNumber } from "@/lib/format-utils"

type PhoneNumberDetailSearch = {
  tab?: string
  edit?: boolean
}

export const Route = createFileRoute("/_app/voice/phone-numbers/$phoneNumberId")({
  component: PhoneNumberDetailPage,
  validateSearch: (search: Record<string, unknown>): PhoneNumberDetailSearch => ({
    tab: (search.tab as string) || undefined,
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
  const { tab = "details", edit } = Route.useSearch()
  const navigate = useNavigate()

  const { data, isLoading, isError, refetch } = usePhoneNumber(phoneNumberId)
  useDocumentTitle(data ? formatPhoneNumber(data.number) : "Phone Number Details")
  const gatewayQuery = useGatewayLookupNumber(data?.number ?? "", tab === "external")
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
          <EmptyState
            icon={AlertCircle}
            title="Unable to load phone number"
            description="The phone number may have been deleted."
            action={<Button variant="outline" size="sm" onClick={() => refetch()}>Try again</Button>}
          />
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
        <Tabs value={tab} onValueChange={(value) => navigate({ to: "/voice/phone-numbers/$phoneNumberId", params: { phoneNumberId }, search: { tab: value }, replace: true })}>
          <TabsList>
            <TabsTrigger value="details">Details</TabsTrigger>
            <TabsTrigger value="external">External Data</TabsTrigger>
            <TabsTrigger value="activity">Activity</TabsTrigger>
          </TabsList>

          <TabsContent value="details" className="mt-6 space-y-6">
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
                  <div>
                    <p className="text-muted-foreground">E911 Status</p>
                    <div className="flex items-center gap-2 pt-0.5">
                      <E911StatusBadge registered={data.e911Registered ?? false} registrationId={data.e911RegistrationId} />
                      {data.e911Registered && data.e911RegistrationId && (
                        <Link
                          to="/e911/$registrationId"
                          params={{ registrationId: data.e911RegistrationId }}
                          className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
                        >
                          <Shield className="h-3 w-3" />
                          View Registration
                        </Link>
                      )}
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

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
          </TabsContent>

          <TabsContent value="external" className="mt-6">
            <ExternalDataTab
              hasIdentifier={!!data.number}
              noIdentifierMessage="This phone number record has no number value. Cannot look up external data."
              sources={gatewayQuery.data?.sources}
              isLoading={gatewayQuery.isLoading}
              isRefetching={gatewayQuery.isRefetching}
              isError={gatewayQuery.isError}
              onRefresh={() => gatewayQuery.refetch()}
            />
          </TabsContent>

          <TabsContent value="activity" className="mt-6 space-y-6">
            <EntityActivityPanel
              targetType="phone_number"
              targetId={phoneNumberId}
              enabled={tab === "activity"}
            />
          </TabsContent>
        </Tabs>
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
