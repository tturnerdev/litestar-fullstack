import { createFileRoute, Link, useBlocker, useNavigate } from "@tanstack/react-router"
import {
  AlertCircle,
  AlertTriangle,
  ArrowLeft,
  ChevronRight,
  Copy,
  Fingerprint,
  Home,
  Link2,
  Loader2,
  MoreHorizontal,
  Pencil,
  Phone,
  PhoneForwarded,
  Shield,
  Trash2,
  Users,
} from "lucide-react"
import { useEffect, useState } from "react"
import { toast } from "sonner"
import { ExternalDataTab } from "@/components/gateway/external-data-tab"
import { EntityActivityPanel } from "@/components/shared/entity-activity-panel"
import { Badge } from "@/components/ui/badge"
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { CopyButton } from "@/components/ui/copy-button"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { Skeleton } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { E911StatusBadge } from "@/components/voice/e911-status-badge"
import { PhoneNumberDeleteDialog } from "@/components/voice/phone-number-delete-dialog"
import { PhoneNumberEditSheet } from "@/components/voice/phone-number-edit-sheet"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { useGatewayLookupNumber } from "@/lib/api/hooks/gateway"
import { useTeam } from "@/lib/api/hooks/teams"
import { useExtensionsByPhoneNumber, usePhoneNumber, useUpdatePhoneNumber } from "@/lib/api/hooks/voice"
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
  const updatePhoneNumber = useUpdatePhoneNumber(phoneNumberId)
  const gatewayQuery = useGatewayLookupNumber(data?.number ?? "", tab === "external")
  const extensionsQuery = useExtensionsByPhoneNumber(phoneNumberId)
  const teamQuery = useTeam(data?.teamId ?? "")
  const [editOpen, setEditOpen] = useState(false)
  const [deleteOpen, setDeleteOpen] = useState(false)

  // Inline editing state
  const [editing, setEditing] = useState(false)
  const [editLabel, setEditLabel] = useState("")
  const [editCallerIdName, setEditCallerIdName] = useState("")

  useBlocker({
    shouldBlockFn: () => editing,
    withResolver: true,
  })

  function startEditing() {
    if (!data) return
    setEditLabel(data.label ?? "")
    setEditCallerIdName(data.callerIdName ?? "")
    setEditing(true)
  }

  function cancelEditing() {
    setEditing(false)
  }

  function handleSave() {
    if (!data) return
    const payload: Record<string, unknown> = {}
    if (editLabel !== (data.label ?? "")) payload.label = editLabel || null
    if (editCallerIdName !== (data.callerIdName ?? "")) payload.callerIdName = editCallerIdName || null
    if (Object.keys(payload).length === 0) {
      setEditing(false)
      return
    }
    updatePhoneNumber.mutate(payload, {
      onSuccess: () => setEditing(false),
    })
  }

  function handleToggleActive() {
    if (!data) return
    updatePhoneNumber.mutate({ isActive: !data.isActive })
  }

  // biome-ignore lint/correctness/useExhaustiveDependencies: startEditing is a stable form-populating function defined above
  useEffect(() => {
    if (edit && data && !editOpen && !editing) {
      startEditing()
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
                // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
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
            action={
              <Button variant="outline" size="sm" onClick={() => refetch()}>
                Try again
              </Button>
            }
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
                  <Link to="/home">
                    <Home className="h-4 w-4" />
                  </Link>
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
            <Badge variant={data.isActive ? "default" : "secondary"}>{data.isActive ? "Active" : "Inactive"}</Badge>
            {!editing && (
              <Button variant="outline" size="sm" onClick={startEditing}>
                <Pencil className="mr-2 h-4 w-4" /> Edit
              </Button>
            )}
            <Button variant="outline" size="sm" className="text-destructive hover:bg-destructive/10" onClick={() => setDeleteOpen(true)}>
              <Trash2 className="mr-2 h-4 w-4" /> Delete
            </Button>
            <Button variant="outline" size="sm" asChild>
              <Link to="/voice/phone-numbers">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back
              </Link>
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm">
                  <MoreHorizontal className="h-4 w-4" />
                  <span className="sr-only">Actions</span>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem
                  onClick={() => {
                    navigator.clipboard.writeText(phoneNumberId)
                    toast.success("Phone number ID copied to clipboard")
                  }}
                >
                  <Copy className="mr-2 h-4 w-4" />
                  Copy Phone Number ID
                </DropdownMenuItem>
                <DropdownMenuItem
                  onClick={() => {
                    navigator.clipboard.writeText(data.number)
                    toast.success("Phone number copied to clipboard")
                  }}
                >
                  <Copy className="mr-2 h-4 w-4" />
                  Copy Number
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem className="text-destructive focus:text-destructive" onClick={() => setDeleteOpen(true)}>
                  <Trash2 className="mr-2 h-4 w-4" />
                  Delete
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
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
            <SectionErrorBoundary name="Number Info">
              <Card>
                <CardHeader className="flex flex-row items-center justify-between">
                  <CardTitle className="flex items-center gap-2">
                    <Phone className="h-5 w-5 text-muted-foreground" />
                    Number Info
                  </CardTitle>
                  {editing && (
                    <div className="flex gap-2">
                      <Button variant="ghost" size="sm" onClick={cancelEditing}>
                        Cancel
                      </Button>
                      <Button size="sm" onClick={handleSave} disabled={updatePhoneNumber.isPending}>
                        {updatePhoneNumber.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                        Save
                      </Button>
                    </div>
                  )}
                </CardHeader>
                <CardContent>
                  {editing ? (
                    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                      <div>
                        <p className="text-muted-foreground text-sm">Number</p>
                        <div className="flex items-center gap-1">
                          <p className="font-mono text-base font-medium">{formatPhoneNumber(data.number)}</p>
                          <CopyButton value={data.number} label="phone number" />
                        </div>
                      </div>
                      <div className="space-y-2">
                        <Label>Label</Label>
                        <Input value={editLabel} onChange={(e) => setEditLabel(e.target.value)} placeholder="e.g. Main Line" />
                      </div>
                      <div>
                        <p className="text-muted-foreground text-sm">Type</p>
                        <Badge variant={numberTypeBadgeVariant[data.numberType] ?? "outline"}>{numberTypeLabel[data.numberType] ?? data.numberType}</Badge>
                      </div>
                      <div className="space-y-2">
                        <Label>Caller ID Name</Label>
                        <Input value={editCallerIdName} onChange={(e) => setEditCallerIdName(e.target.value)} placeholder="e.g. Acme Corp" />
                      </div>
                      <div>
                        <p className="text-muted-foreground text-sm">Status</p>
                        <div className="flex items-center gap-2 pt-1">
                          <Switch checked={data.isActive} onCheckedChange={handleToggleActive} disabled={updatePhoneNumber.isPending} aria-label="Toggle active status" />
                          <span className="text-sm">{data.isActive ? "Active" : "Inactive"}</span>
                        </div>
                      </div>
                      <div>
                        <p className="text-muted-foreground text-sm">Team</p>
                        {data.teamId ? (
                          <div className="flex items-center gap-1">
                            <Link to="/teams/$teamId" params={{ teamId: data.teamId }} className="text-primary hover:underline">
                              {data.teamId.slice(0, 8)}...
                            </Link>
                            <CopyButton value={data.teamId} label="team ID" />
                          </div>
                        ) : (
                          <p className="text-sm">Not assigned</p>
                        )}
                      </div>
                      <div>
                        <p className="text-muted-foreground text-sm">E911 Status</p>
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
                  ) : (
                    <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-3">
                      <div>
                        <p className="text-muted-foreground">Number</p>
                        <div className="flex items-center gap-1">
                          <p className="font-mono text-base font-medium">{formatPhoneNumber(data.number)}</p>
                          <CopyButton value={data.number} label="phone number" />
                        </div>
                      </div>
                      <div>
                        <p className="text-muted-foreground">Label</p>
                        <p className="font-medium">{data.label ?? "---"}</p>
                      </div>
                      <div>
                        <p className="text-muted-foreground">Type</p>
                        <Badge variant={numberTypeBadgeVariant[data.numberType] ?? "outline"}>{numberTypeLabel[data.numberType] ?? data.numberType}</Badge>
                      </div>
                      <div>
                        <p className="text-muted-foreground">Caller ID Name</p>
                        <p className="font-medium">{data.callerIdName ?? "---"}</p>
                      </div>
                      <div>
                        <p className="text-muted-foreground">Status</p>
                        <div className="flex items-center gap-2">
                          <Badge variant={data.isActive ? "default" : "secondary"}>{data.isActive ? "Active" : "Inactive"}</Badge>
                          <Switch checked={data.isActive} onCheckedChange={handleToggleActive} disabled={updatePhoneNumber.isPending} aria-label="Toggle active status" />
                        </div>
                      </div>
                      <div>
                        <p className="text-muted-foreground">Team</p>
                        {data.teamId ? (
                          <div className="flex items-center gap-1">
                            <Link to="/teams/$teamId" params={{ teamId: data.teamId }} className="text-primary hover:underline">
                              {data.teamId.slice(0, 8)}...
                            </Link>
                            <CopyButton value={data.teamId} label="team ID" />
                          </div>
                        ) : (
                          <p>Not assigned</p>
                        )}
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
                  )}
                </CardContent>
              </Card>
            </SectionErrorBoundary>

            <SectionErrorBoundary name="Metadata">
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
                      <p className="text-muted-foreground">E911 Registered</p>
                      <p>{data.e911Registered ? "Yes" : "No"}</p>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Team</p>
                      {data.teamId ? (
                        <div className="flex items-center gap-1">
                          <Link to="/teams/$teamId" params={{ teamId: data.teamId }} className="font-mono text-xs text-primary hover:underline">
                            {data.teamId.slice(0, 8)}...
                          </Link>
                          <CopyButton value={data.teamId} label="team ID" />
                        </div>
                      ) : (
                        <p className="font-mono text-xs">None</p>
                      )}
                    </div>
                    {data.e911RegistrationId && (
                      <div>
                        <p className="text-muted-foreground">E911 Registration ID</p>
                        <div className="flex items-center gap-1">
                          <p className="font-mono text-xs">{data.e911RegistrationId}</p>
                          <CopyButton value={data.e911RegistrationId} label="E911 registration ID" />
                        </div>
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            </SectionErrorBoundary>

            <SectionErrorBoundary name="Related Extensions">
              <Card>
                <CardHeader>
                  <div className="flex items-center gap-2">
                    <PhoneForwarded className="h-5 w-5 text-muted-foreground" />
                    <CardTitle>Related Extensions</CardTitle>
                  </div>
                </CardHeader>
                <CardContent>
                  {extensionsQuery.isLoading ? (
                    <div className="flex items-center justify-center py-6 text-muted-foreground">
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Loading extensions...
                    </div>
                  ) : extensionsQuery.isError ? (
                    <p className="py-4 text-center text-sm text-muted-foreground">Unable to load related extensions.</p>
                  ) : extensionsQuery.data && extensionsQuery.data.length > 0 ? (
                    <Table aria-label="Related extensions">
                      <TableHeader>
                        <TableRow>
                          <TableHead>Extension</TableHead>
                          <TableHead>Display Name</TableHead>
                          <TableHead>Status</TableHead>
                          <TableHead className="w-[1%]" />
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {extensionsQuery.data.map((ext) => (
                          <TableRow key={ext.id}>
                            <TableCell className="font-mono font-medium">{ext.extensionNumber}</TableCell>
                            <TableCell>{ext.displayName}</TableCell>
                            <TableCell>
                              <Badge variant={ext.isActive ? "default" : "secondary"}>{ext.isActive ? "Active" : "Inactive"}</Badge>
                            </TableCell>
                            <TableCell>
                              <Link to="/voice/extensions/$extensionId" params={{ extensionId: ext.id }} className="text-sm text-primary hover:underline whitespace-nowrap">
                                View details
                              </Link>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  ) : (
                    <p className="py-4 text-center text-sm text-muted-foreground">No extensions are currently assigned to this phone number.</p>
                  )}
                </CardContent>
              </Card>
            </SectionErrorBoundary>

            <SectionErrorBoundary name="Related Resources">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Link2 className="h-5 w-5 text-muted-foreground" />
                    Related Resources
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                    {/* Extension */}
                    {extensionsQuery.data && extensionsQuery.data.length > 0 ? (
                      <Link
                        to="/voice/extensions/$extensionId"
                        params={{ extensionId: extensionsQuery.data[0].id }}
                        className="group flex items-center gap-3 rounded-lg border border-border/60 px-4 py-3 transition-colors hover:bg-muted/50 hover:border-primary/30"
                      >
                        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-violet-500/10 text-violet-600 dark:text-violet-400">
                          <PhoneForwarded className="h-4.5 w-4.5" />
                        </div>
                        <div className="min-w-0 flex-1">
                          <p className="text-xs text-muted-foreground">Extension</p>
                          <p className="truncate text-sm font-medium group-hover:text-primary">{extensionsQuery.data[0].displayName ?? extensionsQuery.data[0].extensionNumber}</p>
                        </div>
                        <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground/50 transition-transform group-hover:translate-x-0.5 group-hover:text-primary" />
                      </Link>
                    ) : (
                      <div className="flex items-center gap-3 rounded-lg border border-dashed border-border/60 px-4 py-3">
                        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-muted text-muted-foreground/50">
                          <PhoneForwarded className="h-4.5 w-4.5" />
                        </div>
                        <div className="min-w-0 flex-1">
                          <p className="text-xs text-muted-foreground">Extension</p>
                          <p className="text-sm text-muted-foreground">Not assigned</p>
                        </div>
                      </div>
                    )}

                    {/* Team */}
                    {data.teamId ? (
                      <Link
                        to="/teams/$teamId"
                        params={{ teamId: data.teamId }}
                        className="group flex items-center gap-3 rounded-lg border border-border/60 px-4 py-3 transition-colors hover:bg-muted/50 hover:border-primary/30"
                      >
                        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-blue-500/10 text-blue-600 dark:text-blue-400">
                          <Users className="h-4.5 w-4.5" />
                        </div>
                        <div className="min-w-0 flex-1">
                          <p className="text-xs text-muted-foreground">Team</p>
                          <p className="truncate text-sm font-medium group-hover:text-primary">{teamQuery.data?.name ?? "Loading..."}</p>
                        </div>
                        <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground/50 transition-transform group-hover:translate-x-0.5 group-hover:text-primary" />
                      </Link>
                    ) : (
                      <div className="flex items-center gap-3 rounded-lg border border-dashed border-border/60 px-4 py-3">
                        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-muted text-muted-foreground/50">
                          <Users className="h-4.5 w-4.5" />
                        </div>
                        <div className="min-w-0 flex-1">
                          <p className="text-xs text-muted-foreground">Team</p>
                          <p className="text-sm text-muted-foreground">Not assigned</p>
                        </div>
                      </div>
                    )}

                    {/* E911 Registration */}
                    {data.e911Registered && data.e911RegistrationId ? (
                      <Link
                        to="/e911/$registrationId"
                        params={{ registrationId: data.e911RegistrationId }}
                        className="group flex items-center gap-3 rounded-lg border border-border/60 px-4 py-3 transition-colors hover:bg-muted/50 hover:border-primary/30"
                      >
                        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-amber-500/10 text-amber-600 dark:text-amber-400">
                          <Shield className="h-4.5 w-4.5" />
                        </div>
                        <div className="min-w-0 flex-1">
                          <p className="text-xs text-muted-foreground">E911 Registration</p>
                          <p className="truncate text-sm font-medium group-hover:text-primary">{data.e911RegistrationId.slice(0, 8)}...</p>
                        </div>
                        <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground/50 transition-transform group-hover:translate-x-0.5 group-hover:text-primary" />
                      </Link>
                    ) : (
                      <div className="flex items-center gap-3 rounded-lg border border-dashed border-border/60 px-4 py-3">
                        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-muted text-muted-foreground/50">
                          <Shield className="h-4.5 w-4.5" />
                        </div>
                        <div className="min-w-0 flex-1">
                          <p className="text-xs text-muted-foreground">E911 Registration</p>
                          <p className="text-sm text-muted-foreground">Not registered</p>
                        </div>
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            </SectionErrorBoundary>
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
            <EntityActivityPanel targetType="phone_number" targetId={phoneNumberId} enabled={tab === "activity"} />
          </TabsContent>
        </Tabs>
      </PageSection>

      {/* Danger Zone */}
      <PageSection delay={0.3}>
        <SectionErrorBoundary name="Danger Zone">
          <Card className="border-destructive/30">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-destructive">
                <AlertTriangle className="h-4 w-4" />
                Danger Zone
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium text-sm">Delete this phone number</p>
                  <p className="text-sm text-muted-foreground">This action cannot be undone. Any associated extensions and forwarding rules will also be removed.</p>
                </div>
                <Button variant="destructive" size="sm" onClick={() => setDeleteOpen(true)}>
                  <Trash2 className="mr-2 h-4 w-4" /> Delete
                </Button>
              </div>
            </CardContent>
          </Card>
        </SectionErrorBoundary>
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
