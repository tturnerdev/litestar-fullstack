import { createFileRoute, Link, useRouter } from "@tanstack/react-router"
import { useState } from "react"
import {
  AlertCircle,
  AlertTriangle,
  ArrowLeft,
  Loader2,
  Pencil,
  Plus,
  Trash2,
  Users,
} from "lucide-react"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Badge } from "@/components/ui/badge"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { Button, buttonVariants } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { EmptyState } from "@/components/ui/empty-state"
import { CopyButton } from "@/components/ui/copy-button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import {
  useRingGroup,
  useUpdateRingGroup,
  useDeleteRingGroup,
  useCreateRingGroupMember,
  useDeleteRingGroupMember,
  type RingGroup,
  type RingGroupMember,
} from "@/lib/api/hooks/call-routing"
import { EntityActivityPanel } from "@/components/shared/entity-activity-panel"
import { useDocumentTitle } from "@/hooks/use-document-title"

export const Route = createFileRoute("/_app/call-routing/ring-groups/$ringGroupId")({
  component: RingGroupDetailPage,
})

// -- Constants ----------------------------------------------------------------

const strategyLabels: Record<string, string> = {
  ring_all: "Ring All",
  round_robin: "Round Robin",
  linear: "Linear",
  random: "Random",
}

// -- Delete Dialog ------------------------------------------------------------

function DeleteDialog({ name, onDelete, isPending }: { name: string; onDelete: () => void; isPending: boolean }) {
  const [open, setOpen] = useState(false)
  return (
    <>
      <Button variant="destructive" size="sm" onClick={() => setOpen(true)}>
        <Trash2 className="mr-2 h-4 w-4" /> Delete
      </Button>
      <AlertDialog open={open} onOpenChange={setOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-destructive" /> Delete "{name}"?
            </AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete this ring group and all its member assignments. This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={isPending}>Cancel</AlertDialogCancel>
            <AlertDialogAction className={buttonVariants({ variant: "destructive" })} onClick={onDelete} disabled={isPending}>
              {isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {isPending ? "Deleting..." : "Delete"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

// -- Add Member Inline --------------------------------------------------------

function AddMemberRow({ groupId }: { groupId: string }) {
  const createMember = useCreateRingGroupMember(groupId)
  const [adding, setAdding] = useState(false)
  const [memberType, setMemberType] = useState<"extension" | "external">("extension")
  const [extensionId, setExtensionId] = useState("")
  const [externalNumber, setExternalNumber] = useState("")
  const [sortOrder, setSortOrder] = useState(0)

  const handleSave = () => {
    const payload: Record<string, unknown> = { sortOrder }
    if (memberType === "extension") {
      if (!extensionId.trim()) return
      payload.extensionId = extensionId.trim()
    } else {
      if (!externalNumber.trim()) return
      payload.externalNumber = externalNumber.trim()
    }
    createMember.mutate(payload as Parameters<typeof createMember.mutate>[0], {
      onSuccess: () => {
        setAdding(false)
        setExtensionId("")
        setExternalNumber("")
        setSortOrder(0)
      },
    })
  }

  if (!adding) {
    return (
      <Button variant="outline" size="sm" onClick={() => setAdding(true)}>
        <Plus className="mr-2 h-4 w-4" /> Add member
      </Button>
    )
  }

  return (
    <div className="space-y-3 rounded-lg border border-border/60 bg-muted/20 p-4">
      <div className="space-y-2">
        <Label>Member Type</Label>
        <Select value={memberType} onValueChange={(v) => setMemberType(v as "extension" | "external")}>
          <SelectTrigger><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="extension">Extension</SelectItem>
            <SelectItem value="external">External Number</SelectItem>
          </SelectContent>
        </Select>
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        {memberType === "extension" ? (
          <div className="space-y-2">
            <Label>Extension ID</Label>
            <Input placeholder="Extension UUID" value={extensionId} onChange={(e) => setExtensionId(e.target.value)} />
          </div>
        ) : (
          <div className="space-y-2">
            <Label>External Number</Label>
            <Input placeholder="e.g., +15551234567" value={externalNumber} onChange={(e) => setExternalNumber(e.target.value)} />
          </div>
        )}
        <div className="space-y-2">
          <Label>Sort Order</Label>
          <Input type="number" value={sortOrder} onChange={(e) => setSortOrder(Number(e.target.value))} min={0} />
        </div>
      </div>
      <div className="flex items-center gap-2">
        <Button size="sm" onClick={handleSave} disabled={createMember.isPending || (memberType === "extension" ? !extensionId.trim() : !externalNumber.trim())}>
          {createMember.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
          Add
        </Button>
        <Button variant="ghost" size="sm" onClick={() => setAdding(false)}>Cancel</Button>
      </div>
    </div>
  )
}

// -- Member Row ---------------------------------------------------------------

function MemberRow({ member, groupId }: { member: RingGroupMember; groupId: string }) {
  const deleteMember = useDeleteRingGroupMember(groupId)

  const displayValue = member.extensionId
    ? member.extensionId.slice(0, 8) + "..."
    : member.externalNumber ?? "---"
  const memberType = member.extensionId ? "Extension" : "External"

  return (
    <TableRow>
      <TableCell><span className="text-sm">{member.sortOrder}</span></TableCell>
      <TableCell>
        <Badge variant="outline" className="text-xs">{memberType}</Badge>
      </TableCell>
      <TableCell>
        <span className={member.extensionId ? "font-mono text-xs" : "text-sm"}>{displayValue}</span>
      </TableCell>
      <TableCell className="text-right">
        <Button
          variant="ghost"
          size="sm"
          className="h-7 w-7 p-0 text-muted-foreground hover:text-destructive"
          onClick={() => deleteMember.mutate(member.id)}
          disabled={deleteMember.isPending}
        >
          {deleteMember.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
        </Button>
      </TableCell>
    </TableRow>
  )
}

// -- Info Field ---------------------------------------------------------------

function InfoField({ label, value }: { label: string; value?: string | number | null }) {
  return (
    <div>
      <p className="text-muted-foreground">{label}</p>
      <p>{value ?? "---"}</p>
    </div>
  )
}

// -- Main page ----------------------------------------------------------------

function RingGroupDetailPage() {
  const { ringGroupId } = Route.useParams()
  const router = useRouter()

  const { data, isLoading, isError, refetch } = useRingGroup(ringGroupId)
  const updateMutation = useUpdateRingGroup(ringGroupId)
  const deleteMutation = useDeleteRingGroup()

  const [editing, setEditing] = useState(false)
  const [editName, setEditName] = useState("")
  const [editNumber, setEditNumber] = useState("")
  const [editStrategy, setEditStrategy] = useState("ring_all")
  const [editRingTime, setEditRingTime] = useState(20)
  const [editNoAnswerDest, setEditNoAnswerDest] = useState("")

  useDocumentTitle(data ? `${data.name} - Ring Groups` : "Ring Group Detail")

  function startEditing(rg: RingGroup) {
    setEditName(rg.name)
    setEditNumber(rg.number)
    setEditStrategy(rg.strategy)
    setEditRingTime(rg.ringTime)
    setEditNoAnswerDest(rg.noAnswerDestination ?? "")
    setEditing(true)
  }

  function handleSave() {
    const payload: Record<string, unknown> = {}
    if (editName !== data?.name) payload.name = editName
    if (editNumber !== data?.number) payload.number = editNumber
    if (editStrategy !== data?.strategy) payload.strategy = editStrategy
    if (editRingTime !== data?.ringTime) payload.ringTime = editRingTime
    const dest = editNoAnswerDest || null
    if (dest !== data?.noAnswerDestination) payload.noAnswerDestination = dest
    updateMutation.mutate(payload, { onSuccess: () => setEditing(false) })
  }

  const handleDelete = async () => {
    await deleteMutation.mutateAsync(ringGroupId)
    router.navigate({ to: "/call-routing", search: { tab: "ring-groups" } })
  }

  const members = data?.members ?? []
  const sortedMembers = [...members].sort((a, b) => a.sortOrder - b.sortOrder)
  const extensionCount = members.filter((m) => m.extensionId).length
  const externalCount = members.filter((m) => m.externalNumber).length

  // Loading
  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <div className="space-y-2">
          <Skeleton className="h-4 w-28" /><Skeleton className="h-8 w-52" /><Skeleton className="h-4 w-64" />
        </div>
        <PageSection>
          <div className="grid gap-6 md:grid-cols-[1.1fr_0.9fr]">
            <div className="space-y-6">
              <div className="rounded-xl border border-border/60 bg-card/80 p-6 space-y-4">
                <Skeleton className="h-6 w-40" />
                <div className="grid gap-4 md:grid-cols-2">
                  {Array.from({ length: 5 }).map((_, i) => <div key={i} className="space-y-1.5"><Skeleton className="h-3.5 w-20" /><Skeleton className="h-5 w-36" /></div>)}
                </div>
              </div>
              <div className="rounded-xl border border-border/60 bg-card/80 p-6 space-y-4">
                <Skeleton className="h-6 w-24" />
                {Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}
              </div>
            </div>
            <div className="rounded-xl border border-border/60 bg-card/80 p-6 space-y-4">
              <Skeleton className="h-5 w-24" />
              {Array.from({ length: 3 }).map((_, i) => <div key={i} className="space-y-1"><Skeleton className="h-3 w-20" /><Skeleton className="h-5 w-40" /></div>)}
            </div>
          </div>
        </PageSection>
      </PageContainer>
    )
  }

  // Error
  if (isError || !data) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader eyebrow="Call Routing" title="Ring Group" actions={<Button variant="outline" size="sm" asChild><Link to="/call-routing" search={{ tab: "ring-groups" }}><ArrowLeft className="mr-2 h-4 w-4" /> Back</Link></Button>} />
        <PageSection>
          <EmptyState
            icon={AlertCircle}
            title="Unable to load ring group"
            description="Something went wrong. Please try again."
            action={<Button variant="outline" size="sm" onClick={() => refetch()}>Try again</Button>}
          />
        </PageSection>
      </PageContainer>
    )
  }

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Call Routing"
        title={data.name}
        description={`Ring group ${data.number} -- ${strategyLabels[data.strategy] ?? data.strategy}`}
        breadcrumbs={
          <Breadcrumb>
            <BreadcrumbList>
              <BreadcrumbItem><BreadcrumbLink asChild><Link to="/home">Home</Link></BreadcrumbLink></BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem><BreadcrumbLink asChild><Link to="/call-routing" search={{ tab: "ring-groups" }}>Call Routing</Link></BreadcrumbLink></BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem><BreadcrumbPage>{data.name}</BreadcrumbPage></BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
        actions={
          <div className="flex items-center gap-3">
            <Badge variant="outline">{members.length} member{members.length === 1 ? "" : "s"}</Badge>
            {!editing && (
              <Button variant="outline" size="sm" onClick={() => startEditing(data)}>
                <Pencil className="mr-2 h-4 w-4" /> Edit
              </Button>
            )}
            <Button variant="outline" size="sm" asChild>
              <Link to="/call-routing" search={{ tab: "ring-groups" }}>
                <ArrowLeft className="mr-2 h-4 w-4" /> Back
              </Link>
            </Button>
          </div>
        }
      />

      <PageSection>
        <div className="grid gap-6 md:grid-cols-[1.1fr_0.9fr]">
          <div className="space-y-6">
            {/* Configuration */}
            <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
              <CardHeader className="flex flex-row items-center justify-between">
                <CardTitle className="flex items-center gap-2">
                  <Users className="h-5 w-5 text-muted-foreground" />
                  Group Configuration
                </CardTitle>
                {editing && (
                  <div className="flex gap-2">
                    <Button variant="ghost" size="sm" onClick={() => setEditing(false)}>Cancel</Button>
                    <Button size="sm" onClick={handleSave} disabled={updateMutation.isPending}>
                      {updateMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                      Save
                    </Button>
                  </div>
                )}
              </CardHeader>
              <CardContent className="space-y-4">
                {editing ? (
                  <div className="space-y-4">
                    <div className="grid gap-4 sm:grid-cols-2">
                      <div className="space-y-2">
                        <Label>Name</Label>
                        <Input value={editName} onChange={(e) => setEditName(e.target.value)} />
                      </div>
                      <div className="space-y-2">
                        <Label>Number</Label>
                        <Input value={editNumber} onChange={(e) => setEditNumber(e.target.value)} />
                      </div>
                    </div>
                    <div className="space-y-2">
                      <Label>Strategy</Label>
                      <Select value={editStrategy} onValueChange={setEditStrategy}>
                        <SelectTrigger><SelectValue /></SelectTrigger>
                        <SelectContent>
                          {Object.entries(strategyLabels).map(([k, v]) => (
                            <SelectItem key={k} value={k}>{v}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label>Ring Time (seconds)</Label>
                      <Input type="number" value={editRingTime} onChange={(e) => setEditRingTime(Number(e.target.value))} min={5} />
                    </div>
                    <div className="space-y-2">
                      <Label>No Answer Destination</Label>
                      <Input value={editNoAnswerDest} onChange={(e) => setEditNoAnswerDest(e.target.value)} placeholder="Destination when no one answers (optional)" />
                    </div>
                  </div>
                ) : (
                  <div className="grid gap-4 text-sm md:grid-cols-2">
                    <InfoField label="Name" value={data.name} />
                    <InfoField label="Number" value={data.number} />
                    <InfoField label="Strategy" value={strategyLabels[data.strategy] ?? data.strategy} />
                    <InfoField label="Ring Time" value={`${data.ringTime}s`} />
                    <InfoField label="No Answer Destination" value={data.noAnswerDestination} />
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Members */}
            <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Users className="h-5 w-5 text-muted-foreground" />
                  Group Members
                </CardTitle>
                <CardDescription>Extensions and external numbers that ring when this group is called.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {sortedMembers.length > 0 ? (
                  <div className="overflow-x-auto">
                  <Table aria-label="Ring group members">
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-20">Order</TableHead>
                        <TableHead className="w-28">Type</TableHead>
                        <TableHead>Value</TableHead>
                        <TableHead className="w-16 text-right">Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {sortedMembers.map((m) => (
                        <MemberRow key={m.id} member={m} groupId={ringGroupId} />
                      ))}
                    </TableBody>
                  </Table>
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground py-4 text-center">No members assigned.</p>
                )}
                <AddMemberRow groupId={ringGroupId} />
              </CardContent>
            </Card>

            {/* Danger Zone */}
            <Card className="border-destructive/30 bg-card/80 shadow-md">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-destructive">
                  <AlertTriangle className="h-4 w-4" /> Danger Zone
                </CardTitle>
                <CardDescription>Irreversible and destructive actions.</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="flex items-center justify-between rounded-lg border border-destructive/20 bg-destructive/5 p-4">
                  <div>
                    <p className="font-medium text-sm">Delete this ring group</p>
                    <p className="text-xs text-muted-foreground">Once deleted, this ring group and all member assignments cannot be recovered.</p>
                  </div>
                  <DeleteDialog name={data.name} onDelete={handleDelete} isPending={deleteMutation.isPending} />
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Sidebar */}
          <div className="space-y-4">
            <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
              <CardHeader>
                <CardTitle className="flex items-center gap-2"><Users className="h-4 w-4" /> Metadata</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-1">
                  <p className="text-xs font-medium text-muted-foreground">Ring Group ID</p>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs break-all">{data.id}</span>
                    <CopyButton value={data.id} label="ring group ID" />
                  </div>
                </div>
                <Separator />
                <div className="space-y-1">
                  <p className="text-xs font-medium text-muted-foreground">Team ID</p>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs break-all">{data.teamId}</span>
                    <CopyButton value={data.teamId} label="team ID" />
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
              <CardHeader>
                <CardTitle className="flex items-center gap-2"><Users className="h-4 w-4" /> Summary</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Total members</span>
                  <span className="font-medium text-sm">{members.length}</span>
                </div>
                <Separator />
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Extensions</span>
                  <span className="font-medium text-sm">{extensionCount}</span>
                </div>
                <Separator />
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">External numbers</span>
                  <span className="font-medium text-sm">{externalCount}</span>
                </div>
                <Separator />
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Strategy</span>
                  <span className="font-medium text-sm">{strategyLabels[data.strategy] ?? data.strategy}</span>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </PageSection>

      <PageSection>
        <EntityActivityPanel
          targetType="ring_group"
          targetId={ringGroupId}
        />
      </PageSection>
    </PageContainer>
  )
}
