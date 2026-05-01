import { createFileRoute, Link, useRouter } from "@tanstack/react-router"
import { useState } from "react"
import {
  AlertCircle,
  AlertTriangle,
  ArrowLeft,
  Loader2,
  Pause,
  Pencil,
  Phone,
  Play,
  Plus,
  Trash2,
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
import { CopyButton } from "@/components/ui/copy-button"
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import {
  useCallQueue,
  useUpdateCallQueue,
  useDeleteCallQueue,
  useCreateCallQueueMember,
  useDeleteCallQueueMember,
  usePauseCallQueueMember,
  type CallQueue,
  type CallQueueMember,
} from "@/lib/api/hooks/call-routing"
import { EntityActivityPanel } from "@/components/shared/entity-activity-panel"
import { useDocumentTitle } from "@/hooks/use-document-title"

export const Route = createFileRoute("/_app/call-routing/call-queues/$callQueueId")({
  component: CallQueueDetailPage,
})

// -- Constants ----------------------------------------------------------------

const strategyLabels: Record<string, string> = {
  ring_all: "Ring All",
  round_robin: "Round Robin",
  least_recent: "Least Recent",
  fewest_calls: "Fewest Calls",
  random: "Random",
  linear: "Linear",
  weight_random: "Weighted Random",
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
              This will permanently delete this call queue and all its member assignments. This action cannot be undone.
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

function AddMemberRow({ queueId }: { queueId: string }) {
  const createMember = useCreateCallQueueMember(queueId)
  const [adding, setAdding] = useState(false)
  const [extensionId, setExtensionId] = useState("")
  const [priority, setPriority] = useState(0)
  const [penalty, setPenalty] = useState(0)

  const handleSave = () => {
    createMember.mutate(
      { extensionId: extensionId.trim() || null, priority, penalty, isPaused: false },
      {
        onSuccess: () => {
          setAdding(false)
          setExtensionId("")
          setPriority(0)
          setPenalty(0)
        },
      },
    )
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
      <div className="grid gap-3 sm:grid-cols-3">
        <div className="space-y-2">
          <Label>Extension ID</Label>
          <Input placeholder="Extension UUID" value={extensionId} onChange={(e) => setExtensionId(e.target.value)} />
        </div>
        <div className="space-y-2">
          <Label>Priority</Label>
          <Input type="number" value={priority} onChange={(e) => setPriority(Number(e.target.value))} min={0} />
        </div>
        <div className="space-y-2">
          <Label>Penalty</Label>
          <Input type="number" value={penalty} onChange={(e) => setPenalty(Number(e.target.value))} min={0} />
        </div>
      </div>
      <div className="flex items-center gap-2">
        <Button size="sm" onClick={handleSave} disabled={createMember.isPending}>
          {createMember.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
          Add
        </Button>
        <Button variant="ghost" size="sm" onClick={() => setAdding(false)}>Cancel</Button>
      </div>
    </div>
  )
}

// -- Member Row ---------------------------------------------------------------

function MemberRow({ member, queueId }: { member: CallQueueMember; queueId: string }) {
  const deleteMember = useDeleteCallQueueMember(queueId)
  const pauseMember = usePauseCallQueueMember(queueId)

  return (
    <TableRow>
      <TableCell>
        <span className="font-mono text-xs">{member.extensionId ? member.extensionId.slice(0, 8) + "..." : "---"}</span>
      </TableCell>
      <TableCell><span className="text-sm">{member.priority}</span></TableCell>
      <TableCell><span className="text-sm">{member.penalty}</span></TableCell>
      <TableCell>
        {member.isPaused ? (
          <Badge variant="outline" className="gap-1 text-amber-600 border-amber-300 dark:text-amber-400 dark:border-amber-700">
            <Pause className="h-3 w-3" /> Paused
          </Badge>
        ) : (
          <Badge className="gap-1 bg-emerald-100 text-emerald-700 hover:bg-emerald-100 dark:bg-emerald-900/30 dark:text-emerald-400">
            <Play className="h-3 w-3" /> Active
          </Badge>
        )}
      </TableCell>
      <TableCell className="text-right">
        <div className="flex items-center justify-end gap-1">
          <Button
            variant="ghost"
            size="sm"
            className="h-7 gap-1 text-xs"
            onClick={() => pauseMember.mutate({ memberId: member.id, isPaused: !member.isPaused })}
            disabled={pauseMember.isPending}
          >
            {pauseMember.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : member.isPaused ? <Play className="h-3 w-3" /> : <Pause className="h-3 w-3" />}
            {member.isPaused ? "Unpause" : "Pause"}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className="h-7 w-7 p-0 text-muted-foreground hover:text-destructive"
            onClick={() => deleteMember.mutate(member.id)}
            disabled={deleteMember.isPending}
          >
            {deleteMember.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
          </Button>
        </div>
      </TableCell>
    </TableRow>
  )
}

// -- Info Field ---------------------------------------------------------------

function InfoField({ label, value }: { label: string; value?: string | number | boolean | null }) {
  const display = typeof value === "boolean" ? (value ? "Yes" : "No") : (value ?? "---")
  return (
    <div>
      <p className="text-muted-foreground">{label}</p>
      <p>{String(display)}</p>
    </div>
  )
}

// -- Main page ----------------------------------------------------------------

function CallQueueDetailPage() {
  const { callQueueId } = Route.useParams()
  const router = useRouter()

  const { data, isLoading, isError, refetch } = useCallQueue(callQueueId)
  const updateMutation = useUpdateCallQueue(callQueueId)
  const deleteMutation = useDeleteCallQueue()

  const [editing, setEditing] = useState(false)
  const [editName, setEditName] = useState("")
  const [editNumber, setEditNumber] = useState("")
  const [editStrategy, setEditStrategy] = useState("ring_all")
  const [editRingTime, setEditRingTime] = useState(15)
  const [editMaxWait, setEditMaxWait] = useState(300)
  const [editMaxCallers, setEditMaxCallers] = useState(10)
  const [editWrapup, setEditWrapup] = useState(0)
  const [editJoinEmpty, setEditJoinEmpty] = useState(false)
  const [editLeaveEmpty, setEditLeaveEmpty] = useState(true)
  const [editAnnounceHold, setEditAnnounceHold] = useState(false)
  const [editTimeoutDest, setEditTimeoutDest] = useState("")

  useDocumentTitle(data ? `${data.name} - Call Queues` : "Call Queue Detail")

  function startEditing(q: CallQueue) {
    setEditName(q.name)
    setEditNumber(q.number)
    setEditStrategy(q.strategy)
    setEditRingTime(q.ringTime)
    setEditMaxWait(q.maxWaitTime)
    setEditMaxCallers(q.maxCallers)
    setEditWrapup(q.wrapupTime)
    setEditJoinEmpty(q.joinEmpty)
    setEditLeaveEmpty(q.leaveWhenEmpty)
    setEditAnnounceHold(q.announceHoldtime)
    setEditTimeoutDest(q.timeoutDestination ?? "")
    setEditing(true)
  }

  function handleSave() {
    const payload: Record<string, unknown> = {}
    if (editName !== data?.name) payload.name = editName
    if (editNumber !== data?.number) payload.number = editNumber
    if (editStrategy !== data?.strategy) payload.strategy = editStrategy
    if (editRingTime !== data?.ringTime) payload.ringTime = editRingTime
    if (editMaxWait !== data?.maxWaitTime) payload.maxWaitTime = editMaxWait
    if (editMaxCallers !== data?.maxCallers) payload.maxCallers = editMaxCallers
    if (editWrapup !== data?.wrapupTime) payload.wrapupTime = editWrapup
    if (editJoinEmpty !== data?.joinEmpty) payload.joinEmpty = editJoinEmpty
    if (editLeaveEmpty !== data?.leaveWhenEmpty) payload.leaveWhenEmpty = editLeaveEmpty
    if (editAnnounceHold !== data?.announceHoldtime) payload.announceHoldtime = editAnnounceHold
    const dest = editTimeoutDest || null
    if (dest !== data?.timeoutDestination) payload.timeoutDestination = dest
    updateMutation.mutate(payload, { onSuccess: () => setEditing(false) })
  }

  const handleDelete = async () => {
    await deleteMutation.mutateAsync(callQueueId)
    router.navigate({ to: "/call-routing", search: { tab: "call-queues" } })
  }

  const members = data?.members ?? []
  const activeMemberCount = members.filter((m) => !m.isPaused).length

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
                <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                  {Array.from({ length: 9 }).map((_, i) => <div key={i} className="space-y-1.5"><Skeleton className="h-3.5 w-20" /><Skeleton className="h-5 w-36" /></div>)}
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
        <PageHeader eyebrow="Call Routing" title="Call Queue" actions={<Button variant="outline" size="sm" asChild><Link to="/call-routing" search={{ tab: "call-queues" }}><ArrowLeft className="mr-2 h-4 w-4" /> Back</Link></Button>} />
        <PageSection>
          <EmptyState
            icon={AlertCircle}
            title="Unable to load call queue"
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
        description={`Queue ${data.number} -- ${strategyLabels[data.strategy] ?? data.strategy}`}
        breadcrumbs={
          <Breadcrumb>
            <BreadcrumbList>
              <BreadcrumbItem><BreadcrumbLink asChild><Link to="/home">Home</Link></BreadcrumbLink></BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem><BreadcrumbLink asChild><Link to="/call-routing" search={{ tab: "call-queues" }}>Call Routing</Link></BreadcrumbLink></BreadcrumbItem>
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
              <Link to="/call-routing" search={{ tab: "call-queues" }}>
                <ArrowLeft className="mr-2 h-4 w-4" /> Back
              </Link>
            </Button>
          </div>
        }
      />

      <PageSection>
        <div className="grid gap-6 md:grid-cols-[1.1fr_0.9fr]">
          <div className="space-y-6">
            {/* Queue Configuration */}
            <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
              <CardHeader className="flex flex-row items-center justify-between">
                <CardTitle className="flex items-center gap-2">
                  <Phone className="h-5 w-5 text-muted-foreground" />
                  Queue Configuration
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
                    <div className="grid gap-4 sm:grid-cols-3">
                      <div className="space-y-2">
                        <Label>Ring Time (s)</Label>
                        <Input type="number" value={editRingTime} onChange={(e) => setEditRingTime(Number(e.target.value))} min={5} />
                      </div>
                      <div className="space-y-2">
                        <Label>Max Wait (s)</Label>
                        <Input type="number" value={editMaxWait} onChange={(e) => setEditMaxWait(Number(e.target.value))} min={0} />
                      </div>
                      <div className="space-y-2">
                        <Label>Max Callers</Label>
                        <Input type="number" value={editMaxCallers} onChange={(e) => setEditMaxCallers(Number(e.target.value))} min={1} />
                      </div>
                    </div>
                    <div className="space-y-2">
                      <Label>Wrapup Time (s)</Label>
                      <Input type="number" value={editWrapup} onChange={(e) => setEditWrapup(Number(e.target.value))} min={0} />
                    </div>
                    <div className="space-y-3">
                      <div className="flex items-center gap-3">
                        <Switch checked={editJoinEmpty} onCheckedChange={setEditJoinEmpty} id="edit-join-empty" />
                        <Label htmlFor="edit-join-empty">Join when empty</Label>
                      </div>
                      <div className="flex items-center gap-3">
                        <Switch checked={editLeaveEmpty} onCheckedChange={setEditLeaveEmpty} id="edit-leave-empty" />
                        <Label htmlFor="edit-leave-empty">Leave when empty</Label>
                      </div>
                      <div className="flex items-center gap-3">
                        <Switch checked={editAnnounceHold} onCheckedChange={setEditAnnounceHold} id="edit-announce" />
                        <Label htmlFor="edit-announce">Announce hold time</Label>
                      </div>
                    </div>
                    <div className="space-y-2">
                      <Label>Timeout Destination</Label>
                      <Input value={editTimeoutDest} onChange={(e) => setEditTimeoutDest(e.target.value)} placeholder="Destination on queue timeout (optional)" />
                    </div>
                  </div>
                ) : (
                  <div className="grid gap-4 text-sm md:grid-cols-2 lg:grid-cols-3">
                    <InfoField label="Name" value={data.name} />
                    <InfoField label="Number" value={data.number} />
                    <InfoField label="Strategy" value={strategyLabels[data.strategy] ?? data.strategy} />
                    <InfoField label="Ring Time" value={`${data.ringTime}s`} />
                    <InfoField label="Max Wait" value={`${data.maxWaitTime}s`} />
                    <InfoField label="Max Callers" value={data.maxCallers} />
                    <InfoField label="Wrapup Time" value={`${data.wrapupTime}s`} />
                    <InfoField label="Join Empty" value={data.joinEmpty} />
                    <InfoField label="Leave Empty" value={data.leaveWhenEmpty} />
                    <InfoField label="Announce Hold" value={data.announceHoldtime} />
                    <InfoField label="Timeout Dest." value={data.timeoutDestination} />
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Members */}
            <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Phone className="h-5 w-5 text-muted-foreground" />
                  Queue Members
                </CardTitle>
                <CardDescription>Agents assigned to receive calls from this queue.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {members.length > 0 ? (
                  <div className="overflow-x-auto">
                  <Table aria-label="Queue members">
                    <TableHeader>
                      <TableRow>
                        <TableHead>Extension</TableHead>
                        <TableHead>Priority</TableHead>
                        <TableHead>Penalty</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead className="text-right">Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {members.map((m) => (
                        <MemberRow key={m.id} member={m} queueId={callQueueId} />
                      ))}
                    </TableBody>
                  </Table>
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground py-4 text-center">No members assigned.</p>
                )}
                <AddMemberRow queueId={callQueueId} />
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
                    <p className="font-medium text-sm">Delete this call queue</p>
                    <p className="text-xs text-muted-foreground">Once deleted, this call queue and all member assignments cannot be recovered.</p>
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
                <CardTitle className="flex items-center gap-2"><Phone className="h-4 w-4" /> Metadata</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-1">
                  <p className="text-xs font-medium text-muted-foreground">Call Queue ID</p>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs break-all">{data.id}</span>
                    <CopyButton value={data.id} label="call queue ID" />
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
                <CardTitle className="flex items-center gap-2"><Phone className="h-4 w-4" /> Summary</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Total members</span>
                  <span className="font-medium text-sm">{members.length}</span>
                </div>
                <Separator />
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Active members</span>
                  <span className="font-medium text-sm">{activeMemberCount}</span>
                </div>
                <Separator />
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Paused members</span>
                  <span className="font-medium text-sm">{members.length - activeMemberCount}</span>
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
          targetType="call_queue"
          targetId={callQueueId}
        />
      </PageSection>
    </PageContainer>
  )
}
