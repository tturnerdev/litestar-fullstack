import { createFileRoute, Link, useRouter } from "@tanstack/react-router"
import { AlertCircle, AlertTriangle, ArrowDown, ArrowLeft, ArrowUp, Copy, Loader2, MoreHorizontal, Pause, Pencil, Phone, Play, Plus, Trash2 } from "lucide-react"
import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { toast } from "sonner"
import { EntityActivityPanel } from "@/components/shared/entity-activity-panel"
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
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb"
import { Button, buttonVariants } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { CopyButton } from "@/components/ui/copy-button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useDocumentTitle } from "@/hooks/use-document-title"
import {
  type CallQueue,
  type CallQueueMember,
  useCallQueue,
  useCreateCallQueueMember,
  useDeleteCallQueue,
  useDeleteCallQueueMember,
  usePauseCallQueueMember,
  useReorderCallQueueMembers,
  useUpdateCallQueue,
} from "@/lib/api/hooks/call-routing"

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
            <AlertDialogDescription>This will permanently delete this call queue and all its member assignments. This action cannot be undone.</AlertDialogDescription>
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

// -- Edit Dialog --------------------------------------------------------------

interface EditCallQueueDialogProps {
  queue: CallQueue
  open: boolean
  onOpenChange: (open: boolean) => void
}

function EditCallQueueDialog({ queue, open, onOpenChange }: EditCallQueueDialogProps) {
  const [name, setName] = useState(queue.name)
  const [number, setNumber] = useState(queue.number)
  const [strategy, setStrategy] = useState(queue.strategy)
  const [ringTime, setRingTime] = useState(queue.ringTime)
  const [maxWaitTime, setMaxWaitTime] = useState(queue.maxWaitTime)
  const [maxCallers, setMaxCallers] = useState(queue.maxCallers)
  const [wrapupTime, setWrapupTime] = useState(queue.wrapupTime)
  const [joinEmpty, setJoinEmpty] = useState(queue.joinEmpty)
  const [leaveWhenEmpty, setLeaveWhenEmpty] = useState(queue.leaveWhenEmpty)
  const [announceHoldtime, setAnnounceHoldtime] = useState(queue.announceHoldtime)
  const [timeoutDestination, setTimeoutDestination] = useState(queue.timeoutDestination ?? "")
  const updateMutation = useUpdateCallQueue(queue.id)

  // Reset form state when the dialog opens or the queue data changes
  useEffect(() => {
    if (open) {
      setName(queue.name)
      setNumber(queue.number)
      setStrategy(queue.strategy)
      setRingTime(queue.ringTime)
      setMaxWaitTime(queue.maxWaitTime)
      setMaxCallers(queue.maxCallers)
      setWrapupTime(queue.wrapupTime)
      setJoinEmpty(queue.joinEmpty)
      setLeaveWhenEmpty(queue.leaveWhenEmpty)
      setAnnounceHoldtime(queue.announceHoldtime)
      setTimeoutDestination(queue.timeoutDestination ?? "")
    }
  }, [open, queue])

  const isDirty = useMemo(() => {
    if (name !== queue.name) return true
    if (number !== queue.number) return true
    if (strategy !== queue.strategy) return true
    if (ringTime !== queue.ringTime) return true
    if (maxWaitTime !== queue.maxWaitTime) return true
    if (maxCallers !== queue.maxCallers) return true
    if (wrapupTime !== queue.wrapupTime) return true
    if (joinEmpty !== queue.joinEmpty) return true
    if (leaveWhenEmpty !== queue.leaveWhenEmpty) return true
    if (announceHoldtime !== queue.announceHoldtime) return true
    const dest = timeoutDestination || null
    if (dest !== (queue.timeoutDestination ?? null)) return true
    return false
  }, [name, number, strategy, ringTime, maxWaitTime, maxCallers, wrapupTime, joinEmpty, leaveWhenEmpty, announceHoldtime, timeoutDestination, queue])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    const payload: Record<string, unknown> = {}
    if (name !== queue.name) payload.name = name
    if (number !== queue.number) payload.number = number
    if (strategy !== queue.strategy) payload.strategy = strategy
    if (ringTime !== queue.ringTime) payload.ringTime = ringTime
    if (maxWaitTime !== queue.maxWaitTime) payload.maxWaitTime = maxWaitTime
    if (maxCallers !== queue.maxCallers) payload.maxCallers = maxCallers
    if (wrapupTime !== queue.wrapupTime) payload.wrapupTime = wrapupTime
    if (joinEmpty !== queue.joinEmpty) payload.joinEmpty = joinEmpty
    if (leaveWhenEmpty !== queue.leaveWhenEmpty) payload.leaveWhenEmpty = leaveWhenEmpty
    if (announceHoldtime !== queue.announceHoldtime) payload.announceHoldtime = announceHoldtime
    const dest = timeoutDestination || null
    if (dest !== (queue.timeoutDestination ?? null)) payload.timeoutDestination = dest

    if (Object.keys(payload).length === 0) {
      onOpenChange(false)
      return
    }

    updateMutation.mutate(payload, {
      onSuccess: () => {
        onOpenChange(false)
      },
    })
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <form onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Phone className="h-5 w-5 text-muted-foreground" />
              Edit Call Queue
            </DialogTitle>
            <DialogDescription>
              Update configuration for queue <span className="font-mono font-medium">{queue.number}</span>.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="edit-cq-name">Name</Label>
                <Input id="edit-cq-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Sales Queue" required />
              </div>
              <div className="space-y-2">
                <Label htmlFor="edit-cq-number">Number</Label>
                <Input id="edit-cq-number" value={number} onChange={(e) => setNumber(e.target.value)} placeholder="8001" />
              </div>
            </div>

            <div className="space-y-2">
              <Label>Strategy</Label>
              <Select value={strategy} onValueChange={setStrategy}>
                <SelectTrigger>
                  <SelectValue placeholder="Select strategy" />
                </SelectTrigger>
                <SelectContent>
                  {Object.entries(strategyLabels).map(([k, v]) => (
                    <SelectItem key={k} value={k}>
                      {v}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <Separator />

            <div className="grid gap-4 sm:grid-cols-3">
              <div className="space-y-2">
                <Label htmlFor="edit-cq-ring-time">Ring Time (s)</Label>
                <Input id="edit-cq-ring-time" type="number" value={ringTime} onChange={(e) => setRingTime(Number(e.target.value))} min={5} />
              </div>
              <div className="space-y-2">
                <Label htmlFor="edit-cq-max-wait">Max Wait (s)</Label>
                <Input id="edit-cq-max-wait" type="number" value={maxWaitTime} onChange={(e) => setMaxWaitTime(Number(e.target.value))} min={0} />
              </div>
              <div className="space-y-2">
                <Label htmlFor="edit-cq-max-callers">Max Callers</Label>
                <Input id="edit-cq-max-callers" type="number" value={maxCallers} onChange={(e) => setMaxCallers(Number(e.target.value))} min={1} />
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="edit-cq-wrapup">Wrapup Time (s)</Label>
              <Input id="edit-cq-wrapup" type="number" value={wrapupTime} onChange={(e) => setWrapupTime(Number(e.target.value))} min={0} />
            </div>

            <Separator />

            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label htmlFor="edit-cq-join-empty">Join when empty</Label>
                  <p className="text-xs text-muted-foreground">Allow callers to enter the queue when no agents are available.</p>
                </div>
                <Switch id="edit-cq-join-empty" checked={joinEmpty} onCheckedChange={setJoinEmpty} />
              </div>
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label htmlFor="edit-cq-leave-empty">Leave when empty</Label>
                  <p className="text-xs text-muted-foreground">Remove callers from the queue if all agents leave.</p>
                </div>
                <Switch id="edit-cq-leave-empty" checked={leaveWhenEmpty} onCheckedChange={setLeaveWhenEmpty} />
              </div>
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label htmlFor="edit-cq-announce">Announce hold time</Label>
                  <p className="text-xs text-muted-foreground">Tell callers their estimated wait time.</p>
                </div>
                <Switch id="edit-cq-announce" checked={announceHoldtime} onCheckedChange={setAnnounceHoldtime} />
              </div>
            </div>

            <Separator />

            <div className="space-y-2">
              <Label htmlFor="edit-cq-timeout-dest">Timeout Destination</Label>
              <Input
                id="edit-cq-timeout-dest"
                value={timeoutDestination}
                onChange={(e) => setTimeoutDestination(e.target.value)}
                placeholder="Destination on queue timeout (optional)"
              />
              <p className="text-xs text-muted-foreground">Where to route callers when the max wait time is exceeded.</p>
            </div>
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={!name.trim() || !isDirty || updateMutation.isPending}>
              {updateMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {updateMutation.isPending ? "Saving..." : "Save changes"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
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
        <Button variant="ghost" size="sm" onClick={() => setAdding(false)}>
          Cancel
        </Button>
      </div>
    </div>
  )
}

// -- Member Row ---------------------------------------------------------------

function MemberRow({
  member,
  queueId,
  isFirst,
  isLast,
  isHighlighted,
  onMoveUp,
  onMoveDown,
  isReordering,
}: {
  member: CallQueueMember
  queueId: string
  isFirst: boolean
  isLast: boolean
  isHighlighted: boolean
  onMoveUp: () => void
  onMoveDown: () => void
  isReordering: boolean
}) {
  const deleteMember = useDeleteCallQueueMember(queueId)
  const pauseMember = usePauseCallQueueMember(queueId)

  return (
    <TableRow className={isHighlighted ? "animate-highlight-row" : ""}>
      <TableCell>
        {member.extensionId ? (
          <Link to="/voice/extensions/$extensionId" params={{ extensionId: member.extensionId }} className="text-primary hover:underline font-mono text-sm">
            {member.extensionId.slice(0, 8) + "..."}
          </Link>
        ) : (
          <span className="font-mono text-xs">---</span>
        )}
      </TableCell>
      <TableCell>
        <span className="text-sm">{member.priority}</span>
      </TableCell>
      <TableCell>
        <span className="text-sm">{member.penalty}</span>
      </TableCell>
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
        <div className="flex items-center justify-end gap-0.5">
          <Button variant="ghost" size="icon" className="h-7 w-7 text-muted-foreground" onClick={onMoveUp} disabled={isFirst || isReordering} aria-label="Move up">
            <ArrowUp className="h-3.5 w-3.5" />
          </Button>
          <Button variant="ghost" size="icon" className="h-7 w-7 text-muted-foreground" onClick={onMoveDown} disabled={isLast || isReordering} aria-label="Move down">
            <ArrowDown className="h-3.5 w-3.5" />
          </Button>
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
  const deleteMutation = useDeleteCallQueue()

  const [showEditDialog, setShowEditDialog] = useState(false)
  const [showDeleteAlert, setShowDeleteAlert] = useState(false)

  useDocumentTitle(data ? `${data.name} - Call Queues` : "Call Queue Detail")

  const handleDelete = async () => {
    await deleteMutation.mutateAsync(callQueueId)
    router.navigate({ to: "/call-routing", search: { tab: "call-queues" } })
  }

  const [highlightedId, setHighlightedId] = useState<string | null>(null)
  const highlightTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const reorderMutation = useReorderCallQueueMembers(callQueueId)

  const members = data?.members ?? []
  const sortedMembers = [...members].sort((a, b) => a.priority - b.priority)
  const activeMemberCount = members.filter((m) => !m.isPaused).length

  const handleReorder = useCallback(
    (index: number, direction: "up" | "down") => {
      const swapIndex = direction === "up" ? index - 1 : index + 1
      if (swapIndex < 0 || swapIndex >= sortedMembers.length) return

      const memA = sortedMembers[index]
      const memB = sortedMembers[swapIndex]

      reorderMutation.mutate(
        {
          memberA: { id: memA.id, priority: memA.priority },
          memberB: { id: memB.id, priority: memB.priority },
        },
        {
          onSuccess: () => {
            if (highlightTimer.current) clearTimeout(highlightTimer.current)
            setHighlightedId(memA.id)
            highlightTimer.current = setTimeout(() => setHighlightedId(null), 700)
          },
        },
      )
    },
    [sortedMembers, reorderMutation],
  )

  // Loading
  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <div className="space-y-2">
          <Skeleton className="h-4 w-28" />
          <Skeleton className="h-8 w-52" />
          <Skeleton className="h-4 w-64" />
        </div>
        <PageSection>
          <div className="grid gap-6 md:grid-cols-[1.1fr_0.9fr]">
            <div className="space-y-6">
              <div className="rounded-xl border border-border/60 bg-card/80 p-6 space-y-4">
                <Skeleton className="h-6 w-40" />
                <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                  {["name", "strategy", "timeout", "wrap-up", "max-wait", "weight", "join-empty", "leave-empty", "retry"].map((id) => (
                    <div key={id} className="space-y-1.5">
                      <Skeleton className="h-3.5 w-20" />
                      <Skeleton className="h-5 w-36" />
                    </div>
                  ))}
                </div>
              </div>
              <div className="rounded-xl border border-border/60 bg-card/80 p-6 space-y-4">
                <Skeleton className="h-6 w-24" />
                {["member-a", "member-b", "member-c"].map((id) => (
                  <Skeleton key={id} className="h-10 w-full" />
                ))}
              </div>
            </div>
            <div className="rounded-xl border border-border/60 bg-card/80 p-6 space-y-4">
              <Skeleton className="h-5 w-24" />
              {["created", "updated", "id"].map((id) => (
                <div key={id} className="space-y-1">
                  <Skeleton className="h-3 w-20" />
                  <Skeleton className="h-5 w-40" />
                </div>
              ))}
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
        <PageHeader
          eyebrow="Call Routing"
          title="Call Queue"
          actions={
            <Button variant="outline" size="sm" asChild>
              <Link to="/call-routing" search={{ tab: "call-queues" }}>
                <ArrowLeft className="mr-2 h-4 w-4" /> Back
              </Link>
            </Button>
          }
        />
        <PageSection>
          <EmptyState
            icon={AlertCircle}
            title="Unable to load call queue"
            description="Something went wrong. Please try again."
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
        eyebrow="Call Routing"
        title={data.name}
        description={`Queue ${data.number} -- ${strategyLabels[data.strategy] ?? data.strategy}`}
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
                  <Link to="/call-routing" search={{ tab: "call-queues" }}>
                    Call Routing
                  </Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbPage>{data.name}</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
        actions={
          <div className="flex items-center gap-3">
            <Badge variant="outline">
              {members.length} member{members.length === 1 ? "" : "s"}
            </Badge>
            <Button variant="outline" size="sm" onClick={() => setShowEditDialog(true)}>
              <Pencil className="mr-2 h-4 w-4" /> Edit
            </Button>
            <Button variant="outline" size="sm" asChild>
              <Link to="/call-routing" search={{ tab: "call-queues" }}>
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
                    navigator.clipboard.writeText(callQueueId)
                    toast.success("Queue ID copied to clipboard")
                  }}
                >
                  <Copy className="mr-2 h-4 w-4" />
                  Copy Queue ID
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem className="text-destructive focus:text-destructive" onClick={() => setShowDeleteAlert(true)}>
                  <Trash2 className="mr-2 h-4 w-4" />
                  Delete Queue
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        }
      />

      <PageSection>
        <div className="grid gap-6 md:grid-cols-[1.1fr_0.9fr]">
          <div className="space-y-6">
            {/* Queue Configuration */}
            <SectionErrorBoundary name="Queue Configuration">
              <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Phone className="h-5 w-5 text-muted-foreground" />
                    Queue Configuration
                  </CardTitle>
                </CardHeader>
                <CardContent>
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
                </CardContent>
              </Card>
            </SectionErrorBoundary>

            {/* Members */}
            <SectionErrorBoundary name="Queue Members">
              <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Phone className="h-5 w-5 text-muted-foreground" />
                    Queue Members
                  </CardTitle>
                  <CardDescription>Agents assigned to receive calls from this queue.</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {sortedMembers.length > 0 ? (
                    <div className="overflow-x-auto">
                      <Table aria-label="Queue members">
                        <TableHeader>
                          <TableRow>
                            <TableHead>Extension</TableHead>
                            <TableHead>Priority</TableHead>
                            <TableHead>Penalty</TableHead>
                            <TableHead>Status</TableHead>
                            <TableHead className="w-40 text-right">Actions</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {sortedMembers.map((m, idx) => (
                            <MemberRow
                              key={m.id}
                              member={m}
                              queueId={callQueueId}
                              isFirst={idx === 0}
                              isLast={idx === sortedMembers.length - 1}
                              isHighlighted={highlightedId === m.id}
                              isReordering={reorderMutation.isPending}
                              onMoveUp={() => handleReorder(idx, "up")}
                              onMoveDown={() => handleReorder(idx, "down")}
                            />
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
            </SectionErrorBoundary>

            {/* Danger Zone */}
            <SectionErrorBoundary name="Danger Zone">
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
            </SectionErrorBoundary>
          </div>

          {/* Sidebar */}
          <div className="space-y-4">
            <SectionErrorBoundary name="Metadata">
              <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Phone className="h-4 w-4" /> Metadata
                  </CardTitle>
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
                      <Link to="/teams/$teamId" params={{ teamId: data.teamId }} className="text-primary hover:underline font-mono text-xs break-all">
                        {data.teamId}
                      </Link>
                      <CopyButton value={data.teamId} label="team ID" />
                    </div>
                  </div>
                </CardContent>
              </Card>
            </SectionErrorBoundary>

            <SectionErrorBoundary name="Summary">
              <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Phone className="h-4 w-4" /> Summary
                  </CardTitle>
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
            </SectionErrorBoundary>
          </div>
        </div>
      </PageSection>

      <PageSection>
        <EntityActivityPanel targetType="call_queue" targetId={callQueueId} />
      </PageSection>

      {/* Edit call queue dialog */}
      <EditCallQueueDialog queue={data} open={showEditDialog} onOpenChange={setShowEditDialog} />

      {/* Delete confirmation dialog */}
      <AlertDialog open={showDeleteAlert} onOpenChange={setShowDeleteAlert}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-destructive" /> Delete "{data.name}"?
            </AlertDialogTitle>
            <AlertDialogDescription>This will permanently delete this call queue and all its member assignments. This action cannot be undone.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteMutation.isPending}>Cancel</AlertDialogCancel>
            <AlertDialogAction className={buttonVariants({ variant: "destructive" })} onClick={handleDelete} disabled={deleteMutation.isPending}>
              {deleteMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {deleteMutation.isPending ? "Deleting..." : "Delete"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </PageContainer>
  )
}
