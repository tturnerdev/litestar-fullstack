import { createFileRoute, Link, useRouter } from "@tanstack/react-router"
import { AlertCircle, AlertTriangle, ArrowDown, ArrowLeft, ArrowUp, Copy, Loader2, MoreHorizontal, Pencil, Plus, Trash2, Users } from "lucide-react"
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
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useDocumentTitle } from "@/hooks/use-document-title"
import {
  type RingGroup,
  type RingGroupMember,
  useCreateRingGroupMember,
  useDeleteRingGroup,
  useDeleteRingGroupMember,
  useReorderRingGroupMembers,
  useRingGroup,
  useUpdateRingGroup,
} from "@/lib/api/hooks/call-routing"

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
            <AlertDialogDescription>This will permanently delete this ring group and all its member assignments. This action cannot be undone.</AlertDialogDescription>
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

interface EditRingGroupDialogProps {
  ringGroup: RingGroup
  open: boolean
  onOpenChange: (open: boolean) => void
}

function EditRingGroupDialog({ ringGroup, open, onOpenChange }: EditRingGroupDialogProps) {
  const [name, setName] = useState(ringGroup.name)
  const [number, setNumber] = useState(ringGroup.number)
  const [strategy, setStrategy] = useState(ringGroup.strategy)
  const [ringTime, setRingTime] = useState(ringGroup.ringTime)
  const [noAnswerDest, setNoAnswerDest] = useState(ringGroup.noAnswerDestination ?? "")
  const updateMutation = useUpdateRingGroup(ringGroup.id)

  // Reset form state when the dialog opens or the ring group changes
  useEffect(() => {
    if (open) {
      setName(ringGroup.name)
      setNumber(ringGroup.number)
      setStrategy(ringGroup.strategy)
      setRingTime(ringGroup.ringTime)
      setNoAnswerDest(ringGroup.noAnswerDestination ?? "")
    }
  }, [open, ringGroup])

  const isDirty = useMemo(() => {
    if (name !== ringGroup.name) return true
    if (number !== ringGroup.number) return true
    if (strategy !== ringGroup.strategy) return true
    if (ringTime !== ringGroup.ringTime) return true
    const currentDest = ringGroup.noAnswerDestination ?? ""
    if (noAnswerDest !== currentDest) return true
    return false
  }, [name, number, strategy, ringTime, noAnswerDest, ringGroup])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    const payload: Record<string, unknown> = {}
    if (name !== ringGroup.name) payload.name = name
    if (number !== ringGroup.number) payload.number = number
    if (strategy !== ringGroup.strategy) payload.strategy = strategy
    if (ringTime !== ringGroup.ringTime) payload.ringTime = ringTime
    const dest = noAnswerDest || null
    if (dest !== ringGroup.noAnswerDestination) payload.noAnswerDestination = dest

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
      <DialogContent>
        <form onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Users className="h-5 w-5 text-muted-foreground" />
              Edit Ring Group
            </DialogTitle>
            <DialogDescription>
              Update properties for ring group <span className="font-mono font-medium">{ringGroup.number}</span>.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="edit-rg-name">Name</Label>
                <Input id="edit-rg-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Ring group name" required />
              </div>
              <div className="space-y-2">
                <Label htmlFor="edit-rg-number">Number</Label>
                <Input id="edit-rg-number" value={number} onChange={(e) => setNumber(e.target.value)} placeholder="e.g., 600" />
              </div>
            </div>

            <Separator />

            <div className="space-y-2">
              <Label htmlFor="edit-rg-strategy">Strategy</Label>
              <Select value={strategy} onValueChange={setStrategy}>
                <SelectTrigger id="edit-rg-strategy">
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
              <p className="text-xs text-muted-foreground">How incoming calls are distributed to group members.</p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="edit-rg-ringtime">Ring Time (seconds)</Label>
              <Input id="edit-rg-ringtime" type="number" value={ringTime} onChange={(e) => setRingTime(Number(e.target.value))} min={5} max={300} />
              <p className="text-xs text-muted-foreground">How long each member rings before moving on (5-300 seconds).</p>
            </div>

            <Separator />

            <div className="space-y-2">
              <Label htmlFor="edit-rg-noanswer">No Answer Destination</Label>
              <Input id="edit-rg-noanswer" value={noAnswerDest} onChange={(e) => setNoAnswerDest(e.target.value)} placeholder="Destination when no one answers (optional)" />
              <p className="text-xs text-muted-foreground">Where calls are routed when no group members answer.</p>
            </div>
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={!isDirty || !name.trim() || updateMutation.isPending}>
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
          <SelectTrigger>
            <SelectValue placeholder="Select member type" />
          </SelectTrigger>
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
  groupId,
  isFirst,
  isLast,
  isHighlighted,
  onMoveUp,
  onMoveDown,
  isReordering,
}: {
  member: RingGroupMember
  groupId: string
  isFirst: boolean
  isLast: boolean
  isHighlighted: boolean
  onMoveUp: () => void
  onMoveDown: () => void
  isReordering: boolean
}) {
  const deleteMember = useDeleteRingGroupMember(groupId)

  const memberType = member.extensionId ? "Extension" : "External"

  return (
    <TableRow className={isHighlighted ? "animate-highlight-row" : ""}>
      <TableCell>
        <span className="text-sm">{member.sortOrder}</span>
      </TableCell>
      <TableCell>
        <Badge variant="outline" className="text-xs">
          {memberType}
        </Badge>
      </TableCell>
      <TableCell>
        {member.extensionId ? (
          <Link to="/voice/extensions/$extensionId" params={{ extensionId: member.extensionId }} className="text-primary hover:underline font-mono text-sm">
            {`${member.extensionId.slice(0, 8)}...`}
          </Link>
        ) : (
          <span className="text-sm">{member.externalNumber ?? "---"}</span>
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
  const deleteMutation = useDeleteRingGroup()
  const [showEditDialog, setShowEditDialog] = useState(false)
  const [showDeleteAlert, setShowDeleteAlert] = useState(false)

  useDocumentTitle(data ? `${data.name} - Ring Groups` : "Ring Group Detail")

  const handleDelete = async () => {
    await deleteMutation.mutateAsync(ringGroupId)
    router.navigate({ to: "/call-routing", search: { tab: "ring-groups" } })
  }

  const [highlightedId, setHighlightedId] = useState<string | null>(null)
  const highlightTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const reorderMutation = useReorderRingGroupMembers(ringGroupId)

  const members = data?.members ?? []
  const sortedMembers = [...members].sort((a, b) => a.sortOrder - b.sortOrder)
  const extensionCount = members.filter((m) => m.extensionId).length
  const externalCount = members.filter((m) => m.externalNumber).length

  const handleReorder = useCallback(
    (index: number, direction: "up" | "down") => {
      const swapIndex = direction === "up" ? index - 1 : index + 1
      if (swapIndex < 0 || swapIndex >= sortedMembers.length) return

      const memA = sortedMembers[index]
      const memB = sortedMembers[swapIndex]

      reorderMutation.mutate(
        {
          memberA: { id: memA.id, sortOrder: memA.sortOrder },
          memberB: { id: memB.id, sortOrder: memB.sortOrder },
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
                <div className="grid gap-4 md:grid-cols-2">
                  {["name", "strategy", "ring-time", "description", "cid-prefix"].map((id) => (
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
          title="Ring Group"
          actions={
            <Button variant="outline" size="sm" asChild>
              <Link to="/call-routing" search={{ tab: "ring-groups" }}>
                <ArrowLeft className="mr-2 h-4 w-4" /> Back
              </Link>
            </Button>
          }
        />
        <PageSection>
          <EmptyState
            icon={AlertCircle}
            title="Unable to load ring group"
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
        description={`Ring group ${data.number} -- ${strategyLabels[data.strategy] ?? data.strategy}`}
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
                  <Link to="/call-routing" search={{ tab: "ring-groups" }}>
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
              <Link to="/call-routing" search={{ tab: "ring-groups" }}>
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
                    navigator.clipboard.writeText(ringGroupId)
                    toast.success("Ring Group ID copied to clipboard")
                  }}
                >
                  <Copy className="mr-2 h-4 w-4" />
                  Copy Ring Group ID
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem className="text-destructive focus:text-destructive" onClick={() => setShowDeleteAlert(true)}>
                  <Trash2 className="mr-2 h-4 w-4" />
                  Delete Ring Group
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        }
      />

      <PageSection>
        <div className="grid gap-6 md:grid-cols-[1.1fr_0.9fr]">
          <div className="space-y-6">
            {/* Configuration */}
            <SectionErrorBoundary name="Group Configuration">
              <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Users className="h-5 w-5 text-muted-foreground" />
                    Group Configuration
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid gap-4 text-sm md:grid-cols-2">
                    <InfoField label="Name" value={data.name} />
                    <InfoField label="Number" value={data.number} />
                    <InfoField label="Strategy" value={strategyLabels[data.strategy] ?? data.strategy} />
                    <InfoField label="Ring Time" value={`${data.ringTime}s`} />
                    <InfoField label="No Answer Destination" value={data.noAnswerDestination} />
                  </div>
                </CardContent>
              </Card>
            </SectionErrorBoundary>

            {/* Members */}
            <SectionErrorBoundary name="Group Members">
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
                            <TableHead className="w-28 text-right">Actions</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {sortedMembers.map((m, idx) => (
                            <MemberRow
                              key={m.id}
                              member={m}
                              groupId={ringGroupId}
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
                  <AddMemberRow groupId={ringGroupId} />
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
                      <p className="font-medium text-sm">Delete this ring group</p>
                      <p className="text-xs text-muted-foreground">Once deleted, this ring group and all member assignments cannot be recovered.</p>
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
                    <Users className="h-4 w-4" /> Metadata
                  </CardTitle>
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
                    <Users className="h-4 w-4" /> Summary
                  </CardTitle>
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
            </SectionErrorBoundary>
          </div>
        </div>
      </PageSection>

      <PageSection>
        <EntityActivityPanel targetType="ring_group" targetId={ringGroupId} />
      </PageSection>

      {/* Edit ring group dialog */}
      <EditRingGroupDialog ringGroup={data} open={showEditDialog} onOpenChange={setShowEditDialog} />

      {/* Delete confirmation dialog */}
      <AlertDialog open={showDeleteAlert} onOpenChange={setShowDeleteAlert}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-destructive" /> Delete "{data.name}"?
            </AlertDialogTitle>
            <AlertDialogDescription>This will permanently delete this ring group and all its member assignments. This action cannot be undone.</AlertDialogDescription>
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
