import { createFileRoute, Link, useRouter } from "@tanstack/react-router"
import { useState } from "react"
import { toast } from "sonner"
import {
  AlertTriangle,
  ArrowLeft,
  Clock,
  Loader2,
  Pencil,
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
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"
import {
  useTimeCondition,
  useUpdateTimeCondition,
  useDeleteTimeCondition,
  useSetTimeConditionOverride,
  type TimeCondition,
} from "@/lib/api/hooks/call-routing"
import { EntityActivityPanel } from "@/components/shared/entity-activity-panel"
import { useDocumentTitle } from "@/hooks/use-document-title"

export const Route = createFileRoute("/_app/call-routing/time-conditions/$timeConditionId")({
  component: TimeConditionDetailPage,
})

// -- Constants ----------------------------------------------------------------

const overrideModeLabels: Record<string, string> = {
  none: "None",
  force_match: "Force Match",
  force_no_match: "Force No Match",
}

const overrideModeDescriptions: Record<string, string> = {
  none: "Normal operation -- routing follows the linked schedule.",
  force_match: "Override active -- always routes to the match destination regardless of schedule.",
  force_no_match: "Override active -- always routes to the no-match destination regardless of schedule.",
}

// -- Delete Dialog ------------------------------------------------------------

function DeleteDialog({
  name,
  onDelete,
  isPending,
}: {
  name: string
  onDelete: () => void
  isPending: boolean
}) {
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
              <AlertTriangle className="h-5 w-5 text-destructive" />
              Delete "{name}"?
            </AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete this time condition. Any call routes referencing it will need to be updated. This action cannot be undone.
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

// -- Info Field ---------------------------------------------------------------

function InfoField({ label, value, mono }: { label: string; value?: string | null; mono?: boolean }) {
  return (
    <div>
      <p className="text-muted-foreground">{label}</p>
      <p className={mono ? "font-mono text-xs" : ""}>{value ?? "---"}</p>
    </div>
  )
}

// -- Main page ----------------------------------------------------------------

function TimeConditionDetailPage() {
  const { timeConditionId } = Route.useParams()
  const router = useRouter()

  const { data, isLoading, isError } = useTimeCondition(timeConditionId)
  const updateMutation = useUpdateTimeCondition(timeConditionId)
  const deleteMutation = useDeleteTimeCondition()
  const overrideMutation = useSetTimeConditionOverride(timeConditionId)

  const [editing, setEditing] = useState(false)
  const [editName, setEditName] = useState("")
  const [editMatchDest, setEditMatchDest] = useState("")
  const [editNoMatchDest, setEditNoMatchDest] = useState("")
  const [editScheduleId, setEditScheduleId] = useState("")

  useDocumentTitle(data ? `${data.name} - Time Conditions` : "Time Condition Detail")

  function startEditing(tc: TimeCondition) {
    setEditName(tc.name)
    setEditMatchDest(tc.matchDestination)
    setEditNoMatchDest(tc.noMatchDestination)
    setEditScheduleId(tc.scheduleId ?? "")
    setEditing(true)
  }

  function handleSave() {
    const payload: Record<string, unknown> = {}
    if (editName !== data?.name) payload.name = editName
    if (editMatchDest !== data?.matchDestination) payload.matchDestination = editMatchDest
    if (editNoMatchDest !== data?.noMatchDestination) payload.noMatchDestination = editNoMatchDest
    const newScheduleId = editScheduleId || null
    if (newScheduleId !== data?.scheduleId) payload.scheduleId = newScheduleId
    updateMutation.mutate(payload, {
      onSuccess: () => {
        setEditing(false)
        toast.success("Time condition updated")
      },
      onError: (err) => {
        toast.error("Failed to update time condition", {
          description: err instanceof Error ? err.message : undefined,
        })
      },
    })
  }

  const handleDelete = async () => {
    try {
      await deleteMutation.mutateAsync(timeConditionId)
      toast.success("Time condition deleted")
      router.navigate({ to: "/call-routing", search: { tab: "time-conditions" } })
    } catch (err) {
      toast.error("Failed to delete time condition", {
        description: err instanceof Error ? err.message : undefined,
      })
    }
  }

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
                  {Array.from({ length: 4 }).map((_, i) => (
                    <div key={i} className="space-y-1.5">
                      <Skeleton className="h-3.5 w-20" />
                      <Skeleton className="h-5 w-36" />
                    </div>
                  ))}
                </div>
              </div>
            </div>
            <div className="space-y-4">
              <div className="rounded-xl border border-border/60 bg-card/80 p-6 space-y-4">
                <Skeleton className="h-5 w-24" />
                {Array.from({ length: 2 }).map((_, i) => (
                  <div key={i} className="space-y-1"><Skeleton className="h-3 w-20" /><Skeleton className="h-5 w-40" /></div>
                ))}
              </div>
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
        <PageHeader eyebrow="Call Routing" title="Time Condition" actions={<Button variant="outline" size="sm" asChild><Link to="/call-routing" search={{ tab: "time-conditions" }}><ArrowLeft className="mr-2 h-4 w-4" /> Back</Link></Button>} />
        <PageSection>
          <Card><CardHeader><CardTitle>Time condition detail</CardTitle></CardHeader><CardContent className="text-muted-foreground">We could not load this time condition.</CardContent></Card>
        </PageSection>
      </PageContainer>
    )
  }

  // Loaded
  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Call Routing"
        title={data.name}
        description="Time condition for schedule-based call routing"
        breadcrumbs={
          <Breadcrumb>
            <BreadcrumbList>
              <BreadcrumbItem><BreadcrumbLink asChild><Link to="/home">Home</Link></BreadcrumbLink></BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem><BreadcrumbLink asChild><Link to="/call-routing" search={{ tab: "time-conditions" }}>Call Routing</Link></BreadcrumbLink></BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem><BreadcrumbPage>{data.name}</BreadcrumbPage></BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
        actions={
          <div className="flex items-center gap-3">
            <Badge variant={data.overrideMode === "none" ? "outline" : "default"}>
              {overrideModeLabels[data.overrideMode] ?? data.overrideMode}
            </Badge>
            {!editing && (
              <Button variant="outline" size="sm" onClick={() => startEditing(data)}>
                <Pencil className="mr-2 h-4 w-4" /> Edit
              </Button>
            )}
            <Button variant="outline" size="sm" asChild>
              <Link to="/call-routing" search={{ tab: "time-conditions" }}>
                <ArrowLeft className="mr-2 h-4 w-4" /> Back
              </Link>
            </Button>
          </div>
        }
      />

      <PageSection>
        <div className="grid gap-6 md:grid-cols-[1.1fr_0.9fr]">
          {/* Main column */}
          <div className="space-y-6">
            {/* Configuration */}
            <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
              <CardHeader className="flex flex-row items-center justify-between">
                <CardTitle className="flex items-center gap-2">
                  <Clock className="h-5 w-5 text-muted-foreground" />
                  Configuration
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
                    <div className="space-y-2">
                      <Label>Name</Label>
                      <Input value={editName} onChange={(e) => setEditName(e.target.value)} />
                    </div>
                    <div className="space-y-2">
                      <Label>Match Destination</Label>
                      <Input value={editMatchDest} onChange={(e) => setEditMatchDest(e.target.value)} placeholder="e.g., ext:100" />
                    </div>
                    <div className="space-y-2">
                      <Label>No Match Destination</Label>
                      <Input value={editNoMatchDest} onChange={(e) => setEditNoMatchDest(e.target.value)} placeholder="e.g., voicemail:main" />
                    </div>
                    <div className="space-y-2">
                      <Label>Schedule ID</Label>
                      <Input value={editScheduleId} onChange={(e) => setEditScheduleId(e.target.value)} placeholder="Linked schedule UUID (optional)" />
                    </div>
                  </div>
                ) : (
                  <div className="grid gap-4 text-sm md:grid-cols-2">
                    <InfoField label="Name" value={data.name} />
                    <InfoField label="Match Destination" value={data.matchDestination} />
                    <InfoField label="No Match Destination" value={data.noMatchDestination} />
                    <InfoField label="Schedule ID" value={data.scheduleId} mono />
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Override Mode */}
            <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Clock className="h-5 w-5 text-muted-foreground" />
                  Night Mode Override
                </CardTitle>
                <CardDescription>
                  Override the normal schedule-based routing. Use this for emergencies or planned outages.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <p className="text-sm text-muted-foreground">{overrideModeDescriptions[data.overrideMode] ?? "Unknown mode."}</p>
                <div className="flex flex-wrap gap-2">
                  {Object.entries(overrideModeLabels).map(([mode, label]) => (
                    <Button
                      key={mode}
                      variant={data.overrideMode === mode ? "default" : "outline"}
                      size="sm"
                      onClick={() =>
                        overrideMutation.mutate(mode, {
                          onSuccess: () => {
                            toast.success("Override mode updated")
                          },
                          onError: (err) => {
                            toast.error("Failed to update override mode", {
                              description: err instanceof Error ? err.message : undefined,
                            })
                          },
                        })
                      }
                      disabled={overrideMutation.isPending || data.overrideMode === mode}
                    >
                      {overrideMutation.isPending && overrideMutation.variables === mode && <Loader2 className="mr-2 h-3 w-3 animate-spin" />}
                      {label}
                    </Button>
                  ))}
                </div>
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
                    <p className="font-medium text-sm">Delete this time condition</p>
                    <p className="text-xs text-muted-foreground">Once deleted, this time condition cannot be recovered.</p>
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
                <CardTitle className="flex items-center gap-2">
                  <Clock className="h-4 w-4" /> Metadata
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-1">
                  <p className="text-xs font-medium text-muted-foreground">Time Condition ID</p>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs break-all">{data.id}</span>
                    <CopyButton value={data.id} label="time condition ID" />
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
          </div>
        </div>
      </PageSection>

      <PageSection>
        <EntityActivityPanel
          targetType="time_condition"
          targetId={timeConditionId}
        />
      </PageSection>
    </PageContainer>
  )
}
