import { createFileRoute, Link, useRouter } from "@tanstack/react-router"
import { useCallback, useRef, useState } from "react"
import {
  AlertCircle,
  AlertTriangle,
  ArrowDown,
  ArrowLeft,
  ArrowUp,
  Loader2,
  Menu,
  Pencil,
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
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import {
  useIvrMenu,
  useUpdateIvrMenu,
  useDeleteIvrMenu,
  useCreateIvrMenuOption,
  useReorderIvrMenuOptions,
  useDeleteIvrMenuOption,
  type IvrMenu,
  type IvrMenuOption,
} from "@/lib/api/hooks/call-routing"
import { EntityActivityPanel } from "@/components/shared/entity-activity-panel"
import { useDocumentTitle } from "@/hooks/use-document-title"

export const Route = createFileRoute("/_app/call-routing/ivr-menus/$ivrMenuId")({
  component: IvrMenuDetailPage,
})

// -- Constants ----------------------------------------------------------------

const greetingTypeLabels: Record<string, string> = {
  none: "None",
  text: "Text-to-Speech",
  file: "Audio File",
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
              This will permanently delete this IVR menu and all its options. This action cannot be undone.
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

// -- Add Option Inline --------------------------------------------------------

function AddOptionRow({ menuId }: { menuId: string }) {
  const createOption = useCreateIvrMenuOption(menuId)
  const [adding, setAdding] = useState(false)
  const [digit, setDigit] = useState("")
  const [label, setLabel] = useState("")
  const [destination, setDestination] = useState("")

  const handleSave = () => {
    if (!digit.trim() || !label.trim() || !destination.trim()) return
    createOption.mutate(
      { digit: digit.trim(), label: label.trim(), destination: destination.trim() },
      {
        onSuccess: () => {
          setAdding(false)
          setDigit("")
          setLabel("")
          setDestination("")
        },
      },
    )
  }

  if (!adding) {
    return (
      <Button variant="outline" size="sm" onClick={() => setAdding(true)}>
        <Plus className="mr-2 h-4 w-4" /> Add option
      </Button>
    )
  }

  return (
    <div className="space-y-3 rounded-lg border border-border/60 bg-muted/20 p-4">
      <div className="grid gap-3 sm:grid-cols-3">
        <div className="space-y-2">
          <Label>Digit</Label>
          <Input placeholder="e.g., 1" value={digit} onChange={(e) => setDigit(e.target.value)} maxLength={2} />
        </div>
        <div className="space-y-2">
          <Label>Label</Label>
          <Input placeholder="e.g., Sales" value={label} onChange={(e) => setLabel(e.target.value)} />
        </div>
        <div className="space-y-2">
          <Label>Destination</Label>
          <Input placeholder="e.g., ext:100" value={destination} onChange={(e) => setDestination(e.target.value)} />
        </div>
      </div>
      <div className="flex items-center gap-2">
        <Button size="sm" onClick={handleSave} disabled={!digit.trim() || !label.trim() || !destination.trim() || createOption.isPending}>
          {createOption.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
          Add
        </Button>
        <Button variant="ghost" size="sm" onClick={() => setAdding(false)}>Cancel</Button>
      </div>
    </div>
  )
}

// -- Option Row ---------------------------------------------------------------

function OptionRow({
  option,
  menuId,
  isFirst,
  isLast,
  isHighlighted,
  onMoveUp,
  onMoveDown,
  isReordering,
}: {
  option: IvrMenuOption
  menuId: string
  isFirst: boolean
  isLast: boolean
  isHighlighted: boolean
  onMoveUp: () => void
  onMoveDown: () => void
  isReordering: boolean
}) {
  const deleteOption = useDeleteIvrMenuOption(menuId)
  const [confirmDelete, setConfirmDelete] = useState(false)
  return (
    <TableRow className={isHighlighted ? "animate-highlight-row" : ""}>
      <TableCell>
        <span className="flex h-7 w-7 items-center justify-center rounded-full bg-muted font-mono text-xs font-medium">
          {option.digit}
        </span>
      </TableCell>
      <TableCell><span className="text-sm font-medium">{option.label}</span></TableCell>
      <TableCell><span className="text-sm text-muted-foreground">{option.destination}</span></TableCell>
      <TableCell>
        <div className="flex items-center justify-end gap-0.5">
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7 text-muted-foreground"
            onClick={onMoveUp}
            disabled={isFirst || isReordering}
            aria-label="Move up"
          >
            <ArrowUp className="h-3.5 w-3.5" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7 text-muted-foreground"
            onClick={onMoveDown}
            disabled={isLast || isReordering}
            aria-label="Move down"
          >
            <ArrowDown className="h-3.5 w-3.5" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7 text-muted-foreground hover:text-destructive"
            onClick={() => setConfirmDelete(true)}
            disabled={deleteOption.isPending}
            aria-label="Delete option"
          >
            {deleteOption.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
          </Button>
        </div>
        <AlertDialog open={confirmDelete} onOpenChange={(open) => !open && setConfirmDelete(false)}>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle className="flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-destructive" /> Delete menu option?
              </AlertDialogTitle>
              <AlertDialogDescription>
                This will permanently remove option "{option.digit} - {option.label}" from the menu. This action cannot be undone.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel disabled={deleteOption.isPending}>Cancel</AlertDialogCancel>
              <AlertDialogAction
                className={buttonVariants({ variant: "destructive" })}
                onClick={() => {
                  deleteOption.mutate(option.id, { onSuccess: () => setConfirmDelete(false) })
                }}
                disabled={deleteOption.isPending}
              >
                {deleteOption.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                {deleteOption.isPending ? "Deleting..." : "Delete"}
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
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

function IvrMenuDetailPage() {
  const { ivrMenuId } = Route.useParams()
  const router = useRouter()

  const { data, isLoading, isError, refetch } = useIvrMenu(ivrMenuId)
  const updateMutation = useUpdateIvrMenu(ivrMenuId)
  const deleteMutation = useDeleteIvrMenu()

  const [editing, setEditing] = useState(false)
  const [editName, setEditName] = useState("")
  const [editGreetingType, setEditGreetingType] = useState("none")
  const [editGreetingText, setEditGreetingText] = useState("")
  const [editTimeout, setEditTimeout] = useState(5)
  const [editMaxRetries, setEditMaxRetries] = useState(3)
  const [editTimeoutDest, setEditTimeoutDest] = useState("")
  const [editInvalidDest, setEditInvalidDest] = useState("")

  useDocumentTitle(data ? `${data.name} - IVR Menus` : "IVR Menu Detail")

  function startEditing(ivr: IvrMenu) {
    setEditName(ivr.name)
    setEditGreetingType(ivr.greetingType)
    setEditGreetingText(ivr.greetingText ?? "")
    setEditTimeout(ivr.timeoutSeconds)
    setEditMaxRetries(ivr.maxRetries)
    setEditTimeoutDest(ivr.timeoutDestination ?? "")
    setEditInvalidDest(ivr.invalidDestination ?? "")
    setEditing(true)
  }

  function handleSave() {
    const payload: Record<string, unknown> = {}
    if (editName !== data?.name) payload.name = editName
    if (editGreetingType !== data?.greetingType) payload.greetingType = editGreetingType
    if (editGreetingText !== (data?.greetingText ?? "")) payload.greetingText = editGreetingText || null
    if (editTimeout !== data?.timeoutSeconds) payload.timeoutSeconds = editTimeout
    if (editMaxRetries !== data?.maxRetries) payload.maxRetries = editMaxRetries
    if (editTimeoutDest !== (data?.timeoutDestination ?? "")) payload.timeoutDestination = editTimeoutDest || null
    if (editInvalidDest !== (data?.invalidDestination ?? "")) payload.invalidDestination = editInvalidDest || null
    updateMutation.mutate(payload, { onSuccess: () => setEditing(false) })
  }

  const handleDelete = async () => {
    await deleteMutation.mutateAsync(ivrMenuId)
    router.navigate({ to: "/call-routing", search: { tab: "ivr-menus" } })
  }

  const [highlightedId, setHighlightedId] = useState<string | null>(null)
  const highlightTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const reorderMutation = useReorderIvrMenuOptions(ivrMenuId)

  const options = data?.options ?? []
  const sortedOptions = [...options].sort((a, b) => a.sortOrder - b.sortOrder)

  const handleReorder = useCallback(
    (index: number, direction: "up" | "down") => {
      const swapIndex = direction === "up" ? index - 1 : index + 1
      if (swapIndex < 0 || swapIndex >= sortedOptions.length) return

      const optA = sortedOptions[index]
      const optB = sortedOptions[swapIndex]

      reorderMutation.mutate(
        {
          optionA: { id: optA.id, sortOrder: optA.sortOrder },
          optionB: { id: optB.id, sortOrder: optB.sortOrder },
        },
        {
          onSuccess: () => {
            if (highlightTimer.current) clearTimeout(highlightTimer.current)
            setHighlightedId(optA.id)
            highlightTimer.current = setTimeout(() => setHighlightedId(null), 700)
          },
        },
      )
    },
    [sortedOptions, reorderMutation],
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
                  {Array.from({ length: 6 }).map((_, i) => <div key={i} className="space-y-1.5"><Skeleton className="h-3.5 w-20" /><Skeleton className="h-5 w-36" /></div>)}
                </div>
              </div>
              <div className="rounded-xl border border-border/60 bg-card/80 p-6 space-y-4">
                <Skeleton className="h-6 w-24" />
                {Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}
              </div>
            </div>
            <div className="rounded-xl border border-border/60 bg-card/80 p-6 space-y-4">
              <Skeleton className="h-5 w-24" />
              {Array.from({ length: 2 }).map((_, i) => <div key={i} className="space-y-1"><Skeleton className="h-3 w-20" /><Skeleton className="h-5 w-40" /></div>)}
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
        <PageHeader eyebrow="Call Routing" title="IVR Menu" actions={<Button variant="outline" size="sm" asChild><Link to="/call-routing" search={{ tab: "ivr-menus" }}><ArrowLeft className="mr-2 h-4 w-4" /> Back</Link></Button>} />
        <PageSection>
          <EmptyState
            icon={AlertCircle}
            title="Unable to load IVR menu"
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
        description="Interactive voice response menu"
        breadcrumbs={
          <Breadcrumb>
            <BreadcrumbList>
              <BreadcrumbItem><BreadcrumbLink asChild><Link to="/home">Home</Link></BreadcrumbLink></BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem><BreadcrumbLink asChild><Link to="/call-routing" search={{ tab: "ivr-menus" }}>Call Routing</Link></BreadcrumbLink></BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem><BreadcrumbPage>{data.name}</BreadcrumbPage></BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
        actions={
          <div className="flex items-center gap-3">
            <Badge variant="outline">{options.length} option{options.length === 1 ? "" : "s"}</Badge>
            {!editing && (
              <Button variant="outline" size="sm" onClick={() => startEditing(data)}>
                <Pencil className="mr-2 h-4 w-4" /> Edit
              </Button>
            )}
            <Button variant="outline" size="sm" asChild>
              <Link to="/call-routing" search={{ tab: "ivr-menus" }}>
                <ArrowLeft className="mr-2 h-4 w-4" /> Back
              </Link>
            </Button>
          </div>
        }
      />

      <PageSection>
        <div className="grid gap-6 md:grid-cols-[1.1fr_0.9fr]">
          <div className="space-y-6">
            {/* Menu Configuration */}
            <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
              <CardHeader className="flex flex-row items-center justify-between">
                <CardTitle className="flex items-center gap-2">
                  <Menu className="h-5 w-5 text-muted-foreground" />
                  Menu Configuration
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
                      <Label>Greeting Type</Label>
                      <Select value={editGreetingType} onValueChange={setEditGreetingType}>
                        <SelectTrigger><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="none">None</SelectItem>
                          <SelectItem value="text">Text-to-Speech</SelectItem>
                          <SelectItem value="file">Audio File</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    {editGreetingType === "text" && (
                      <div className="space-y-2">
                        <Label>Greeting Text</Label>
                        <Input value={editGreetingText} onChange={(e) => setEditGreetingText(e.target.value)} placeholder="Enter greeting text..." />
                      </div>
                    )}
                    <div className="grid gap-4 sm:grid-cols-2">
                      <div className="space-y-2">
                        <Label>Timeout (seconds)</Label>
                        <Input type="number" value={editTimeout} onChange={(e) => setEditTimeout(Number(e.target.value))} min={1} max={60} />
                      </div>
                      <div className="space-y-2">
                        <Label>Max Retries</Label>
                        <Input type="number" value={editMaxRetries} onChange={(e) => setEditMaxRetries(Number(e.target.value))} min={0} max={10} />
                      </div>
                    </div>
                    <div className="space-y-2">
                      <Label>Timeout Destination</Label>
                      <Input value={editTimeoutDest} onChange={(e) => setEditTimeoutDest(e.target.value)} placeholder="Destination on timeout (optional)" />
                    </div>
                    <div className="space-y-2">
                      <Label>Invalid Destination</Label>
                      <Input value={editInvalidDest} onChange={(e) => setEditInvalidDest(e.target.value)} placeholder="Destination on invalid input (optional)" />
                    </div>
                  </div>
                ) : (
                  <div className="grid gap-4 text-sm md:grid-cols-2">
                    <InfoField label="Name" value={data.name} />
                    <InfoField label="Greeting Type" value={greetingTypeLabels[data.greetingType] ?? data.greetingType} />
                    {data.greetingType === "text" && <InfoField label="Greeting Text" value={data.greetingText} />}
                    <InfoField label="Timeout" value={`${data.timeoutSeconds}s`} />
                    <InfoField label="Max Retries" value={data.maxRetries} />
                    <InfoField label="Timeout Destination" value={data.timeoutDestination} />
                    <InfoField label="Invalid Destination" value={data.invalidDestination} />
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Options */}
            <Card className="border-border/60 bg-card/80 shadow-md shadow-primary/10">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Menu className="h-5 w-5 text-muted-foreground" />
                  Menu Options
                </CardTitle>
                <CardDescription>Define the key-press options available to callers.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {sortedOptions.length > 0 ? (
                  <div className="overflow-x-auto">
                  <Table aria-label="IVR menu options">
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-16">Digit</TableHead>
                        <TableHead>Label</TableHead>
                        <TableHead>Destination</TableHead>
                        <TableHead className="w-28 text-right">Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {sortedOptions.map((opt, idx) => (
                        <OptionRow
                          key={opt.id}
                          option={opt}
                          menuId={ivrMenuId}
                          isFirst={idx === 0}
                          isLast={idx === sortedOptions.length - 1}
                          isHighlighted={highlightedId === opt.id}
                          isReordering={reorderMutation.isPending}
                          onMoveUp={() => handleReorder(idx, "up")}
                          onMoveDown={() => handleReorder(idx, "down")}
                        />
                      ))}
                    </TableBody>
                  </Table>
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground py-4 text-center">No options configured.</p>
                )}
                <AddOptionRow menuId={ivrMenuId} />
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
                    <p className="font-medium text-sm">Delete this IVR menu</p>
                    <p className="text-xs text-muted-foreground">Once deleted, this IVR menu and all its options cannot be recovered.</p>
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
                <CardTitle className="flex items-center gap-2"><Menu className="h-4 w-4" /> Metadata</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-1">
                  <p className="text-xs font-medium text-muted-foreground">IVR Menu ID</p>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs break-all">{data.id}</span>
                    <CopyButton value={data.id} label="IVR menu ID" />
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
                <CardTitle className="flex items-center gap-2"><Menu className="h-4 w-4" /> Summary</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Options count</span>
                  <span className="font-medium text-sm">{options.length}</span>
                </div>
                <Separator />
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Greeting type</span>
                  <span className="font-medium text-sm">{greetingTypeLabels[data.greetingType] ?? data.greetingType}</span>
                </div>
                <Separator />
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Timeout</span>
                  <span className="font-medium text-sm">{data.timeoutSeconds}s</span>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </PageSection>

      <PageSection>
        <EntityActivityPanel
          targetType="ivr_menu"
          targetId={ivrMenuId}
        />
      </PageSection>
    </PageContainer>
  )
}
