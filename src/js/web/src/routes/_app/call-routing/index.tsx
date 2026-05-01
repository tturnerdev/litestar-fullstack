import { createFileRoute, Link, useNavigate } from "@tanstack/react-router"
import { useCallback, useEffect, useState } from "react"
import {
  AlertCircle,
  Clock,
  Home,
  Loader2,
  Menu,
  Phone,
  Plus,
  Search,
  Users,
  X,
} from "lucide-react"
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { SkeletonTable } from "@/components/ui/skeleton"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import {
  useTimeConditions,
  useCreateTimeCondition,
  useIvrMenus,
  useCreateIvrMenu,
  useCallQueues,
  useCreateCallQueue,
  useRingGroups,
  useCreateRingGroup,
  type TimeCondition,
  type IvrMenu,
  type CallQueue,
  type RingGroup,
} from "@/lib/api/hooks/call-routing"
import { useDebouncedValue } from "@/hooks/use-debounced-value"
import { useDocumentTitle } from "@/hooks/use-document-title"

// ---------------------------------------------------------------------------
// Route definition
// ---------------------------------------------------------------------------

export const Route = createFileRoute("/_app/call-routing/")({
  component: CallRoutingPage,
  validateSearch: (search: Record<string, unknown>): { tab?: string } => ({
    tab: (search.tab as string) || undefined,
  }),
})

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const strategyLabels: Record<string, string> = {
  ring_all: "Ring All",
  round_robin: "Round Robin",
  least_recent: "Least Recent",
  fewest_calls: "Fewest Calls",
  random: "Random",
  linear: "Linear",
  weight_random: "Weighted Random",
}

const overrideModeLabels: Record<string, string> = {
  none: "None",
  force_match: "Force Match",
  force_no_match: "Force No Match",
}

// ---------------------------------------------------------------------------
// New entity dialogs
// ---------------------------------------------------------------------------

function NewTimeConditionDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const navigate = useNavigate()
  const create = useCreateTimeCondition()
  const [name, setName] = useState("")
  const [matchDest, setMatchDest] = useState("")
  const [noMatchDest, setNoMatchDest] = useState("")

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!name.trim()) return
    create.mutate(
      { name: name.trim(), matchDestination: matchDest.trim(), noMatchDestination: noMatchDest.trim() },
      {
        onSuccess: (data) => {
          onOpenChange(false)
          setName("")
          setMatchDest("")
          setNoMatchDest("")
          navigate({ to: "/call-routing/time-conditions/$timeConditionId", params: { timeConditionId: data.id } })
        },
      },
    )
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New Time Condition</DialogTitle>
          <DialogDescription>Create a new time condition for call routing based on schedules.</DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="tc-name">Name</Label>
            <Input id="tc-name" placeholder="e.g., Business Hours Check" value={name} onChange={(e) => setName(e.target.value)} required />
          </div>
          <div className="space-y-2">
            <Label htmlFor="tc-match">Match Destination</Label>
            <Input id="tc-match" placeholder="e.g., ext:100" value={matchDest} onChange={(e) => setMatchDest(e.target.value)} required />
          </div>
          <div className="space-y-2">
            <Label htmlFor="tc-nomatch">No Match Destination</Label>
            <Input id="tc-nomatch" placeholder="e.g., voicemail:main" value={noMatchDest} onChange={(e) => setNoMatchDest(e.target.value)} required />
          </div>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>Cancel</Button>
            <Button type="submit" disabled={!name.trim() || !matchDest.trim() || !noMatchDest.trim() || create.isPending}>
              {create.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Create
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function NewIvrMenuDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const navigate = useNavigate()
  const create = useCreateIvrMenu()
  const [name, setName] = useState("")

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!name.trim()) return
    create.mutate(
      { name: name.trim() },
      {
        onSuccess: (data) => {
          onOpenChange(false)
          setName("")
          navigate({ to: "/call-routing/ivr-menus/$ivrMenuId", params: { ivrMenuId: data.id } })
        },
      },
    )
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New IVR Menu</DialogTitle>
          <DialogDescription>Create an interactive voice response menu for callers.</DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="ivr-name">Name</Label>
            <Input id="ivr-name" placeholder="e.g., Main Auto Attendant" value={name} onChange={(e) => setName(e.target.value)} required />
          </div>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>Cancel</Button>
            <Button type="submit" disabled={!name.trim() || create.isPending}>
              {create.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Create
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function NewCallQueueDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const navigate = useNavigate()
  const create = useCreateCallQueue()
  const [name, setName] = useState("")
  const [number, setNumber] = useState("")
  const [strategy, setStrategy] = useState("ring_all")

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!name.trim() || !number.trim()) return
    create.mutate(
      { name: name.trim(), number: number.trim(), strategy },
      {
        onSuccess: (data) => {
          onOpenChange(false)
          setName("")
          setNumber("")
          setStrategy("ring_all")
          navigate({ to: "/call-routing/call-queues/$callQueueId", params: { callQueueId: data.id } })
        },
      },
    )
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New Call Queue</DialogTitle>
          <DialogDescription>Create a call queue to distribute incoming calls among agents.</DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="cq-name">Name</Label>
            <Input id="cq-name" placeholder="e.g., Support Queue" value={name} onChange={(e) => setName(e.target.value)} required />
          </div>
          <div className="space-y-2">
            <Label htmlFor="cq-number">Number</Label>
            <Input id="cq-number" placeholder="e.g., 400" value={number} onChange={(e) => setNumber(e.target.value)} required />
          </div>
          <div className="space-y-2">
            <Label htmlFor="cq-strategy">Strategy</Label>
            <Select value={strategy} onValueChange={setStrategy}>
              <SelectTrigger id="cq-strategy"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="ring_all">Ring All</SelectItem>
                <SelectItem value="round_robin">Round Robin</SelectItem>
                <SelectItem value="least_recent">Least Recent</SelectItem>
                <SelectItem value="fewest_calls">Fewest Calls</SelectItem>
                <SelectItem value="random">Random</SelectItem>
                <SelectItem value="linear">Linear</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>Cancel</Button>
            <Button type="submit" disabled={!name.trim() || !number.trim() || create.isPending}>
              {create.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Create
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function NewRingGroupDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const navigate = useNavigate()
  const create = useCreateRingGroup()
  const [name, setName] = useState("")
  const [number, setNumber] = useState("")
  const [strategy, setStrategy] = useState("ring_all")

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!name.trim() || !number.trim()) return
    create.mutate(
      { name: name.trim(), number: number.trim(), strategy },
      {
        onSuccess: (data) => {
          onOpenChange(false)
          setName("")
          setNumber("")
          setStrategy("ring_all")
          navigate({ to: "/call-routing/ring-groups/$ringGroupId", params: { ringGroupId: data.id } })
        },
      },
    )
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New Ring Group</DialogTitle>
          <DialogDescription>Create a ring group to ring multiple extensions simultaneously or in sequence.</DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="rg-name">Name</Label>
            <Input id="rg-name" placeholder="e.g., Sales Team" value={name} onChange={(e) => setName(e.target.value)} required />
          </div>
          <div className="space-y-2">
            <Label htmlFor="rg-number">Number</Label>
            <Input id="rg-number" placeholder="e.g., 600" value={number} onChange={(e) => setNumber(e.target.value)} required />
          </div>
          <div className="space-y-2">
            <Label htmlFor="rg-strategy">Strategy</Label>
            <Select value={strategy} onValueChange={setStrategy}>
              <SelectTrigger id="rg-strategy"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="ring_all">Ring All</SelectItem>
                <SelectItem value="round_robin">Round Robin</SelectItem>
                <SelectItem value="linear">Linear</SelectItem>
                <SelectItem value="random">Random</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>Cancel</Button>
            <Button type="submit" disabled={!name.trim() || !number.trim() || create.isPending}>
              {create.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Create
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

// ---------------------------------------------------------------------------
// Tab content components
// ---------------------------------------------------------------------------

function TimeConditionsTab() {
  const navigate = useNavigate()
  const [search, setSearch] = useState("")
  const debouncedSearch = useDebouncedValue(search)
  const [page, setPage] = useState(1)
  const [dialogOpen, setDialogOpen] = useState(false)

  useEffect(() => { setPage(1) }, [debouncedSearch])

  const { data, isLoading, isError, refetch } = useTimeConditions({
    page, pageSize: 25, search: debouncedSearch || undefined,
  })

  const items = data?.items ?? []
  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / 25))

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <div className="relative max-w-sm flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input placeholder="Search time conditions..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-9 pr-8" />
          {search && (
            <button type="button" onClick={() => setSearch("")} className="absolute right-2 top-1/2 -translate-y-1/2 rounded-sm p-0.5 text-muted-foreground hover:text-foreground">
              <X className="h-3.5 w-3.5" /><span className="sr-only">Clear search</span>
            </button>
          )}
        </div>
        <Button size="sm" onClick={() => setDialogOpen(true)}>
          <Plus className="mr-2 h-4 w-4" /> New
        </Button>
      </div>

      {isLoading ? (
        <SkeletonTable rows={5} />
      ) : isError ? (
        <EmptyState icon={AlertCircle} title="Unable to load time conditions" description="Something went wrong. Please try again." action={<Button variant="outline" size="sm" onClick={() => refetch()}>Try again</Button>} />
      ) : items.length === 0 ? (
        <EmptyState icon={Clock} title={search ? "No results found" : "No time conditions yet"} description={search ? "No time conditions match your search." : "Create a time condition to route calls based on schedules."} variant={search ? "no-results" : undefined} action={search ? <Button variant="outline" size="sm" onClick={() => setSearch("")}>Clear search</Button> : <Button size="sm" onClick={() => setDialogOpen(true)}><Plus className="mr-2 h-4 w-4" /> New time condition</Button>} />
      ) : (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-xs text-muted-foreground">{total} time condition{total === 1 ? "" : "s"}{search && " (filtered)"}</p>
            {totalPages > 1 && <p className="text-xs text-muted-foreground">Page {page} of {totalPages}</p>}
          </div>
          <div className="overflow-x-auto rounded-md border border-border/60 bg-card/80">
            <Table aria-label="Time Conditions">
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Match Destination</TableHead>
                  <TableHead>No Match Destination</TableHead>
                  <TableHead>Override</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((tc: TimeCondition) => (
                  <TableRow key={tc.id} className="cursor-pointer hover:bg-muted/50 transition-colors" onClick={() => navigate({ to: "/call-routing/time-conditions/$timeConditionId", params: { timeConditionId: tc.id } })}>
                    <TableCell>
                      <Link to="/call-routing/time-conditions/$timeConditionId" params={{ timeConditionId: tc.id }} className="group flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
                        <Clock className="h-4 w-4 text-muted-foreground" />
                        <span className="font-medium group-hover:underline">{tc.name}</span>
                      </Link>
                    </TableCell>
                    <TableCell><span className="text-sm text-muted-foreground">{tc.matchDestination || "---"}</span></TableCell>
                    <TableCell><span className="text-sm text-muted-foreground">{tc.noMatchDestination || "---"}</span></TableCell>
                    <TableCell>
                      <Badge variant={tc.overrideMode === "none" ? "outline" : "default"}>
                        {overrideModeLabels[tc.overrideMode] ?? tc.overrideMode}
                      </Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          {totalPages > 1 && (
            <div className="flex items-center justify-end gap-2">
              <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page <= 1}>Previous</Button>
              <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page >= totalPages}>Next</Button>
            </div>
          )}
        </div>
      )}

      <NewTimeConditionDialog open={dialogOpen} onOpenChange={setDialogOpen} />
    </div>
  )
}

function IvrMenusTab() {
  const navigate = useNavigate()
  const [search, setSearch] = useState("")
  const debouncedSearch = useDebouncedValue(search)
  const [page, setPage] = useState(1)
  const [dialogOpen, setDialogOpen] = useState(false)

  useEffect(() => { setPage(1) }, [debouncedSearch])

  const { data, isLoading, isError, refetch } = useIvrMenus({
    page, pageSize: 25, search: debouncedSearch || undefined,
  })

  const items = data?.items ?? []
  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / 25))

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <div className="relative max-w-sm flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input placeholder="Search IVR menus..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-9 pr-8" />
          {search && (
            <button type="button" onClick={() => setSearch("")} className="absolute right-2 top-1/2 -translate-y-1/2 rounded-sm p-0.5 text-muted-foreground hover:text-foreground">
              <X className="h-3.5 w-3.5" /><span className="sr-only">Clear search</span>
            </button>
          )}
        </div>
        <Button size="sm" onClick={() => setDialogOpen(true)}>
          <Plus className="mr-2 h-4 w-4" /> New
        </Button>
      </div>

      {isLoading ? (
        <SkeletonTable rows={5} />
      ) : isError ? (
        <EmptyState icon={AlertCircle} title="Unable to load IVR menus" description="Something went wrong. Please try again." action={<Button variant="outline" size="sm" onClick={() => refetch()}>Try again</Button>} />
      ) : items.length === 0 ? (
        <EmptyState icon={Menu} title={search ? "No results found" : "No IVR menus yet"} description={search ? "No IVR menus match your search." : "Create an IVR menu to build interactive call menus."} variant={search ? "no-results" : undefined} action={search ? <Button variant="outline" size="sm" onClick={() => setSearch("")}>Clear search</Button> : <Button size="sm" onClick={() => setDialogOpen(true)}><Plus className="mr-2 h-4 w-4" /> New IVR menu</Button>} />
      ) : (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-xs text-muted-foreground">{total} IVR menu{total === 1 ? "" : "s"}{search && " (filtered)"}</p>
            {totalPages > 1 && <p className="text-xs text-muted-foreground">Page {page} of {totalPages}</p>}
          </div>
          <div className="overflow-x-auto rounded-md border border-border/60 bg-card/80">
            <Table aria-label="IVR Menus">
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Greeting</TableHead>
                  <TableHead>Options</TableHead>
                  <TableHead>Timeout</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((ivr: IvrMenu) => (
                  <TableRow key={ivr.id} className="cursor-pointer hover:bg-muted/50 transition-colors" onClick={() => navigate({ to: "/call-routing/ivr-menus/$ivrMenuId", params: { ivrMenuId: ivr.id } })}>
                    <TableCell>
                      <Link to="/call-routing/ivr-menus/$ivrMenuId" params={{ ivrMenuId: ivr.id }} className="group flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
                        <Menu className="h-4 w-4 text-muted-foreground" />
                        <span className="font-medium group-hover:underline">{ivr.name}</span>
                      </Link>
                    </TableCell>
                    <TableCell><Badge variant="outline">{ivr.greetingType}</Badge></TableCell>
                    <TableCell><span className="text-sm text-muted-foreground">{ivr.options?.length ?? 0} option{(ivr.options?.length ?? 0) === 1 ? "" : "s"}</span></TableCell>
                    <TableCell><span className="text-sm text-muted-foreground">{ivr.timeoutSeconds}s</span></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          {totalPages > 1 && (
            <div className="flex items-center justify-end gap-2">
              <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page <= 1}>Previous</Button>
              <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page >= totalPages}>Next</Button>
            </div>
          )}
        </div>
      )}

      <NewIvrMenuDialog open={dialogOpen} onOpenChange={setDialogOpen} />
    </div>
  )
}

function CallQueuesTab() {
  const navigate = useNavigate()
  const [search, setSearch] = useState("")
  const debouncedSearch = useDebouncedValue(search)
  const [page, setPage] = useState(1)
  const [dialogOpen, setDialogOpen] = useState(false)

  useEffect(() => { setPage(1) }, [debouncedSearch])

  const { data, isLoading, isError, refetch } = useCallQueues({
    page, pageSize: 25, search: debouncedSearch || undefined,
  })

  const items = data?.items ?? []
  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / 25))

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <div className="relative max-w-sm flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input placeholder="Search call queues..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-9 pr-8" />
          {search && (
            <button type="button" onClick={() => setSearch("")} className="absolute right-2 top-1/2 -translate-y-1/2 rounded-sm p-0.5 text-muted-foreground hover:text-foreground">
              <X className="h-3.5 w-3.5" /><span className="sr-only">Clear search</span>
            </button>
          )}
        </div>
        <Button size="sm" onClick={() => setDialogOpen(true)}>
          <Plus className="mr-2 h-4 w-4" /> New
        </Button>
      </div>

      {isLoading ? (
        <SkeletonTable rows={5} />
      ) : isError ? (
        <EmptyState icon={AlertCircle} title="Unable to load call queues" description="Something went wrong. Please try again." action={<Button variant="outline" size="sm" onClick={() => refetch()}>Try again</Button>} />
      ) : items.length === 0 ? (
        <EmptyState icon={Phone} title={search ? "No results found" : "No call queues yet"} description={search ? "No call queues match your search." : "Create a call queue to distribute calls among agents."} variant={search ? "no-results" : undefined} action={search ? <Button variant="outline" size="sm" onClick={() => setSearch("")}>Clear search</Button> : <Button size="sm" onClick={() => setDialogOpen(true)}><Plus className="mr-2 h-4 w-4" /> New call queue</Button>} />
      ) : (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-xs text-muted-foreground">{total} call queue{total === 1 ? "" : "s"}{search && " (filtered)"}</p>
            {totalPages > 1 && <p className="text-xs text-muted-foreground">Page {page} of {totalPages}</p>}
          </div>
          <div className="overflow-x-auto rounded-md border border-border/60 bg-card/80">
            <Table aria-label="Call Queues">
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Number</TableHead>
                  <TableHead>Strategy</TableHead>
                  <TableHead>Members</TableHead>
                  <TableHead>Ring Time</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((q: CallQueue) => (
                  <TableRow key={q.id} className="cursor-pointer hover:bg-muted/50 transition-colors" onClick={() => navigate({ to: "/call-routing/call-queues/$callQueueId", params: { callQueueId: q.id } })}>
                    <TableCell>
                      <Link to="/call-routing/call-queues/$callQueueId" params={{ callQueueId: q.id }} className="group flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
                        <Phone className="h-4 w-4 text-muted-foreground" />
                        <span className="font-medium group-hover:underline">{q.name}</span>
                      </Link>
                    </TableCell>
                    <TableCell><span className="font-mono text-sm text-muted-foreground">{q.number}</span></TableCell>
                    <TableCell><Badge variant="outline">{strategyLabels[q.strategy] ?? q.strategy}</Badge></TableCell>
                    <TableCell><span className="text-sm text-muted-foreground">{q.members?.length ?? 0}</span></TableCell>
                    <TableCell><span className="text-sm text-muted-foreground">{q.ringTime}s</span></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          {totalPages > 1 && (
            <div className="flex items-center justify-end gap-2">
              <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page <= 1}>Previous</Button>
              <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page >= totalPages}>Next</Button>
            </div>
          )}
        </div>
      )}

      <NewCallQueueDialog open={dialogOpen} onOpenChange={setDialogOpen} />
    </div>
  )
}

function RingGroupsTab() {
  const navigate = useNavigate()
  const [search, setSearch] = useState("")
  const debouncedSearch = useDebouncedValue(search)
  const [page, setPage] = useState(1)
  const [dialogOpen, setDialogOpen] = useState(false)

  useEffect(() => { setPage(1) }, [debouncedSearch])

  const { data, isLoading, isError, refetch } = useRingGroups({
    page, pageSize: 25, search: debouncedSearch || undefined,
  })

  const items = data?.items ?? []
  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / 25))

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <div className="relative max-w-sm flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input placeholder="Search ring groups..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-9 pr-8" />
          {search && (
            <button type="button" onClick={() => setSearch("")} className="absolute right-2 top-1/2 -translate-y-1/2 rounded-sm p-0.5 text-muted-foreground hover:text-foreground">
              <X className="h-3.5 w-3.5" /><span className="sr-only">Clear search</span>
            </button>
          )}
        </div>
        <Button size="sm" onClick={() => setDialogOpen(true)}>
          <Plus className="mr-2 h-4 w-4" /> New
        </Button>
      </div>

      {isLoading ? (
        <SkeletonTable rows={5} />
      ) : isError ? (
        <EmptyState icon={AlertCircle} title="Unable to load ring groups" description="Something went wrong. Please try again." action={<Button variant="outline" size="sm" onClick={() => refetch()}>Try again</Button>} />
      ) : items.length === 0 ? (
        <EmptyState icon={Users} title={search ? "No results found" : "No ring groups yet"} description={search ? "No ring groups match your search." : "Create a ring group to ring multiple extensions."} variant={search ? "no-results" : undefined} action={search ? <Button variant="outline" size="sm" onClick={() => setSearch("")}>Clear search</Button> : <Button size="sm" onClick={() => setDialogOpen(true)}><Plus className="mr-2 h-4 w-4" /> New ring group</Button>} />
      ) : (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-xs text-muted-foreground">{total} ring group{total === 1 ? "" : "s"}{search && " (filtered)"}</p>
            {totalPages > 1 && <p className="text-xs text-muted-foreground">Page {page} of {totalPages}</p>}
          </div>
          <div className="overflow-x-auto rounded-md border border-border/60 bg-card/80">
            <Table aria-label="Ring Groups">
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Number</TableHead>
                  <TableHead>Strategy</TableHead>
                  <TableHead>Members</TableHead>
                  <TableHead>Ring Time</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((rg: RingGroup) => (
                  <TableRow key={rg.id} className="cursor-pointer hover:bg-muted/50 transition-colors" onClick={() => navigate({ to: "/call-routing/ring-groups/$ringGroupId", params: { ringGroupId: rg.id } })}>
                    <TableCell>
                      <Link to="/call-routing/ring-groups/$ringGroupId" params={{ ringGroupId: rg.id }} className="group flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
                        <Users className="h-4 w-4 text-muted-foreground" />
                        <span className="font-medium group-hover:underline">{rg.name}</span>
                      </Link>
                    </TableCell>
                    <TableCell><span className="font-mono text-sm text-muted-foreground">{rg.number}</span></TableCell>
                    <TableCell><Badge variant="outline">{strategyLabels[rg.strategy] ?? rg.strategy}</Badge></TableCell>
                    <TableCell><span className="text-sm text-muted-foreground">{rg.members?.length ?? 0}</span></TableCell>
                    <TableCell><span className="text-sm text-muted-foreground">{rg.ringTime}s</span></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          {totalPages > 1 && (
            <div className="flex items-center justify-end gap-2">
              <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page <= 1}>Previous</Button>
              <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page >= totalPages}>Next</Button>
            </div>
          )}
        </div>
      )}

      <NewRingGroupDialog open={dialogOpen} onOpenChange={setDialogOpen} />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

function CallRoutingPage() {
  useDocumentTitle("Call Routing")

  const { tab = "time-conditions" } = Route.useSearch()
  const navigate = Route.useNavigate()

  const setTab = useCallback(
    (value: string) => {
      navigate({ search: () => ({ tab: value }), replace: true })
    },
    [navigate],
  )

  const breadcrumbs = (
    <Breadcrumb>
      <BreadcrumbList>
        <BreadcrumbItem>
          <BreadcrumbLink asChild>
            <Link to="/">
              <Home className="h-3.5 w-3.5" />
            </Link>
          </BreadcrumbLink>
        </BreadcrumbItem>
        <BreadcrumbSeparator />
        <BreadcrumbItem>
          <BreadcrumbPage>Call Routing</BreadcrumbPage>
        </BreadcrumbItem>
      </BreadcrumbList>
    </Breadcrumb>
  )

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Workspace"
        title="Call Routing"
        description="Manage time conditions, IVR menus, call queues, and ring groups."
        breadcrumbs={breadcrumbs}
      />

      <PageSection>
        <Tabs value={tab} onValueChange={setTab}>
          <TabsList>
            <TabsTrigger value="time-conditions">
              <Clock className="mr-2 h-4 w-4" />
              Time Conditions
            </TabsTrigger>
            <TabsTrigger value="ivr-menus">
              <Menu className="mr-2 h-4 w-4" />
              IVR Menus
            </TabsTrigger>
            <TabsTrigger value="call-queues">
              <Phone className="mr-2 h-4 w-4" />
              Call Queues
            </TabsTrigger>
            <TabsTrigger value="ring-groups">
              <Users className="mr-2 h-4 w-4" />
              Ring Groups
            </TabsTrigger>
          </TabsList>

          <TabsContent value="time-conditions" className="mt-6">
            <TimeConditionsTab />
          </TabsContent>
          <TabsContent value="ivr-menus" className="mt-6">
            <IvrMenusTab />
          </TabsContent>
          <TabsContent value="call-queues" className="mt-6">
            <CallQueuesTab />
          </TabsContent>
          <TabsContent value="ring-groups" className="mt-6">
            <RingGroupsTab />
          </TabsContent>
        </Tabs>
      </PageSection>
    </PageContainer>
  )
}
