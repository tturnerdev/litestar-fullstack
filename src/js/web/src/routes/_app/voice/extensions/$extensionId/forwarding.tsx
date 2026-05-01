import { createFileRoute, Link } from "@tanstack/react-router"
import { useState } from "react"
import {
  AlertTriangle,
  ArrowLeft,
  Loader2,
  PhoneForwarded,
  Plus,
  Trash2,
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
import { Button, buttonVariants } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { EmptyState } from "@/components/ui/empty-state"
import { ErrorState } from "@/components/ui/error-state"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { useDocumentTitle } from "@/hooks/use-document-title"
import {
  type ForwardingRule,
  useCreateForwardingRule,
  useDeleteForwardingRule,
  useExtension,
  useForwardingRules,
  useUpdateForwardingRule,
} from "@/lib/api/hooks/voice"

export const Route = createFileRoute(
  "/_app/voice/extensions/$extensionId/forwarding",
)({
  component: ForwardingPage,
})

// ---------------------------------------------------------------------------
// Label maps
// ---------------------------------------------------------------------------

const RULE_TYPE_LABELS: Record<string, string> = {
  always: "Always",
  busy: "Busy",
  no_answer: "No Answer",
  unreachable: "Unreachable",
}

const RULE_TYPE_DESCRIPTIONS: Record<string, string> = {
  always: "Forward all incoming calls",
  busy: "Forward when line is busy",
  no_answer: "Forward after ring timeout",
  unreachable: "Forward when extension is offline",
}

const DEST_TYPE_LABELS: Record<string, string> = {
  extension: "Extension",
  external: "External Number",
  voicemail: "Voicemail",
}

const CONDITION_VARIANTS: Record<string, "default" | "secondary" | "outline"> = {
  always: "default",
  busy: "secondary",
  no_answer: "outline",
  unreachable: "outline",
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

function ForwardingPage() {
  useDocumentTitle("Call Forwarding")
  const { extensionId } = Route.useParams()
  const {
    data: extension,
    isLoading: extLoading,
    isError: extError,
  } = useExtension(extensionId)
  const {
    data: rulesData,
    isLoading: rulesLoading,
    isError: rulesError,
    refetch,
  } = useForwardingRules(extensionId)

  const [showAddDialog, setShowAddDialog] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<ForwardingRule | null>(null)

  const isLoading = extLoading || rulesLoading
  const isError = extError || rulesError

  // -- Loading ----------------------------------------------------------------

  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader eyebrow="Voice" title="Call Forwarding" />
        <PageSection>
          <SkeletonCard />
        </PageSection>
      </PageContainer>
    )
  }

  // -- Error ------------------------------------------------------------------

  if (isError) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader
          eyebrow="Voice"
          title="Call Forwarding"
          actions={
            <Button variant="outline" size="sm" asChild>
              <Link
                to="/voice/extensions/$extensionId"
                params={{ extensionId }}
              >
                <ArrowLeft className="mr-2 h-4 w-4" /> Back to Extension
              </Link>
            </Button>
          }
        />
        <PageSection>
          <ErrorState
            title="Unable to load forwarding rules"
            description="Something went wrong loading this extension's forwarding configuration. Please try again."
            onRetry={() => refetch()}
          />
        </PageSection>
      </PageContainer>
    )
  }

  const rules: ForwardingRule[] = (rulesData?.items ?? []).sort(
    (a, b) => a.priority - b.priority,
  )
  const ruleCount = rules.length
  const activeCount = rules.filter((r) => r.isActive).length
  const extensionName = extension?.displayName ?? "Extension"
  const extensionNumber = extension?.extensionNumber

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Voice"
        title="Call Forwarding"
        description={`Configure how calls to ${extensionName}${extensionNumber ? ` (Ext. ${extensionNumber})` : ""} are routed when unavailable.`}
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
                  <Link to="/voice/extensions">Extensions</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbLink asChild>
                  <Link
                    to="/voice/extensions/$extensionId"
                    params={{ extensionId }}
                  >
                    {extensionName}
                  </Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbPage>Forwarding</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
        actions={
          <div className="flex items-center gap-2">
            {ruleCount > 0 && (
              <Badge variant="secondary">
                {activeCount} of {ruleCount} rules active
              </Badge>
            )}
            <Button size="sm" onClick={() => setShowAddDialog(true)}>
              <Plus className="mr-2 h-4 w-4" /> Add Rule
            </Button>
            <Button variant="outline" size="sm" asChild>
              <Link
                to="/voice/extensions/$extensionId"
                params={{ extensionId }}
              >
                <ArrowLeft className="mr-2 h-4 w-4" /> Back to Extension
              </Link>
            </Button>
          </div>
        }
      />

      <PageSection>
        {ruleCount === 0 ? (
          <EmptyState
            icon={PhoneForwarded}
            title="No forwarding rules"
            description="Forwarding rules let you redirect calls to other extensions, external numbers, or voicemail based on conditions like busy, no answer, or unreachable."
            action={
              <Button onClick={() => setShowAddDialog(true)}>
                <Plus className="mr-2 h-4 w-4" /> Add your first rule
              </Button>
            }
          />
        ) : (
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <PhoneForwarded className="h-5 w-5 text-muted-foreground" />
                <CardTitle>Forwarding Rules</CardTitle>
              </div>
              <p className="text-sm text-muted-foreground">
                Rules are evaluated in priority order. Lower numbers run first.
              </p>
            </CardHeader>
            <CardContent>
              <RulesTable
                rules={rules}
                extensionId={extensionId}
                onDelete={setDeleteTarget}
              />
            </CardContent>
          </Card>
        )}
      </PageSection>

      {/* Add rule dialog */}
      <AddRuleDialog
        extensionId={extensionId}
        open={showAddDialog}
        onOpenChange={setShowAddDialog}
      />

      {/* Delete confirmation dialog */}
      <DeleteRuleDialog
        extensionId={extensionId}
        rule={deleteTarget}
        onOpenChange={(open) => {
          if (!open) setDeleteTarget(null)
        }}
      />
    </PageContainer>
  )
}

// ---------------------------------------------------------------------------
// Rules table
// ---------------------------------------------------------------------------

function RulesTable({
  rules,
  extensionId,
  onDelete,
}: {
  rules: ForwardingRule[]
  extensionId: string
  onDelete: (rule: ForwardingRule) => void
}) {
  const updateMutation = useUpdateForwardingRule(extensionId)

  function handleToggleActive(rule: ForwardingRule) {
    updateMutation.mutate({
      ruleId: rule.id,
      payload: { isActive: !rule.isActive },
    })
  }

  return (
    <Table aria-label="Forwarding rules">
      <TableHeader>
        <TableRow>
          <TableHead className="w-20">Priority</TableHead>
          <TableHead>Condition</TableHead>
          <TableHead>Destination</TableHead>
          <TableHead>Target</TableHead>
          <TableHead className="w-24">Timeout</TableHead>
          <TableHead className="w-24">Enabled</TableHead>
          <TableHead className="w-16 text-right">Actions</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {rules.map((rule) => (
          <TableRow key={rule.id}>
            <TableCell className="font-mono text-sm">{rule.priority}</TableCell>
            <TableCell>
              <div className="flex flex-col gap-1">
                <Badge variant={CONDITION_VARIANTS[rule.ruleType] ?? "outline"}>
                  {RULE_TYPE_LABELS[rule.ruleType] ?? rule.ruleType}
                </Badge>
                <span className="text-xs text-muted-foreground">
                  {RULE_TYPE_DESCRIPTIONS[rule.ruleType] ?? ""}
                </span>
              </div>
            </TableCell>
            <TableCell>
              <Badge variant="outline">
                {DEST_TYPE_LABELS[rule.destinationType] ??
                  rule.destinationType}
              </Badge>
            </TableCell>
            <TableCell className="font-mono text-sm">
              {rule.destinationValue}
            </TableCell>
            <TableCell className="text-sm text-muted-foreground">
              {rule.ringTimeoutSeconds != null
                ? `${rule.ringTimeoutSeconds}s`
                : "--"}
            </TableCell>
            <TableCell>
              <Switch
                checked={rule.isActive}
                onCheckedChange={() => handleToggleActive(rule)}
                disabled={updateMutation.isPending}
              />
            </TableCell>
            <TableCell className="text-right">
              <Button
                variant="ghost"
                size="sm"
                className="text-destructive hover:bg-destructive/10 hover:text-destructive"
                onClick={() => onDelete(rule)}
              >
                <Trash2 className="h-4 w-4" />
              </Button>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}

// ---------------------------------------------------------------------------
// Add rule dialog
// ---------------------------------------------------------------------------

function AddRuleDialog({
  extensionId,
  open,
  onOpenChange,
}: {
  extensionId: string
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const createMutation = useCreateForwardingRule(extensionId)

  const [ruleType, setRuleType] = useState("no_answer")
  const [destType, setDestType] = useState("voicemail")
  const [destValue, setDestValue] = useState("")
  const [timeout, setTimeout] = useState("")
  const [priority, setPriority] = useState("0")

  function resetForm() {
    setRuleType("no_answer")
    setDestType("voicemail")
    setDestValue("")
    setTimeout("")
    setPriority("0")
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    createMutation.mutate(
      {
        ruleType,
        destinationType: destType,
        destinationValue: destValue,
        ringTimeoutSeconds: timeout ? Number(timeout) : null,
        priority: Number(priority) || 0,
        isActive: true,
      },
      {
        onSuccess: () => {
          resetForm()
          onOpenChange(false)
        },
      },
    )
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(v) => {
        if (!v) resetForm()
        onOpenChange(v)
      }}
    >
      <DialogContent className="sm:max-w-md">
        <form onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle>Add Forwarding Rule</DialogTitle>
            <DialogDescription>
              Create a new call forwarding rule. Choose when to forward and
              where calls should be sent.
            </DialogDescription>
          </DialogHeader>
          <div className="mt-4 space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="rule-type">When</Label>
                <Select value={ruleType} onValueChange={setRuleType}>
                  <SelectTrigger id="rule-type">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="always">Always</SelectItem>
                    <SelectItem value="busy">Busy</SelectItem>
                    <SelectItem value="no_answer">No Answer</SelectItem>
                    <SelectItem value="unreachable">Unreachable</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="dest-type">Forward to</Label>
                <Select value={destType} onValueChange={setDestType}>
                  <SelectTrigger id="dest-type">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="extension">Extension</SelectItem>
                    <SelectItem value="external">External Number</SelectItem>
                    <SelectItem value="voicemail">Voicemail</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="dest-value">Destination</Label>
              <Input
                id="dest-value"
                value={destValue}
                onChange={(e) => setDestValue(e.target.value)}
                placeholder={
                  destType === "voicemail"
                    ? "Voicemail box ID"
                    : destType === "extension"
                      ? "Extension number"
                      : "Phone number (e.g. +15551234567)"
                }
              />
            </div>
            {ruleType === "no_answer" && (
              <div className="space-y-2">
                <Label htmlFor="ring-timeout">Ring timeout (seconds)</Label>
                <Input
                  id="ring-timeout"
                  type="number"
                  value={timeout}
                  onChange={(e) => setTimeout(e.target.value)}
                  placeholder="e.g. 20"
                  min={5}
                  max={120}
                />
              </div>
            )}
            <div className="space-y-2">
              <Label htmlFor="priority">Priority</Label>
              <Input
                id="priority"
                type="number"
                value={priority}
                onChange={(e) => setPriority(e.target.value)}
                min={0}
              />
              <p className="text-xs text-muted-foreground">
                Lower numbers are evaluated first.
              </p>
            </div>
          </div>
          <DialogFooter className="mt-6">
            <Button
              type="button"
              variant="outline"
              onClick={() => {
                resetForm()
                onOpenChange(false)
              }}
              disabled={createMutation.isPending}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              disabled={!destValue.trim() || createMutation.isPending}
            >
              {createMutation.isPending && (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              )}
              Add Rule
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

// ---------------------------------------------------------------------------
// Delete confirmation dialog
// ---------------------------------------------------------------------------

function DeleteRuleDialog({
  extensionId,
  rule,
  onOpenChange,
}: {
  extensionId: string
  rule: ForwardingRule | null
  onOpenChange: (open: boolean) => void
}) {
  const deleteMutation = useDeleteForwardingRule(extensionId)

  function handleDelete() {
    if (!rule) return
    deleteMutation.mutate(rule.id, {
      onSuccess: () => onOpenChange(false),
    })
  }

  return (
    <AlertDialog open={rule !== null} onOpenChange={onOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            Delete Forwarding Rule
          </AlertDialogTitle>
          <AlertDialogDescription>
            Are you sure you want to delete this forwarding rule?
            {rule && (
              <>
                {" "}
                This{" "}
                <span className="font-medium">
                  {RULE_TYPE_LABELS[rule.ruleType]?.toLowerCase() ?? rule.ruleType}
                </span>{" "}
                rule forwards to{" "}
                <span className="font-mono text-foreground">
                  {rule.destinationValue}
                </span>
                . This action cannot be undone.
              </>
            )}
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel
            onClick={() => onOpenChange(false)}
            disabled={deleteMutation.isPending}
          >
            Cancel
          </AlertDialogCancel>
          <AlertDialogAction
            className={buttonVariants({ variant: "destructive" })}
            onClick={handleDelete}
            disabled={deleteMutation.isPending}
          >
            {deleteMutation.isPending && (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            )}
            Delete
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
