import { PhoneForwarded, PhoneMissed, PhoneOff, Plus } from "lucide-react"
import { useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { ForwardingRuleRow } from "@/components/voice/forwarding-rule-row"
import {
  type ForwardingRule,
  useCreateForwardingRule,
  useDeleteForwardingRule,
  useForwardingRules,
  useUpdateForwardingRule,
} from "@/lib/api/hooks/voice"

const RULE_TYPE_CONFIG: Record<string, { label: string; icon: typeof PhoneForwarded }> = {
  always: { label: "Always", icon: PhoneForwarded },
  busy: { label: "Busy", icon: PhoneOff },
  no_answer: { label: "No Answer", icon: PhoneMissed },
  unreachable: { label: "Unreachable", icon: PhoneOff },
}

export function ForwardingRuleEditor({ extensionId }: { extensionId: string }) {
  const { data, isLoading, isError } = useForwardingRules(extensionId)
  const createMutation = useCreateForwardingRule(extensionId)
  const updateMutation = useUpdateForwardingRule(extensionId)
  const deleteMutation = useDeleteForwardingRule(extensionId)

  const [dialogOpen, setDialogOpen] = useState(false)
  const [newRuleType, setNewRuleType] = useState("no_answer")
  const [newDestType, setNewDestType] = useState("voicemail")
  const [newDestValue, setNewDestValue] = useState("")
  const [newTimeout, setNewTimeout] = useState("")
  const [newPriority, setNewPriority] = useState("0")
  const [newIsActive, setNewIsActive] = useState(true)

  if (isLoading) return <SkeletonCard />

  if (isError || !data) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Call Forwarding</CardTitle>
        </CardHeader>
        <CardContent className="text-muted-foreground">Unable to load forwarding rules.</CardContent>
      </Card>
    )
  }

  function resetNewRuleForm() {
    setNewRuleType("no_answer")
    setNewDestType("voicemail")
    setNewDestValue("")
    setNewTimeout("")
    setNewPriority("0")
    setNewIsActive(true)
  }

  function handleAdd() {
    createMutation.mutate(
      {
        ruleType: newRuleType,
        destinationType: newDestType,
        destinationValue: newDestValue,
        ringTimeoutSeconds: newTimeout ? Number(newTimeout) : null,
        priority: Number(newPriority) || 0,
        isActive: newIsActive,
      },
      {
        onSuccess: () => {
          setDialogOpen(false)
          resetNewRuleForm()
        },
      },
    )
  }

  function handleUpdate(ruleId: string, payload: Record<string, unknown>) {
    updateMutation.mutate({ ruleId, payload })
  }

  function handleDelete(ruleId: string) {
    deleteMutation.mutate(ruleId)
  }

  const rules: ForwardingRule[] = (data.items ?? []).sort((a, b) => a.priority - b.priority)

  const NewRuleTypeIcon = RULE_TYPE_CONFIG[newRuleType]?.icon ?? PhoneForwarded

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <div>
          <CardTitle>Call Forwarding Rules</CardTitle>
          <p className="mt-1 text-sm text-muted-foreground">
            Rules are evaluated in priority order. Lower numbers run first.
          </p>
        </div>
        <Dialog open={dialogOpen} onOpenChange={(open) => { setDialogOpen(open); if (!open) resetNewRuleForm(); }}>
          <DialogTrigger asChild>
            <Button size="sm">
              <Plus className="mr-1 h-4 w-4" />
              Add rule
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <NewRuleTypeIcon className="h-5 w-5" />
                Add Forwarding Rule
              </DialogTitle>
              <DialogDescription>
                Configure when and where calls should be forwarded.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-2">
              <div className="space-y-2">
                <Label>When</Label>
                <Select value={newRuleType} onValueChange={setNewRuleType}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {Object.entries(RULE_TYPE_CONFIG).map(([value, config]) => {
                      const Icon = config.icon
                      return (
                        <SelectItem key={value} value={value}>
                          <span className="flex items-center gap-2">
                            <Icon className="h-4 w-4" />
                            {config.label}
                          </span>
                        </SelectItem>
                      )
                    })}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>Forward to</Label>
                <Select value={newDestType} onValueChange={setNewDestType}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="extension">Extension</SelectItem>
                    <SelectItem value="external">External number</SelectItem>
                    <SelectItem value="voicemail">Voicemail</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>Destination</Label>
                <Input
                  value={newDestValue}
                  onChange={(e) => setNewDestValue(e.target.value)}
                  placeholder={newDestType === "voicemail" ? "Voicemail box" : "Extension or phone number"}
                />
                {!newDestValue && (
                  <p className="text-xs text-destructive">Destination is required</p>
                )}
              </div>
              {newRuleType === "no_answer" && (
                <div className="space-y-2">
                  <Label>Ring timeout (seconds)</Label>
                  <Input
                    type="number"
                    value={newTimeout}
                    onChange={(e) => setNewTimeout(e.target.value)}
                    placeholder="e.g. 20"
                    min={1}
                  />
                  <p className="text-xs text-muted-foreground">
                    How long to wait before forwarding unanswered calls.
                  </p>
                </div>
              )}
              <div className="space-y-2">
                <Label>Priority</Label>
                <Input
                  type="number"
                  value={newPriority}
                  onChange={(e) => setNewPriority(e.target.value)}
                  min={0}
                />
                <p className="text-xs text-muted-foreground">
                  Lower numbers are evaluated first.
                </p>
              </div>
              <div className="flex items-center justify-between rounded-lg border p-3">
                <div>
                  <Label>Active</Label>
                  <p className="text-xs text-muted-foreground">Enable this rule immediately</p>
                </div>
                <Switch checked={newIsActive} onCheckedChange={setNewIsActive} />
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setDialogOpen(false)}>
                Cancel
              </Button>
              <Button onClick={handleAdd} disabled={!newDestValue || createMutation.isPending}>
                {createMutation.isPending ? "Adding..." : "Add rule"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </CardHeader>
      <CardContent className="space-y-4">
        {rules.length === 0 ? (
          <div className="flex flex-col items-center justify-center rounded-lg border border-dashed py-12">
            <div className="flex h-12 w-12 items-center justify-center rounded-full bg-muted">
              <PhoneForwarded className="h-6 w-6 text-muted-foreground" />
            </div>
            <h3 className="mt-4 text-sm font-semibold">No forwarding rules</h3>
            <p className="mt-1 text-sm text-muted-foreground">
              Add a rule to forward calls when conditions are met.
            </p>
            <Button size="sm" variant="outline" className="mt-4" onClick={() => setDialogOpen(true)}>
              <Plus className="mr-1 h-4 w-4" />
              Add your first rule
            </Button>
          </div>
        ) : (
          <div className="space-y-2">
            {rules.map((rule) => {
              const config = RULE_TYPE_CONFIG[rule.ruleType]
              const RuleIcon = config?.icon ?? PhoneForwarded
              return (
                <div
                  key={rule.id}
                  className="group flex items-center gap-3 rounded-lg border p-3 transition-colors hover:bg-accent/50"
                >
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-muted">
                    <RuleIcon className="h-4 w-4 text-muted-foreground" />
                  </div>
                  <Badge variant="outline" className="shrink-0 font-mono text-xs">
                    #{rule.priority}
                  </Badge>
                  <ForwardingRuleRow
                    rule={rule}
                    onUpdate={handleUpdate}
                    onDelete={handleDelete}
                    isUpdating={updateMutation.isPending}
                    isDeleting={deleteMutation.isPending}
                  />
                </div>
              )
            })}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
