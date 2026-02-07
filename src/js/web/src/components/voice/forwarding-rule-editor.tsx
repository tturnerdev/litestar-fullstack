import { Plus, Trash2 } from "lucide-react"
import { useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { type ForwardingRule, useCreateForwardingRule, useDeleteForwardingRule, useForwardingRules } from "@/lib/api/hooks/voice"

const RULE_TYPE_LABELS: Record<string, string> = {
  always: "Always",
  busy: "Busy",
  no_answer: "No Answer",
  unreachable: "Unreachable",
}

const DEST_TYPE_LABELS: Record<string, string> = {
  extension: "Extension",
  external: "External",
  voicemail: "Voicemail",
}

export function ForwardingRuleEditor({ extensionId }: { extensionId: string }) {
  const { data, isLoading, isError } = useForwardingRules(extensionId)
  const createMutation = useCreateForwardingRule(extensionId)
  const deleteMutation = useDeleteForwardingRule(extensionId)

  const [showAdd, setShowAdd] = useState(false)
  const [newRuleType, setNewRuleType] = useState("no_answer")
  const [newDestType, setNewDestType] = useState("voicemail")
  const [newDestValue, setNewDestValue] = useState("")
  const [newTimeout, setNewTimeout] = useState("")
  const [newPriority, setNewPriority] = useState("0")

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

  function handleAdd() {
    createMutation.mutate(
      {
        ruleType: newRuleType,
        destinationType: newDestType,
        destinationValue: newDestValue,
        ringTimeoutSeconds: newTimeout ? Number(newTimeout) : null,
        priority: Number(newPriority) || 0,
        isActive: true,
      },
      {
        onSuccess: () => {
          setShowAdd(false)
          setNewDestValue("")
          setNewTimeout("")
          setNewPriority("0")
        },
      },
    )
  }

  function handleDelete(ruleId: string) {
    deleteMutation.mutate(ruleId)
  }

  const rules: ForwardingRule[] = data.items ?? []

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle>Call Forwarding Rules</CardTitle>
        <Button size="sm" onClick={() => setShowAdd(!showAdd)}>
          <Plus className="h-4 w-4" />
          Add rule
        </Button>
      </CardHeader>
      <CardContent className="space-y-4">
        {showAdd && (
          <div className="rounded-lg border border-border/60 bg-muted/30 p-4 space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Rule type</Label>
                <Select value={newRuleType} onValueChange={setNewRuleType}>
                  <SelectTrigger>
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
                <Label>Destination type</Label>
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
                <Label>Destination value</Label>
                <Input value={newDestValue} onChange={(e) => setNewDestValue(e.target.value)} placeholder="Extension or phone number" />
              </div>
              <div className="space-y-2">
                <Label>Ring timeout (seconds)</Label>
                <Input type="number" value={newTimeout} onChange={(e) => setNewTimeout(e.target.value)} placeholder="e.g. 20" />
              </div>
              <div className="space-y-2">
                <Label>Priority</Label>
                <Input type="number" value={newPriority} onChange={(e) => setNewPriority(e.target.value)} />
              </div>
            </div>
            <div className="flex gap-2">
              <Button size="sm" onClick={handleAdd} disabled={!newDestValue || createMutation.isPending}>
                {createMutation.isPending ? "Adding..." : "Add"}
              </Button>
              <Button size="sm" variant="outline" onClick={() => setShowAdd(false)}>
                Cancel
              </Button>
            </div>
          </div>
        )}

        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Priority</TableHead>
              <TableHead>Condition</TableHead>
              <TableHead>Destination</TableHead>
              <TableHead>Target</TableHead>
              <TableHead>Timeout</TableHead>
              <TableHead>Status</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rules.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} className="h-24 text-center text-muted-foreground">
                  No forwarding rules configured.
                </TableCell>
              </TableRow>
            ) : (
              rules.map((rule) => (
                <TableRow key={rule.id}>
                  <TableCell>{rule.priority}</TableCell>
                  <TableCell>{RULE_TYPE_LABELS[rule.ruleType] ?? rule.ruleType}</TableCell>
                  <TableCell>{DEST_TYPE_LABELS[rule.destinationType] ?? rule.destinationType}</TableCell>
                  <TableCell className="font-mono">{rule.destinationValue}</TableCell>
                  <TableCell>{rule.ringTimeoutSeconds != null ? `${rule.ringTimeoutSeconds}s` : "--"}</TableCell>
                  <TableCell>
                    <Badge variant={rule.isActive ? "default" : "outline"}>{rule.isActive ? "Active" : "Inactive"}</Badge>
                  </TableCell>
                  <TableCell className="text-right">
                    <Button variant="ghost" size="sm" onClick={() => handleDelete(rule.id)} disabled={deleteMutation.isPending}>
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}
