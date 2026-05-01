import { Pencil, Trash2 } from "lucide-react"
import { useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import type { ForwardingRule } from "@/lib/api/hooks/voice"

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

interface ForwardingRuleRowProps {
  rule: ForwardingRule
  onUpdate: (ruleId: string, payload: Record<string, unknown>) => void
  onDelete: (ruleId: string) => void
  isUpdating?: boolean
  isDeleting?: boolean
}

export function ForwardingRuleRow({ rule, onUpdate, onDelete, isUpdating, isDeleting }: ForwardingRuleRowProps) {
  const [isEditing, setIsEditing] = useState(false)
  const [editRuleType, setEditRuleType] = useState(rule.ruleType)
  const [editDestType, setEditDestType] = useState(rule.destinationType)
  const [editDestValue, setEditDestValue] = useState(rule.destinationValue)
  const [editTimeout, setEditTimeout] = useState(rule.ringTimeoutSeconds != null ? String(rule.ringTimeoutSeconds) : "")
  const [editPriority, setEditPriority] = useState(String(rule.priority))

  function handleSave() {
    onUpdate(rule.id, {
      ruleType: editRuleType,
      destinationType: editDestType,
      destinationValue: editDestValue,
      ringTimeoutSeconds: editTimeout ? Number(editTimeout) : null,
      priority: Number(editPriority) || 0,
    })
    setIsEditing(false)
  }

  function handleCancel() {
    setEditRuleType(rule.ruleType)
    setEditDestType(rule.destinationType)
    setEditDestValue(rule.destinationValue)
    setEditTimeout(rule.ringTimeoutSeconds != null ? String(rule.ringTimeoutSeconds) : "")
    setEditPriority(String(rule.priority))
    setIsEditing(false)
  }

  if (isEditing) {
    return (
      <div className="flex w-full flex-col gap-3">
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <div className="space-y-1">
            <Label className="text-xs">Condition</Label>
            <Select value={editRuleType} onValueChange={(v) => setEditRuleType(v as ForwardingRule["ruleType"])}>
              <SelectTrigger className="h-8">
                <SelectValue placeholder="Select condition..." />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="always">Always</SelectItem>
                <SelectItem value="busy">Busy</SelectItem>
                <SelectItem value="no_answer">No Answer</SelectItem>
                <SelectItem value="unreachable">Unreachable</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1">
            <Label className="text-xs">Destination</Label>
            <Select value={editDestType} onValueChange={(v) => setEditDestType(v as ForwardingRule["destinationType"])}>
              <SelectTrigger className="h-8">
                <SelectValue placeholder="Select destination..." />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="extension">Extension</SelectItem>
                <SelectItem value="external">External</SelectItem>
                <SelectItem value="voicemail">Voicemail</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1">
            <Label className="text-xs">Target</Label>
            <Input value={editDestValue} onChange={(e) => setEditDestValue(e.target.value)} className="h-8" placeholder="Target" />
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div className="space-y-1">
              <Label className="text-xs">Timeout</Label>
              <Input type="number" value={editTimeout} onChange={(e) => setEditTimeout(e.target.value)} className="h-8" placeholder="--" />
            </div>
            <div className="space-y-1">
              <Label className="text-xs">Priority</Label>
              <Input type="number" value={editPriority} onChange={(e) => setEditPriority(e.target.value)} className="h-8" />
            </div>
          </div>
        </div>
        <div className="flex items-center gap-1">
          <Button size="sm" onClick={handleSave} disabled={isUpdating || !editDestValue}>
            {isUpdating ? "Saving..." : "Save"}
          </Button>
          <Button size="sm" variant="outline" onClick={handleCancel}>
            Cancel
          </Button>
        </div>
      </div>
    )
  }

  return (
    <>
      <div className="flex min-w-0 flex-1 flex-wrap items-center gap-x-4 gap-y-1">
        <span className="text-sm font-medium">{RULE_TYPE_LABELS[rule.ruleType] ?? rule.ruleType}</span>
        <span className="text-sm text-muted-foreground">to</span>
        <Badge variant="secondary" className="text-xs">
          {DEST_TYPE_LABELS[rule.destinationType] ?? rule.destinationType}
        </Badge>
        <span className="font-mono text-sm">{rule.destinationValue}</span>
        {rule.ringTimeoutSeconds != null && (
          <span className="text-xs text-muted-foreground">({rule.ringTimeoutSeconds}s timeout)</span>
        )}
      </div>
      <Badge variant={rule.isActive ? "default" : "outline"} className="shrink-0">
        {rule.isActive ? "Active" : "Inactive"}
      </Badge>
      <div className="flex shrink-0 items-center gap-1 opacity-0 transition-opacity group-hover:opacity-100">
        <Button variant="ghost" size="sm" onClick={() => setIsEditing(true)} aria-label="Edit rule">
          <Pencil className="h-4 w-4" />
        </Button>
        <Button variant="ghost" size="sm" onClick={() => onDelete(rule.id)} disabled={isDeleting} aria-label="Delete rule">
          <Trash2 className="h-4 w-4" />
        </Button>
      </div>
    </>
  )
}
