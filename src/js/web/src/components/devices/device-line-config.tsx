import { useState } from "react"
import { AlertCircle, AlertTriangle, Cable, GripVertical, Loader2, Plus, Save, Trash2 } from "lucide-react"
import type { DeviceLineAssignment } from "@/lib/generated/api"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { EmptyState } from "@/components/ui/empty-state"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useDeviceLines, useSetDeviceLines, type SetDeviceLinesPayload } from "@/lib/api/hooks/devices"

const lineTypes = [
  { value: "private", label: "Private" },
  { value: "shared", label: "Shared" },
  { value: "monitored", label: "Monitored" },
]

const lineTypeBadgeClasses: Record<string, string> = {
  private: "border-blue-500/30 bg-blue-500/10 text-blue-700 dark:text-blue-400",
  shared: "border-green-500/30 bg-green-500/10 text-green-700 dark:text-green-400",
  monitored: "border-yellow-500/30 bg-yellow-500/10 text-yellow-700 dark:text-yellow-400",
}

interface LineRow {
  lineNumber: number
  label: string
  lineType: string
  extensionId: string
  isActive: boolean
}

function toLineRow(line: DeviceLineAssignment): LineRow {
  return {
    lineNumber: line.lineNumber,
    label: line.label,
    lineType: line.lineType,
    extensionId: line.extensionId ?? "",
    isActive: line.isActive ?? true,
  }
}

function emptyLine(lineNumber: number): LineRow {
  return {
    lineNumber,
    label: `Line ${lineNumber}`,
    lineType: "private",
    extensionId: "",
    isActive: true,
  }
}

interface DeviceLineConfigProps {
  deviceId: string
}

export function DeviceLineConfig({ deviceId }: DeviceLineConfigProps) {
  const { data, isLoading, isError, refetch } = useDeviceLines(deviceId)
  const setLinesMutation = useSetDeviceLines(deviceId)
  const [lines, setLines] = useState<LineRow[] | null>(null)
  const [dirty, setDirty] = useState(false)

  if (isLoading) return <SkeletonCard />

  if (isError) {
    return (
      <EmptyState
        icon={AlertCircle}
        title="Unable to load line assignments"
        description="Something went wrong. Please try again."
        action={<Button variant="outline" size="sm" onClick={() => refetch()}>Try again</Button>}
      />
    )
  }

  const currentLines = lines ?? (data?.items ?? []).map(toLineRow)

  function updateLine(index: number, field: keyof LineRow, value: string | number | boolean) {
    const updated = [...currentLines]
    updated[index] = { ...updated[index], [field]: value }
    setLines(updated)
    setDirty(true)
  }

  function addLine() {
    const nextNumber = currentLines.length > 0 ? Math.max(...currentLines.map((l) => l.lineNumber)) + 1 : 1
    setLines([...currentLines, emptyLine(nextNumber)])
    setDirty(true)
  }

  function removeLine(index: number) {
    const updated = currentLines.filter((_, i) => i !== index)
    setLines(updated)
    setDirty(true)
  }

  function handleSave() {
    const payload: SetDeviceLinesPayload[] = currentLines.map((line) => ({
      lineNumber: line.lineNumber,
      label: line.label,
      lineType: line.lineType,
      extensionId: line.extensionId || null,
      isActive: line.isActive,
    }))
    setLinesMutation.mutate(payload, {
      onSuccess: () => {
        setDirty(false)
        setLines(null)
      },
    })
  }

  function handleReset() {
    setLines(null)
    setDirty(false)
  }

  return (
    <Card>
      {dirty && (
        <div className="flex items-center gap-2 rounded-t-lg border-b border-amber-500/30 bg-amber-500/10 px-4 py-2.5 text-sm text-amber-700 dark:text-amber-400">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          <span className="font-medium">You have unsaved changes</span>
        </div>
      )}
      <CardHeader className="flex flex-row items-center justify-between space-y-0">
        <div className="flex items-center gap-3">
          <CardTitle>Line Assignments</CardTitle>
          {currentLines.length > 0 && (
            <span className="text-sm text-muted-foreground">
              {currentLines.length} {currentLines.length === 1 ? "line" : "lines"} configured
            </span>
          )}
        </div>
        {currentLines.length > 0 && (
          <Button variant="outline" size="sm" onClick={addLine}>
            <Plus className="mr-2 h-4 w-4" />
            Add Line
          </Button>
        )}
      </CardHeader>
      <CardContent className="space-y-4">
        {currentLines.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-4 py-12">
            <Cable className="h-12 w-12 text-muted-foreground/40" />
            <div className="text-center">
              <p className="font-medium text-muted-foreground">No line assignments configured</p>
              <p className="mt-1 text-sm text-muted-foreground/70">
                Assign extensions to line keys to configure this device.
              </p>
            </div>
            <Button onClick={addLine}>
              <Plus className="mr-2 h-4 w-4" />
              Add first line
            </Button>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
            <Table aria-label="Line assignments">
              <TableHeader>
                <TableRow>
                  <TableHead className="w-10" />
                  <TableHead className="w-16">Line</TableHead>
                  <TableHead>Label</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Extension ID</TableHead>
                  <TableHead className="w-20">Active</TableHead>
                  <TableHead className="w-16" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {currentLines.map((line, index) => (
                  <TableRow key={line.lineNumber} className="hover:bg-muted/50 transition-colors">
                    <TableCell className="w-10 px-2">
                      <GripVertical className="h-4 w-4 text-muted-foreground/40" />
                    </TableCell>
                    <TableCell className="font-mono font-medium">{line.lineNumber}</TableCell>
                    <TableCell>
                      <Input
                        value={line.label}
                        onChange={(e) => updateLine(index, "label", e.target.value)}
                        className="h-8"
                        placeholder="Line label"
                      />
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <Select value={line.lineType} onValueChange={(v) => updateLine(index, "lineType", v)}>
                          <SelectTrigger className="h-8 w-32">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            {lineTypes.map((t) => (
                              <SelectItem key={t.value} value={t.value}>
                                {t.label}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                        <Badge variant="outline" className={lineTypeBadgeClasses[line.lineType] ?? ""}>
                          {lineTypes.find((t) => t.value === line.lineType)?.label ?? line.lineType}
                        </Badge>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Input
                        value={line.extensionId}
                        onChange={(e) => updateLine(index, "extensionId", e.target.value)}
                        className="h-8 font-mono text-xs"
                        placeholder="Optional extension ID"
                      />
                    </TableCell>
                    <TableCell>
                      <Switch
                        checked={line.isActive}
                        onCheckedChange={(checked) => updateLine(index, "isActive", checked)}
                      />
                    </TableCell>
                    <TableCell>
                      <AlertDialog>
                        <AlertDialogTrigger asChild>
                          <Button variant="ghost" size="sm" className="h-8 w-8 p-0 text-muted-foreground hover:text-destructive">
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </AlertDialogTrigger>
                        <AlertDialogContent>
                          <AlertDialogHeader>
                            <AlertDialogTitle>Remove line {line.lineNumber}?</AlertDialogTitle>
                            <AlertDialogDescription>
                              This will remove &quot;{line.label}&quot; from the configuration. This change won&apos;t take effect until you save.
                            </AlertDialogDescription>
                          </AlertDialogHeader>
                          <AlertDialogFooter>
                            <AlertDialogCancel>Cancel</AlertDialogCancel>
                            <AlertDialogAction onClick={() => removeLine(index)} className="bg-destructive text-destructive-foreground hover:bg-destructive/90">
                              Remove
                            </AlertDialogAction>
                          </AlertDialogFooter>
                        </AlertDialogContent>
                      </AlertDialog>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            </div>

            {dirty && (
              <>
                <Separator />
                <div className="flex items-center justify-end gap-2">
                  <Button variant="ghost" onClick={handleReset} disabled={setLinesMutation.isPending}>
                    Reset
                  </Button>
                  <Button onClick={handleSave} disabled={setLinesMutation.isPending}>
                    {setLinesMutation.isPending ? (
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    ) : (
                      <Save className="mr-2 h-4 w-4" />
                    )}
                    Save Line Assignments
                  </Button>
                </div>
              </>
            )}
          </>
        )}
      </CardContent>
    </Card>
  )
}
