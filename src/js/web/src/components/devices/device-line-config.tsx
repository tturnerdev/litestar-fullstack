import { useState } from "react"
import { Loader2, Plus, Trash2 } from "lucide-react"
import type { DeviceLineAssignment } from "@/lib/generated/api"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { SkeletonCard } from "@/components/ui/skeleton"
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
  const { data, isLoading, isError } = useDeviceLines(deviceId)
  const setLinesMutation = useSetDeviceLines(deviceId)
  const [lines, setLines] = useState<LineRow[] | null>(null)
  const [dirty, setDirty] = useState(false)

  if (isLoading) return <SkeletonCard />

  if (isError) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Line Assignments</CardTitle>
        </CardHeader>
        <CardContent className="text-muted-foreground">Unable to load line assignments.</CardContent>
      </Card>
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
      <CardHeader className="flex flex-row items-center justify-between space-y-0">
        <CardTitle>Line Assignments</CardTitle>
        <Button variant="outline" size="sm" onClick={addLine}>
          <Plus className="mr-2 h-4 w-4" />
          Add Line
        </Button>
      </CardHeader>
      <CardContent className="space-y-4">
        {currentLines.length === 0 ? (
          <p className="py-8 text-center text-muted-foreground text-sm">
            No line assignments configured. Click "Add Line" to assign extensions to line keys.
          </p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
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
                <TableRow key={line.lineNumber}>
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
                    <Badge
                      variant="outline"
                      className={`cursor-pointer ${line.isActive ? lineTypeBadgeClasses[line.lineType] ?? "" : "text-muted-foreground"}`}
                      onClick={() => updateLine(index, "isActive", !line.isActive)}
                    >
                      {line.isActive ? "Yes" : "No"}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Button variant="ghost" size="sm" className="h-8 w-8 p-0 text-muted-foreground hover:text-destructive" onClick={() => removeLine(index)}>
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}

        {dirty && (
          <div className="flex items-center justify-end gap-2 border-t pt-4">
            <Button variant="ghost" onClick={handleReset} disabled={setLinesMutation.isPending}>
              Reset
            </Button>
            <Button onClick={handleSave} disabled={setLinesMutation.isPending}>
              {setLinesMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Save Line Assignments
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
