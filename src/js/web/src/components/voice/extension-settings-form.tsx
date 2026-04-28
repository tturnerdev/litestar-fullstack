import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { SkeletonCard } from "@/components/ui/skeleton"
import { useExtension, useUpdateExtension } from "@/lib/api/hooks/voice"

interface ExtensionSettingsFormProps {
  extensionId: string
}

export function ExtensionSettingsForm({ extensionId }: ExtensionSettingsFormProps) {
  const { data, isLoading, isError } = useExtension(extensionId)
  const updateMutation = useUpdateExtension(extensionId)
  const [displayName, setDisplayName] = useState("")
  const [dirty, setDirty] = useState(false)

  if (isLoading) return <SkeletonCard />

  if (isError || !data) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>General</CardTitle>
        </CardHeader>
        <CardContent className="text-muted-foreground">Unable to load extension details.</CardContent>
      </Card>
    )
  }

  const currentDisplayName = displayName || data.displayName

  function handleSave() {
    const payload: Record<string, unknown> = {}
    if (displayName) payload.displayName = displayName
    updateMutation.mutate(payload, {
      onSuccess: () => setDirty(false),
    })
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>General Settings</CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="space-y-2">
          <Label>Extension number</Label>
          <Input value={data.extensionNumber} disabled />
        </div>

        <div className="space-y-2">
          <Label htmlFor="ext-display-name">Display name</Label>
          <Input
            id="ext-display-name"
            value={currentDisplayName}
            onChange={(e) => {
              setDisplayName(e.target.value)
              setDirty(true)
            }}
          />
        </div>

        <div className="flex items-center justify-between">
          <Label>Status</Label>
          <span className={data.isActive ? "text-sm font-medium text-green-600" : "text-sm font-medium text-muted-foreground"}>
            {data.isActive ? "Active" : "Inactive"}
          </span>
        </div>

        {data.phoneNumberId && (
          <div className="flex items-center justify-between">
            <Label>Linked phone number</Label>
            <span className="text-sm font-medium">Assigned</span>
          </div>
        )}

        <Button onClick={handleSave} disabled={!dirty || updateMutation.isPending}>
          {updateMutation.isPending ? "Saving..." : "Save changes"}
        </Button>
      </CardContent>
    </Card>
  )
}
