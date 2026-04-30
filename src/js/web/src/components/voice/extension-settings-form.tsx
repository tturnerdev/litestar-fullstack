import { useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Separator } from "@/components/ui/separator"
import { Switch } from "@/components/ui/switch"
import { SkeletonCard } from "@/components/ui/skeleton"
import { useExtension, useUpdateExtension, usePhoneNumber } from "@/lib/api/hooks/voice"
import { AlertTriangle, Clock, Phone, RotateCcw, Save } from "lucide-react"

interface ExtensionSettingsFormProps {
  extensionId: string
}

function formatRelativeTime(dateString: string | null): string | null {
  if (!dateString) return null
  const date = new Date(dateString)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffSeconds = Math.floor(diffMs / 1000)
  const diffMinutes = Math.floor(diffSeconds / 60)
  const diffHours = Math.floor(diffMinutes / 60)
  const diffDays = Math.floor(diffHours / 24)

  if (diffDays > 30) {
    const diffMonths = Math.floor(diffDays / 30)
    return diffMonths === 1 ? "1 month ago" : `${diffMonths} months ago`
  }
  if (diffDays > 0) return diffDays === 1 ? "1 day ago" : `${diffDays} days ago`
  if (diffHours > 0) return diffHours === 1 ? "1 hour ago" : `${diffHours} hours ago`
  if (diffMinutes > 0) return diffMinutes === 1 ? "1 minute ago" : `${diffMinutes} minutes ago`
  return "just now"
}

export function ExtensionSettingsForm({ extensionId }: ExtensionSettingsFormProps) {
  const { data, isLoading, isError } = useExtension(extensionId)
  const updateMutation = useUpdateExtension(extensionId)
  const { data: phoneNumber } = usePhoneNumber(data?.phoneNumberId ?? "")

  const [displayName, setDisplayName] = useState("")
  const [isActive, setIsActive] = useState(true)
  const [initialized, setInitialized] = useState(false)

  // Sync local state when data loads or changes (after mutation success, etc.)
  useEffect(() => {
    if (data && !initialized) {
      setDisplayName(data.displayName)
      setIsActive(data.isActive)
      setInitialized(true)
    }
  }, [data, initialized])

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

  const dirty = displayName !== data.displayName || isActive !== data.isActive

  function handleSave() {
    if (!data) return
    const payload: Record<string, unknown> = {}
    if (displayName !== data.displayName) payload.displayName = displayName
    if (isActive !== data.isActive) payload.isActive = isActive
    updateMutation.mutate(payload, {
      onSuccess: () => {
        setInitialized(false)
      },
    })
  }

  function handleReset() {
    if (!data) return
    setDisplayName(data.displayName)
    setIsActive(data.isActive)
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>General Settings</CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Unsaved changes banner */}
        {dirty && (
          <div className="flex items-center gap-2 rounded-md bg-amber-50 px-4 py-3 text-sm text-amber-800 dark:bg-amber-950/50 dark:text-amber-200">
            <AlertTriangle className="h-4 w-4 shrink-0" />
            <span>You have unsaved changes</span>
          </div>
        )}

        {/* Extension number (read-only) */}
        <div className="space-y-2">
          <Label>Extension number</Label>
          <Input value={data.extensionNumber} disabled />
        </div>

        <Separator />

        {/* Display name */}
        <div className="space-y-2">
          <Label htmlFor="ext-display-name">Display name</Label>
          <Input
            id="ext-display-name"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
          />
          <p className="text-xs text-muted-foreground">
            The name shown on caller ID and in the directory
          </p>
        </div>

        <Separator />

        {/* Status toggle */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <div className="space-y-1">
              <Label htmlFor="ext-status-toggle">Status</Label>
              <p className="text-xs text-muted-foreground">
                Controls whether this extension can make and receive calls
              </p>
            </div>
            <div className="flex items-center gap-2">
              <span className={`text-sm font-medium ${isActive ? "text-green-600 dark:text-green-400" : "text-muted-foreground"}`}>
                {isActive ? "Active" : "Inactive"}
              </span>
              <Switch
                id="ext-status-toggle"
                checked={isActive}
                onCheckedChange={setIsActive}
              />
            </div>
          </div>
        </div>

        <Separator />

        {/* Linked phone number */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Phone className="h-4 w-4 text-muted-foreground" />
            <Label>Linked phone number</Label>
          </div>
          {data.phoneNumberId ? (
            <span className="text-sm font-medium font-mono">
              {phoneNumber?.number ?? data.phoneNumberId}
            </span>
          ) : (
            <span className="text-sm text-muted-foreground">None assigned</span>
          )}
        </div>

        {/* Timestamps */}
        {(data.createdAt || data.updatedAt) && (
          <>
            <Separator />
            <div className="flex flex-col gap-2 text-xs text-muted-foreground">
              {data.createdAt && (
                <div className="flex items-center gap-1.5">
                  <Clock className="h-3.5 w-3.5" />
                  <span>Created {formatRelativeTime(data.createdAt)}</span>
                </div>
              )}
              {data.updatedAt && (
                <div className="flex items-center gap-1.5">
                  <Clock className="h-3.5 w-3.5" />
                  <span>Updated {formatRelativeTime(data.updatedAt)}</span>
                </div>
              )}
            </div>
          </>
        )}

        <Separator />

        {/* Action buttons */}
        <div className="flex items-center gap-2">
          <Button onClick={handleSave} disabled={!dirty || updateMutation.isPending}>
            <Save className="mr-2 h-4 w-4" />
            {updateMutation.isPending ? "Saving..." : "Save changes"}
          </Button>
          {dirty && (
            <Button variant="outline" onClick={handleReset}>
              <RotateCcw className="mr-2 h-4 w-4" />
              Cancel
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  )
}
