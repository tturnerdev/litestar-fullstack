import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { SkeletonCard } from "@/components/ui/skeleton"
import { useUpdateVoicemailSettings, useVoicemailSettings } from "@/lib/api/hooks/voice"

export function VoicemailSettingsForm({ extensionId }: { extensionId: string }) {
  const { data, isLoading, isError } = useVoicemailSettings(extensionId)
  const updateMutation = useUpdateVoicemailSettings(extensionId)
  const [dirty, setDirty] = useState(false)

  const [isEnabled, setIsEnabled] = useState<boolean | null>(null)
  const [pin, setPin] = useState("")
  const [greetingType, setGreetingType] = useState("")
  const [maxLength, setMaxLength] = useState("")
  const [emailNotification, setEmailNotification] = useState<boolean | null>(null)
  const [emailAttachAudio, setEmailAttachAudio] = useState<boolean | null>(null)
  const [transcriptionEnabled, setTranscriptionEnabled] = useState<boolean | null>(null)
  const [autoDeleteDays, setAutoDeleteDays] = useState("")

  if (isLoading) return <SkeletonCard />

  if (isError || !data) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Voicemail</CardTitle>
        </CardHeader>
        <CardContent className="text-muted-foreground">Unable to load voicemail settings.</CardContent>
      </Card>
    )
  }

  const currentEnabled = isEnabled ?? data.isEnabled
  const currentGreeting = greetingType || data.greetingType
  const currentMaxLength = maxLength || String(data.maxMessageLengthSeconds)
  const currentEmailNotif = emailNotification ?? data.emailNotification
  const currentAttachAudio = emailAttachAudio ?? data.emailAttachAudio
  const currentTranscription = transcriptionEnabled ?? data.transcriptionEnabled
  const currentAutoDelete = autoDeleteDays || (data.autoDeleteDays != null ? String(data.autoDeleteDays) : "")

  function handleSave() {
    const payload: Record<string, unknown> = {}
    if (isEnabled !== null) payload.isEnabled = isEnabled
    if (pin) payload.pin = pin
    if (greetingType) payload.greetingType = greetingType
    if (maxLength) payload.maxMessageLengthSeconds = Number(maxLength)
    if (emailNotification !== null) payload.emailNotification = emailNotification
    if (emailAttachAudio !== null) payload.emailAttachAudio = emailAttachAudio
    if (transcriptionEnabled !== null) payload.transcriptionEnabled = transcriptionEnabled
    if (autoDeleteDays) payload.autoDeleteDays = Number(autoDeleteDays) || null

    updateMutation.mutate(payload, {
      onSuccess: () => {
        setDirty(false)
        setPin("")
      },
    })
  }

  function toggle(setter: (v: boolean) => void, value: boolean) {
    setter(value)
    setDirty(true)
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Voicemail Settings</CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="flex items-center justify-between">
          <Label>Voicemail enabled</Label>
          <Button variant={currentEnabled ? "default" : "outline"} size="sm" onClick={() => toggle(setIsEnabled, !currentEnabled)}>
            {currentEnabled ? "Enabled" : "Disabled"}
          </Button>
        </div>

        <div className="space-y-2">
          <Label htmlFor="vm-pin">Access PIN</Label>
          <Input
            id="vm-pin"
            type="password"
            placeholder="Enter new PIN"
            value={pin}
            onChange={(e) => {
              setPin(e.target.value)
              setDirty(true)
            }}
          />
        </div>

        <div className="space-y-2">
          <Label>Greeting type</Label>
          <Select
            value={currentGreeting}
            onValueChange={(v) => {
              setGreetingType(v)
              setDirty(true)
            }}
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="default">Default</SelectItem>
              <SelectItem value="custom">Custom</SelectItem>
              <SelectItem value="name_only">Name only</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <div className="space-y-2">
          <Label htmlFor="vm-max-length">Max message length (seconds)</Label>
          <Input
            id="vm-max-length"
            type="number"
            value={currentMaxLength}
            onChange={(e) => {
              setMaxLength(e.target.value)
              setDirty(true)
            }}
          />
        </div>

        <div className="flex items-center justify-between">
          <Label>Email notification</Label>
          <Button variant={currentEmailNotif ? "default" : "outline"} size="sm" onClick={() => toggle(setEmailNotification, !currentEmailNotif)}>
            {currentEmailNotif ? "On" : "Off"}
          </Button>
        </div>

        <div className="flex items-center justify-between">
          <Label>Attach audio to email</Label>
          <Button variant={currentAttachAudio ? "default" : "outline"} size="sm" onClick={() => toggle(setEmailAttachAudio, !currentAttachAudio)}>
            {currentAttachAudio ? "On" : "Off"}
          </Button>
        </div>

        <div className="flex items-center justify-between">
          <Label>Transcription</Label>
          <Button variant={currentTranscription ? "default" : "outline"} size="sm" onClick={() => toggle(setTranscriptionEnabled, !currentTranscription)}>
            {currentTranscription ? "On" : "Off"}
          </Button>
        </div>

        <div className="space-y-2">
          <Label htmlFor="vm-auto-delete">Auto-delete after (days)</Label>
          <Input
            id="vm-auto-delete"
            type="number"
            placeholder="Leave empty to keep forever"
            value={currentAutoDelete}
            onChange={(e) => {
              setAutoDeleteDays(e.target.value)
              setDirty(true)
            }}
          />
        </div>

        <Button onClick={handleSave} disabled={!dirty || updateMutation.isPending}>
          {updateMutation.isPending ? "Saving..." : "Save changes"}
        </Button>
      </CardContent>
    </Card>
  )
}
