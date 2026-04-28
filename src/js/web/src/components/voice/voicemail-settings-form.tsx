import { Upload } from "lucide-react"
import { useRef, useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { SkeletonCard } from "@/components/ui/skeleton"
import { useUpdateVoicemailSettings, useUploadVoicemailGreeting, useVoicemailSettings } from "@/lib/api/hooks/voice"

const GREETING_TYPE_DESCRIPTIONS: Record<string, string> = {
  default: "Plays the system default greeting.",
  custom: "Plays your uploaded custom greeting.",
  name_only: "Plays your name only.",
}

export function VoicemailSettingsForm({ extensionId }: { extensionId: string }) {
  const { data, isLoading, isError } = useVoicemailSettings(extensionId)
  const updateMutation = useUpdateVoicemailSettings(extensionId)
  const uploadMutation = useUploadVoicemailGreeting(extensionId)
  const fileInputRef = useRef<HTMLInputElement>(null)
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

  function handleGreetingUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (file) {
      uploadMutation.mutate(file)
    }
  }

  function toggle(setter: (v: boolean) => void, value: boolean) {
    setter(value)
    setDirty(true)
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle>Voicemail Settings</CardTitle>
            <CardDescription>Configure how voicemail works for this extension.</CardDescription>
          </div>
          <Badge variant={currentEnabled ? "default" : "outline"}>
            {currentEnabled ? "Enabled" : "Disabled"}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <Label>Voicemail enabled</Label>
            <p className="text-xs text-muted-foreground">Turn voicemail on or off for this extension.</p>
          </div>
          <Button
            variant={currentEnabled ? "default" : "outline"}
            size="sm"
            onClick={() => toggle(setIsEnabled, !currentEnabled)}
          >
            {currentEnabled ? "Enabled" : "Disabled"}
          </Button>
        </div>

        <div className="space-y-2">
          <Label htmlFor="vm-pin">Access PIN</Label>
          <p className="text-xs text-muted-foreground">Used to access voicemail by phone.</p>
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
          <p className="text-xs text-muted-foreground">{GREETING_TYPE_DESCRIPTIONS[currentGreeting]}</p>
        </div>

        {currentGreeting === "custom" && (
          <div className="space-y-2">
            <Label>Custom greeting</Label>
            <div className="flex items-center gap-3">
              {data.greetingFilePath ? (
                <Badge variant="secondary">Greeting uploaded</Badge>
              ) : (
                <span className="text-sm text-muted-foreground">No custom greeting uploaded.</span>
              )}
              <input
                ref={fileInputRef}
                type="file"
                accept="audio/*"
                className="hidden"
                onChange={handleGreetingUpload}
              />
              <Button
                variant="outline"
                size="sm"
                onClick={() => fileInputRef.current?.click()}
                disabled={uploadMutation.isPending}
              >
                <Upload className="mr-1 h-4 w-4" />
                {uploadMutation.isPending ? "Uploading..." : "Upload greeting"}
              </Button>
            </div>
          </div>
        )}

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

        <div className="space-y-4 rounded-lg border border-border/60 bg-muted/20 p-4">
          <p className="text-sm font-medium">Email notifications</p>

          <div className="flex items-center justify-between">
            <div>
              <Label>Email notification</Label>
              <p className="text-xs text-muted-foreground">Send an email when a new voicemail is received.</p>
            </div>
            <Button
              variant={currentEmailNotif ? "default" : "outline"}
              size="sm"
              onClick={() => toggle(setEmailNotification, !currentEmailNotif)}
            >
              {currentEmailNotif ? "On" : "Off"}
            </Button>
          </div>

          <div className="flex items-center justify-between">
            <div>
              <Label>Attach audio to email</Label>
              <p className="text-xs text-muted-foreground">Include the voicemail recording as an attachment.</p>
            </div>
            <Button
              variant={currentAttachAudio ? "default" : "outline"}
              size="sm"
              onClick={() => toggle(setEmailAttachAudio, !currentAttachAudio)}
            >
              {currentAttachAudio ? "On" : "Off"}
            </Button>
          </div>
        </div>

        <div className="flex items-center justify-between">
          <div>
            <Label>Transcription</Label>
            <p className="text-xs text-muted-foreground">Convert voicemail audio to text.</p>
          </div>
          <Button
            variant={currentTranscription ? "default" : "outline"}
            size="sm"
            onClick={() => toggle(setTranscriptionEnabled, !currentTranscription)}
          >
            {currentTranscription ? "On" : "Off"}
          </Button>
        </div>

        <div className="space-y-2">
          <Label htmlFor="vm-auto-delete">Auto-delete after (days)</Label>
          <p className="text-xs text-muted-foreground">Leave empty to keep messages indefinitely.</p>
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
