import { RotateCcw, Upload } from "lucide-react"
import { useRef, useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { useUpdateVoicemailSettings, useUploadVoicemailGreeting, useVoicemailSettings } from "@/lib/api/hooks/voice"

const GREETING_TYPE_DESCRIPTIONS: Record<string, string> = {
  default: "Plays the system default greeting.",
  custom: "Plays your uploaded custom greeting.",
  name_only: "Plays your name only.",
}

const DEFAULTS = {
  isEnabled: true,
  greetingType: "default",
  maxLength: "120",
  emailNotification: true,
  emailAttachAudio: false,
  transcriptionEnabled: true,
  autoDeleteDays: "90",
} as const

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

  function handleResetToDefaults() {
    setIsEnabled(DEFAULTS.isEnabled)
    setGreetingType(DEFAULTS.greetingType)
    setMaxLength(DEFAULTS.maxLength)
    setEmailNotification(DEFAULTS.emailNotification)
    setEmailAttachAudio(DEFAULTS.emailAttachAudio)
    setTranscriptionEnabled(DEFAULTS.transcriptionEnabled)
    setAutoDeleteDays(DEFAULTS.autoDeleteDays)
    setPin("")
    setDirty(true)
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
        {/* Unsaved changes indicator */}
        {dirty && (
          <div className="flex items-center gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm text-amber-700 dark:text-amber-400">
            <span className="inline-block h-1.5 w-1.5 rounded-full bg-amber-500" />
            You have unsaved changes
          </div>
        )}

        {/* ── General ──────────────────────────────────────────────────── */}
        <div>
          <h3 className="text-sm font-semibold tracking-tight">General</h3>
          <p className="text-xs text-muted-foreground">Basic voicemail behavior and greeting configuration.</p>
        </div>

        <div className="flex items-center justify-between">
          <div className="space-y-0.5">
            <Label>Voicemail enabled</Label>
            <p className="text-xs text-muted-foreground">When disabled, callers will not be able to leave voicemails on this extension.</p>
          </div>
          <Switch
            checked={!!currentEnabled}
            onCheckedChange={(v) => toggle(setIsEnabled, v)}
          />
        </div>

        <div className="space-y-2">
          <Label>Greeting type</Label>
          <p className="text-xs text-muted-foreground">Choose which greeting callers hear before leaving a message.</p>
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
          <p className="text-xs text-muted-foreground">{GREETING_TYPE_DESCRIPTIONS[currentGreeting ?? "default"]}</p>
        </div>

        {currentGreeting === "custom" && (
          <div className="space-y-2">
            <Label>Custom greeting</Label>
            <p className="text-xs text-muted-foreground">Upload an audio file to use as your personal greeting.</p>
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
          <p className="text-xs text-muted-foreground">Maximum recording duration for each voicemail message. Callers will be cut off after this limit.</p>
          <Input
            id="vm-max-length"
            type="number"
            min={10}
            max={600}
            value={currentMaxLength}
            onChange={(e) => {
              setMaxLength(e.target.value)
              setDirty(true)
            }}
          />
        </div>

        <div className="space-y-2">
          <Label htmlFor="vm-pin">Access PIN</Label>
          <p className="text-xs text-muted-foreground">Used to access voicemail remotely by phone. Must be numeric.</p>
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

        <Separator />

        {/* ── Notifications ────────────────────────────────────────────── */}
        <div>
          <h3 className="text-sm font-semibold tracking-tight">Notifications</h3>
          <p className="text-xs text-muted-foreground">Control how you are notified when new voicemails arrive.</p>
        </div>

        <div className="space-y-4 rounded-lg border border-border/60 bg-muted/20 p-4">
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label>Email notification</Label>
              <p className="text-xs text-muted-foreground">Send an email alert whenever a new voicemail is received on this extension.</p>
            </div>
            <Switch
              checked={!!currentEmailNotif}
              onCheckedChange={(v) => toggle(setEmailNotification, v)}
            />
          </div>

          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label>Attach audio to email</Label>
              <p className="text-xs text-muted-foreground">Include the voicemail recording as an audio attachment in the notification email.</p>
            </div>
            <Switch
              checked={!!currentAttachAudio}
              onCheckedChange={(v) => toggle(setEmailAttachAudio, v)}
            />
          </div>
        </div>

        <Separator />

        {/* ── Advanced ─────────────────────────────────────────────────── */}
        <div>
          <h3 className="text-sm font-semibold tracking-tight">Advanced</h3>
          <p className="text-xs text-muted-foreground">Retention and transcription settings.</p>
        </div>

        <div className="space-y-2">
          <Label htmlFor="vm-auto-delete">Retention period (days)</Label>
          <p className="text-xs text-muted-foreground">Automatically delete voicemails older than this number of days. Leave empty to keep messages indefinitely.</p>
          <Input
            id="vm-auto-delete"
            type="number"
            min={1}
            max={365}
            placeholder="Leave empty to keep forever"
            value={currentAutoDelete}
            onChange={(e) => {
              setAutoDeleteDays(e.target.value)
              setDirty(true)
            }}
          />
        </div>

        <div className="flex items-center justify-between">
          <div className="space-y-0.5">
            <Label>Transcription</Label>
            <p className="text-xs text-muted-foreground">Automatically convert voicemail audio to text so you can read messages without listening.</p>
          </div>
          <Switch
            checked={!!currentTranscription}
            onCheckedChange={(v) => toggle(setTranscriptionEnabled, v)}
          />
        </div>

        <Separator />

        {/* ── Actions ──────────────────────────────────────────────────── */}
        <div className="flex items-center gap-3">
          <Button onClick={handleSave} disabled={!dirty || updateMutation.isPending}>
            {updateMutation.isPending ? "Saving..." : "Save changes"}
          </Button>
          <Button variant="outline" onClick={handleResetToDefaults}>
            <RotateCcw className="mr-1.5 h-3.5 w-3.5" />
            Reset to defaults
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}
