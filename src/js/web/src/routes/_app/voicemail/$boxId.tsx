import { createFileRoute, Link } from "@tanstack/react-router"
import { useEffect, useState } from "react"
import { toast } from "sonner"
import {
  AlertCircle,
  AlertTriangle,
  ArrowLeft,
  BellRing,
  CheckCircle2,
  CheckSquare,
  Inbox,
  Loader2,
  Mail,
  MailOpen,
  Mic,
  RotateCcw,
  Settings2,
  Square,
  Trash2,
  User,
  Volume2,
  Wrench,
} from "lucide-react"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Badge } from "@/components/ui/badge"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { Skeleton, SkeletonCard } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { VoicemailPlayer } from "@/components/voice/voicemail-player"
import { EntityActivityPanel } from "@/components/shared/entity-activity-panel"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { formatDateTime, formatFullDateTime, formatRelativeTimeShort } from "@/lib/date-utils"
import { formatDuration, formatDurationHuman } from "@/lib/format-utils"
import { cn } from "@/lib/utils"
import {
  useDeleteVoicemailMessage,
  useToggleVoicemailRead,
  useUpdateVoicemailBox,
  useVoicemailBox,
  useVoicemailMessages,
  type VoicemailMessage,
} from "@/lib/api/hooks/voicemail"

export const Route = createFileRoute("/_app/voicemail/$boxId")({
  component: VoicemailBoxDetailPage,
})

// -- Constants ----------------------------------------------------------------

const PAGE_SIZE = 15

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

function formatRetention(days: number): string {
  if (days < 7) return `${days} day${days !== 1 ? "s" : ""}`
  if (days < 30) {
    const weeks = Math.floor(days / 7)
    return `${weeks} week${weeks !== 1 ? "s" : ""}`
  }
  const months = Math.round(days / 30)
  return `${months} month${months !== 1 ? "s" : ""}`
}

// -- Main page ----------------------------------------------------------------

function VoicemailBoxDetailPage() {
  const { boxId } = Route.useParams()
  const { data: box, isLoading, isError, refetch } = useVoicemailBox(boxId)

  const boxLabel = box?.extensionNumber
    ? `Ext. ${box.extensionNumber}`
    : box?.mailboxNumber ?? "Voicemail Box"

  useDocumentTitle(isLoading ? "Voicemail Box" : `${boxLabel} - Voicemail`)

  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <div className="space-y-2">
          <Skeleton className="h-4 w-20" />
          <Skeleton className="h-8 w-64" />
        </div>
        <PageSection>
          <SkeletonCard />
        </PageSection>
        <PageSection delay={0.1}>
          <SkeletonCard />
        </PageSection>
      </PageContainer>
    )
  }

  if (isError || !box) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader
          eyebrow="Voicemail"
          title="Voicemail Box"
          actions={
            <Button variant="outline" size="sm" asChild>
              <Link to="/voicemail">Back to Voicemail</Link>
            </Button>
          }
        />
        <PageSection>
          <EmptyState
            icon={AlertCircle}
            title="Unable to load voicemail box"
            description="Something went wrong. Please try again."
            action={<Button variant="outline" size="sm" onClick={() => refetch()}>Try again</Button>}
          />
        </PageSection>
      </PageContainer>
    )
  }

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Voicemail"
        title={boxLabel}
        description={box.email ? `Notifications to ${box.email}` : undefined}
        breadcrumbs={
          <Breadcrumb>
            <BreadcrumbList>
              <BreadcrumbItem>
                <BreadcrumbLink asChild>
                  <Link to="/home">Home</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbLink asChild>
                  <Link to="/voicemail">Voicemail</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbPage>{boxLabel}</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
        actions={
          <div className="flex items-center gap-2">
            {!box.isEnabled && (
              <Badge variant="outline" className="gap-1.5 text-muted-foreground">
                <span className="h-1.5 w-1.5 rounded-full bg-muted-foreground" />
                Disabled
              </Badge>
            )}
            {box.isEnabled && box.unreadCount > 0 && (
              <Badge variant="secondary" className="gap-1.5">
                <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-primary" />
                {box.unreadCount} unread
              </Badge>
            )}
            {box.extensionId && (
              <Button variant="outline" size="sm" asChild>
                <Link
                  to="/voice/extensions/$extensionId"
                  params={{ extensionId: box.extensionId }}
                >
                  View Extension
                </Link>
              </Button>
            )}
            <Button variant="outline" size="sm" asChild>
              <Link to="/voicemail">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back to Voicemail
              </Link>
            </Button>
          </div>
        }
      />

      {/* Box Settings */}
      <PageSection>
        <BoxSettingsForm boxId={boxId} />
      </PageSection>

      {/* Messages */}
      <PageSection delay={0.1}>
        <BoxMessageList boxId={boxId} />
      </PageSection>

      {/* Activity */}
      <PageSection delay={0.2}>
        <EntityActivityPanel
          targetType="voicemail_box"
          targetId={boxId}
        />
      </PageSection>
    </PageContainer>
  )
}

// -- Box Settings Form --------------------------------------------------------

function BoxSettingsForm({ boxId }: { boxId: string }) {
  const { data, isLoading, isError, refetch: refetchSettings } = useVoicemailBox(boxId)
  const updateMutation = useUpdateVoicemailBox(boxId)
  const [dirty, setDirty] = useState(false)
  const [showSaveSuccess, setShowSaveSuccess] = useState(false)
  const [pinError, setPinError] = useState("")

  const [isEnabled, setIsEnabled] = useState<boolean | null>(null)
  const [pin, setPin] = useState("")
  const [email, setEmail] = useState<string | null>(null)
  const [greetingType, setGreetingType] = useState("")
  const [maxLength, setMaxLength] = useState("")
  const [emailNotification, setEmailNotification] = useState<boolean | null>(null)
  const [emailAttachAudio, setEmailAttachAudio] = useState<boolean | null>(null)
  const [transcriptionEnabled, setTranscriptionEnabled] = useState<boolean | null>(null)
  const [autoDeleteDays, setAutoDeleteDays] = useState("")

  useEffect(() => {
    if (!showSaveSuccess) return
    const timer = setTimeout(() => setShowSaveSuccess(false), 1500)
    return () => clearTimeout(timer)
  }, [showSaveSuccess])

  if (isLoading) return <SkeletonCard />

  if (isError || !data) {
    return (
      <EmptyState
        icon={AlertCircle}
        title="Unable to load voicemail box settings"
        description="Something went wrong. Please try again."
        action={<Button variant="outline" size="sm" onClick={() => refetchSettings()}>Try again</Button>}
      />
    )
  }

  const currentEnabled = isEnabled ?? data.isEnabled
  const currentEmail = email ?? data.email ?? ""
  const currentGreeting = greetingType || data.greetingType
  const currentMaxLength = maxLength || String(data.maxMessageLengthSeconds)
  const currentEmailNotif = emailNotification ?? data.emailNotification
  const currentAttachAudio = emailAttachAudio ?? data.emailAttachAudio
  const currentTranscription = transcriptionEnabled ?? data.transcriptionEnabled
  const currentAutoDelete =
    autoDeleteDays || (data.autoDeleteDays != null ? String(data.autoDeleteDays) : "")

  function handleSave() {
    const payload: Record<string, unknown> = {}
    if (isEnabled !== null) payload.isEnabled = isEnabled
    if (pin) payload.pin = pin
    if (email !== null) payload.email = email || null
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
        setPinError("")
        setEmail(null)
        setShowSaveSuccess(true)
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

  function toggle(setter: (v: boolean) => void, value: boolean) {
    setter(value)
    setDirty(true)
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle>Voicemail Box Settings</CardTitle>
            <CardDescription>
              Configure mailbox behavior, notifications, and retention.
            </CardDescription>
          </div>
          {currentEnabled ? (
            <Badge className="gap-1.5 bg-emerald-100 text-emerald-700 hover:bg-emerald-100 dark:bg-emerald-900/30 dark:text-emerald-400">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
              Enabled
            </Badge>
          ) : (
            <Badge variant="outline" className="gap-1.5 text-muted-foreground">
              <span className="h-1.5 w-1.5 rounded-full bg-muted-foreground" />
              Disabled
            </Badge>
          )}
        </div>
      </CardHeader>
      <CardContent className="space-y-6">
        {dirty && (
          <div className="flex items-center gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm text-amber-700 dark:text-amber-400">
            <span className="inline-block h-1.5 w-1.5 rounded-full bg-amber-500" />
            You have unsaved changes
          </div>
        )}

        {/* General */}
        <div>
          <h3 className="flex items-center gap-1.5 text-sm font-semibold tracking-tight">
            <Settings2 className="h-3.5 w-3.5 text-muted-foreground" />
            General
          </h3>
          <p className="text-xs text-muted-foreground">
            Basic voicemail behavior and greeting configuration.
          </p>
        </div>

        <div className="flex items-center justify-between">
          <div className="space-y-0.5">
            <Label>Voicemail enabled</Label>
            <p
              className={`text-xs text-muted-foreground transition-opacity ${!currentEnabled ? "opacity-50" : ""}`}
            >
              When disabled, callers will not be able to leave voicemails.
            </p>
          </div>
          <Switch
            checked={!!currentEnabled}
            onCheckedChange={(v) => toggle(setIsEnabled, v)}
          />
        </div>

        <div className="space-y-2">
          <Label htmlFor="vm-email">Notification email</Label>
          <p className="text-xs text-muted-foreground">
            Email address for voicemail notifications.
          </p>
          <Input
            id="vm-email"
            type="email"
            placeholder="user@example.com"
            value={currentEmail}
            onChange={(e) => {
              setEmail(e.target.value)
              setDirty(true)
            }}
          />
        </div>

        <div className="space-y-2">
          <Label>Greeting type</Label>
          <p className="text-xs text-muted-foreground">
            Choose which greeting callers hear before leaving a message.
          </p>
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
              <SelectItem value="default">
                <span className="flex items-center gap-2">
                  <Volume2 className="h-3.5 w-3.5 text-muted-foreground" />
                  Default
                </span>
              </SelectItem>
              <SelectItem value="custom">
                <span className="flex items-center gap-2">
                  <Mic className="h-3.5 w-3.5 text-muted-foreground" />
                  Custom
                </span>
              </SelectItem>
              <SelectItem value="name_only">
                <span className="flex items-center gap-2">
                  <User className="h-3.5 w-3.5 text-muted-foreground" />
                  Name only
                </span>
              </SelectItem>
            </SelectContent>
          </Select>
          <p className="text-xs text-muted-foreground">
            {GREETING_TYPE_DESCRIPTIONS[currentGreeting ?? "default"]}
          </p>
        </div>

        <div className="space-y-2">
          <Label htmlFor="vm-max-length">Max message length (seconds)</Label>
          <p className="text-xs text-muted-foreground">
            Maximum recording duration for each voicemail message.
          </p>
          <div className="flex items-center gap-3">
            <Input
              id="vm-max-length"
              type="number"
              min={10}
              max={600}
              className="max-w-[140px]"
              value={currentMaxLength}
              onChange={(e) => {
                setMaxLength(e.target.value)
                setDirty(true)
              }}
            />
            {currentMaxLength && Number(currentMaxLength) > 0 && (
              <span className="text-xs text-muted-foreground">
                = {formatDurationHuman(Number(currentMaxLength))}
              </span>
            )}
          </div>
        </div>

        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <Label htmlFor="vm-pin">Access PIN</Label>
            {pin && (
              <span
                className={`text-xs ${pin.length >= 4 && pin.length <= 6 ? "text-muted-foreground" : "text-destructive"}`}
              >
                {pin.length}/4-6 digits
              </span>
            )}
          </div>
          <p className="text-xs text-muted-foreground">
            Used to access voicemail remotely by phone. Must be 4-6 digits.
          </p>
          <Input
            id="vm-pin"
            type="password"
            inputMode="numeric"
            placeholder="Enter new PIN"
            className={
              pinError ? "border-destructive focus-visible:ring-destructive" : ""
            }
            value={pin}
            onChange={(e) => {
              const value = e.target.value
              if (value && !/^\d*$/.test(value)) {
                setPinError("PIN must contain only digits")
                return
              }
              if (value.length > 6) return
              setPinError(
                value.length > 0 && value.length < 4
                  ? "PIN must be at least 4 digits"
                  : "",
              )
              setPin(value)
              setDirty(true)
            }}
          />
          {pinError && <p className="text-xs text-destructive">{pinError}</p>}
        </div>

        <div className="space-y-2">
          <Label htmlFor="vm-auto-delete">Auto-delete days</Label>
          <p className="text-xs text-muted-foreground">
            Automatically delete voicemails older than this number of days. Leave empty to
            keep messages indefinitely.
          </p>
          <div className="flex items-center gap-3">
            <Input
              id="vm-auto-delete"
              type="number"
              min={1}
              max={365}
              className="max-w-[140px]"
              placeholder="Forever"
              value={currentAutoDelete}
              onChange={(e) => {
                setAutoDeleteDays(e.target.value)
                setDirty(true)
              }}
            />
            {currentAutoDelete && Number(currentAutoDelete) >= 7 && (
              <span className="text-xs text-muted-foreground">
                {formatRetention(Number(currentAutoDelete))}
              </span>
            )}
          </div>
        </div>

        <Separator />

        {/* Notifications */}
        <div className="flex items-start justify-between">
          <div>
            <h3 className="flex items-center gap-1.5 text-sm font-semibold tracking-tight">
              <BellRing className="h-3.5 w-3.5 text-muted-foreground" />
              Notifications
            </h3>
            <p className="text-xs text-muted-foreground">
              Control how you are notified when new voicemails arrive.
            </p>
          </div>
          <div className="flex items-center gap-1.5">
            <Badge
              variant={currentEmailNotif ? "default" : "outline"}
              className={cn(
                "gap-1.5",
                currentEmailNotif
                  ? "bg-emerald-100 text-emerald-700 hover:bg-emerald-100 dark:bg-emerald-900/30 dark:text-emerald-400"
                  : "text-muted-foreground",
              )}
            >
              <span className={cn("h-1.5 w-1.5 rounded-full", currentEmailNotif ? "bg-emerald-500" : "bg-muted-foreground")} />
              Email
            </Badge>
            <Badge
              variant={currentAttachAudio ? "default" : "outline"}
              className={cn(
                "gap-1.5",
                currentAttachAudio
                  ? "bg-emerald-100 text-emerald-700 hover:bg-emerald-100 dark:bg-emerald-900/30 dark:text-emerald-400"
                  : "text-muted-foreground",
              )}
            >
              <span className={cn("h-1.5 w-1.5 rounded-full", currentAttachAudio ? "bg-emerald-500" : "bg-muted-foreground")} />
              Audio
            </Badge>
          </div>
        </div>

        <div className="space-y-4 rounded-lg border border-border/60 bg-muted/20 p-4">
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label>Email notification</Label>
              <p
                className={`text-xs text-muted-foreground transition-opacity ${!currentEmailNotif ? "opacity-50" : ""}`}
              >
                Send an email alert whenever a new voicemail is received.
              </p>
            </div>
            <Switch
              checked={!!currentEmailNotif}
              onCheckedChange={(v) => toggle(setEmailNotification, v)}
            />
          </div>

          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label>Attach audio to email</Label>
              <p
                className={`text-xs text-muted-foreground transition-opacity ${!currentAttachAudio ? "opacity-50" : ""}`}
              >
                Include the voicemail recording as an audio attachment.
              </p>
            </div>
            <Switch
              checked={!!currentAttachAudio}
              onCheckedChange={(v) => toggle(setEmailAttachAudio, v)}
            />
          </div>
        </div>

        <Separator />

        {/* Advanced */}
        <div className="flex items-start justify-between">
          <div>
            <h3 className="flex items-center gap-1.5 text-sm font-semibold tracking-tight">
              <Wrench className="h-3.5 w-3.5 text-muted-foreground" />
              Advanced
            </h3>
            <p className="text-xs text-muted-foreground">
              Transcription settings.
            </p>
          </div>
          <Badge
            variant={currentTranscription ? "default" : "outline"}
            className={cn(
              "gap-1.5",
              currentTranscription
                ? "bg-emerald-100 text-emerald-700 hover:bg-emerald-100 dark:bg-emerald-900/30 dark:text-emerald-400"
                : "text-muted-foreground",
            )}
          >
            <span className={cn("h-1.5 w-1.5 rounded-full", currentTranscription ? "bg-emerald-500" : "bg-muted-foreground")} />
            {currentTranscription ? "Enabled" : "Disabled"}
          </Badge>
        </div>

        <div className="flex items-center justify-between">
          <div className="space-y-0.5">
            <Label>Transcription</Label>
            <p
              className={`text-xs text-muted-foreground transition-opacity ${!currentTranscription ? "opacity-50" : ""}`}
            >
              Automatically convert voicemail audio to text.
            </p>
          </div>
          <Switch
            checked={!!currentTranscription}
            onCheckedChange={(v) => toggle(setTranscriptionEnabled, v)}
          />
        </div>

        <Separator />

        {/* Actions */}
        <Separator />
        <div className="grid gap-4 text-sm md:grid-cols-2">
          <div>
            <p className="text-muted-foreground text-sm">Created</p>
            {data.createdAt ? (
              <Tooltip>
                <TooltipTrigger asChild>
                  <p className="cursor-default text-sm">{formatRelativeTimeShort(data.createdAt)}</p>
                </TooltipTrigger>
                <TooltipContent>{formatDateTime(data.createdAt)}</TooltipContent>
              </Tooltip>
            ) : (
              <p className="text-sm">---</p>
            )}
          </div>
          <div>
            <p className="text-muted-foreground text-sm">Last Updated</p>
            {data.updatedAt ? (
              <Tooltip>
                <TooltipTrigger asChild>
                  <p className="cursor-default text-sm">{formatRelativeTimeShort(data.updatedAt)}</p>
                </TooltipTrigger>
                <TooltipContent>{formatDateTime(data.updatedAt)}</TooltipContent>
              </Tooltip>
            ) : (
              <p className="text-sm">---</p>
            )}
          </div>
        </div>

        <div className="flex items-center gap-3">
          <Button
            onClick={handleSave}
            disabled={
              (!dirty && !showSaveSuccess) || updateMutation.isPending || !!pinError
            }
            variant={showSaveSuccess ? "outline" : "default"}
            className={
              showSaveSuccess
                ? "border-green-500/50 text-green-600 dark:text-green-400"
                : ""
            }
          >
            {showSaveSuccess ? (
              <>
                <CheckCircle2 className="mr-1.5 h-4 w-4" />
                Saved
              </>
            ) : updateMutation.isPending ? (
              "Saving..."
            ) : (
              "Save changes"
            )}
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

// -- Box Message List ---------------------------------------------------------

function BoxMessageList({ boxId }: { boxId: string }) {
  const [page, setPage] = useState(1)
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [singleDeleteId, setSingleDeleteId] = useState<string | null>(null)

  const { data, isLoading, isError, refetch: refetchMessages } = useVoicemailMessages({
    boxId,
    page,
    pageSize: PAGE_SIZE,
  })
  const toggleReadMutation = useToggleVoicemailRead()
  const deleteMutation = useDeleteVoicemailMessage()

  if (isLoading) {
    return <SkeletonCard />
  }

  if (isError || !data) {
    return (
      <EmptyState
        icon={AlertCircle}
        title="Unable to load voicemail messages"
        description="Something went wrong. Please try again."
        action={<Button variant="outline" size="sm" onClick={() => refetchMessages()}>Try again</Button>}
      />
    )
  }

  const totalPages = Math.max(1, Math.ceil(data.total / PAGE_SIZE))
  const unreadCount = data.items.filter((m) => !m.isRead).length
  const allSelected = data.items.length > 0 && selectedIds.size === data.items.length
  const someSelected = selectedIds.size > 0

  function toggleSelectAll() {
    if (allSelected) {
      setSelectedIds(new Set())
    } else {
      setSelectedIds(new Set(data?.items.map((m) => m.id) ?? []))
    }
  }

  function toggleSelect(id: string) {
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  function handleExpand(message: VoicemailMessage) {
    if (expandedId === message.id) {
      setExpandedId(null)
    } else {
      setExpandedId(message.id)
      if (!message.isRead) {
        toggleReadMutation.mutate({ messageId: message.id, isRead: true })
      }
    }
  }

  function handleDeleteConfirm() {
    if (!singleDeleteId) return
    const messageId = singleDeleteId
    deleteMutation.mutate(messageId, {
      onSuccess: () => {
        setSingleDeleteId(null)
        if (expandedId === messageId) setExpandedId(null)
        setSelectedIds((prev) => {
          const next = new Set(prev)
          next.delete(messageId)
          return next
        })
      },
    })
  }

  if (data.items.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Messages</CardTitle>
        </CardHeader>
        <CardContent>
          <EmptyState
            icon={Inbox}
            title="No voicemail messages"
            description="When callers leave a voicemail for this box, their messages will appear here."
          />
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <div className="flex items-center gap-3">
          <CardTitle>Messages ({data.total})</CardTitle>
          {unreadCount > 0 && (
            <Badge variant="secondary" className="gap-1.5">
              <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-primary" />
              {unreadCount} unread
            </Badge>
          )}
          {someSelected && (
            <Badge variant="outline">{selectedIds.size} selected</Badge>
          )}
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="overflow-x-auto">
        <Table aria-label="Voicemail messages">
          <TableHeader>
            <TableRow>
              <TableHead className="w-10">
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-6 w-6 p-0"
                  onClick={toggleSelectAll}
                >
                  {allSelected ? (
                    <CheckSquare className="h-4 w-4" />
                  ) : (
                    <Square className="h-4 w-4" />
                  )}
                </Button>
              </TableHead>
              <TableHead className="w-10" />
              <TableHead>Caller</TableHead>
              <TableHead>Duration</TableHead>
              <TableHead>Received</TableHead>
              <TableHead>Transcription</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.items.map((msg, index) => {
              const callerDisplay = msg.callerName ?? msg.callerNumber
              const transcriptionPreview = msg.transcription
                ? msg.transcription.length > 60
                  ? `${msg.transcription.slice(0, 60)}...`
                  : msg.transcription
                : null

              return (
                <BoxMessageRow
                  key={msg.id}
                  message={msg}
                  callerDisplay={callerDisplay}
                  transcriptionPreview={transcriptionPreview}
                  isExpanded={expandedId === msg.id}
                  isSelected={selectedIds.has(msg.id)}
                  isEvenRow={index % 2 === 0}
                  onExpand={() => handleExpand(msg)}
                  onDelete={() => setSingleDeleteId(msg.id)}
                  onToggleRead={() =>
                    toggleReadMutation.mutate(
                      {
                        messageId: msg.id,
                        isRead: !msg.isRead,
                      },
                      {
                        onSuccess: () => {
                          toast.success(
                            msg.isRead ? "Marked as unread" : "Marked as read",
                          )
                        },
                      },
                    )
                  }
                  onToggleSelect={() => toggleSelect(msg.id)}
                />
              )
            })}
          </TableBody>
        </Table>
        </div>

        {totalPages > 1 && (
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">
              Page {page} of {totalPages}
            </p>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1}
              >
                Previous
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
              >
                Next
              </Button>
            </div>
          </div>
        )}
      </CardContent>

      {/* Single delete confirmation */}
      <AlertDialog
        open={singleDeleteId !== null}
        onOpenChange={(open) => {
          if (!open && !deleteMutation.isPending) setSingleDeleteId(null)
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2 text-destructive">
              <AlertTriangle className="size-5" />
              Delete voicemail
            </AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete this voicemail message. This action cannot be
              undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteMutation.isPending}>
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDeleteConfirm}
              disabled={deleteMutation.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteMutation.isPending ? (
                <>
                  <Loader2 className="mr-1 size-4 animate-spin" />
                  Deleting...
                </>
              ) : (
                <>
                  <Trash2 className="mr-1 size-4" />
                  Delete
                </>
              )}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  )
}

// -- Box Message Row ----------------------------------------------------------

function BoxMessageRow({
  message,
  callerDisplay,
  transcriptionPreview,
  isExpanded,
  isSelected,
  isEvenRow,
  onExpand,
  onDelete,
  onToggleRead,
  onToggleSelect,
}: {
  message: VoicemailMessage
  callerDisplay: string
  transcriptionPreview: string | null
  isExpanded: boolean
  isSelected: boolean
  isEvenRow: boolean
  onExpand: () => void
  onDelete: () => void
  onToggleRead: () => void
  onToggleSelect: () => void
}) {
  return (
    <>
      <TableRow
        className={`cursor-pointer transition-colors hover:bg-muted/50 ${isEvenRow ? "bg-muted/20" : ""} ${!message.isRead ? "bg-primary/5 font-medium" : ""} ${isSelected ? "bg-primary/10" : ""}`}
        onClick={onExpand}
      >
        <TableCell>
          <Button
            variant="ghost"
            size="sm"
            className="h-6 w-6 p-0"
            onClick={(e) => {
              e.stopPropagation()
              onToggleSelect()
            }}
          >
            {isSelected ? (
              <CheckSquare className="h-4 w-4" />
            ) : (
              <Square className="h-4 w-4" />
            )}
          </Button>
        </TableCell>
        <TableCell>
          <div className="flex items-center gap-1">
            {!message.isRead && (
              <div className="h-2.5 w-2.5 animate-pulse rounded-full bg-primary" />
            )}
            {message.isUrgent && (
              <AlertTriangle className="h-3.5 w-3.5 text-destructive" />
            )}
          </div>
        </TableCell>
        <TableCell>
          <div>
            <span className={!message.isRead ? "font-semibold" : ""}>
              {callerDisplay}
            </span>
            {message.callerName && (
              <p className="font-mono text-xs text-muted-foreground">
                {message.callerNumber}
              </p>
            )}
          </div>
        </TableCell>
        <TableCell className="tabular-nums">
          {formatDuration(message.durationSeconds)}
        </TableCell>
        <TableCell>
          <div className="flex items-center gap-2">
            <Tooltip>
              <TooltipTrigger asChild>
                <span className="text-sm">{formatDateTime(message.receivedAt)}</span>
              </TooltipTrigger>
              <TooltipContent>
                <p>{formatFullDateTime(message.receivedAt)}</p>
              </TooltipContent>
            </Tooltip>
            {message.isUrgent && (
              <Badge variant="destructive" className="gap-1.5 text-xs">
                <span className="h-1.5 w-1.5 rounded-full bg-red-200 dark:bg-red-400" />
                Urgent
              </Badge>
            )}
          </div>
        </TableCell>
        <TableCell className="max-w-xs text-sm text-muted-foreground">
          {transcriptionPreview ? (
            <Tooltip>
              <TooltipTrigger asChild>
                <span className="block truncate">{transcriptionPreview}</span>
              </TooltipTrigger>
              <TooltipContent side="top" className="max-w-sm">
                <p>{transcriptionPreview}</p>
              </TooltipContent>
            </Tooltip>
          ) : (
            <Badge variant="outline" className="gap-1.5 text-muted-foreground">
              <span className="h-1.5 w-1.5 rounded-full bg-muted-foreground" />
              None
            </Badge>
          )}
        </TableCell>
        <TableCell className="text-right">
          <div className="flex items-center justify-end gap-1">
            <Button
              variant="ghost"
              size="sm"
              onClick={(e) => {
                e.stopPropagation()
                onToggleRead()
              }}
              title={message.isRead ? "Mark as unread" : "Mark as read"}
            >
              {message.isRead ? (
                <MailOpen className="h-4 w-4" />
              ) : (
                <Mail className="h-4 w-4" />
              )}
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={(e) => {
                e.stopPropagation()
                onDelete()
              }}
            >
              <Trash2 className="h-4 w-4" />
            </Button>
          </div>
        </TableCell>
      </TableRow>
      {isExpanded && (
        <TableRow>
          <TableCell colSpan={7} className="bg-muted/30 px-6 py-4">
            <div className="space-y-4">
              <VoicemailPlayer
                audioUrl={message.audioFilePath}
                durationSeconds={message.durationSeconds}
              />
              {message.transcription && (
                <div className="space-y-1">
                  <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                    Transcription
                  </p>
                  <p className="text-sm leading-relaxed">{message.transcription}</p>
                </div>
              )}
            </div>
          </TableCell>
        </TableRow>
      )}
    </>
  )
}
