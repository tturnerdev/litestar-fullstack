import { createFileRoute, Link } from "@tanstack/react-router"
import {
  ArrowLeft,
  BellOff,
  BellRing,
  Calendar,
  Clock,
  Loader2,
  ShieldCheck,
} from "lucide-react"
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
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonCard } from "@/components/ui/skeleton"
import { DndSettingsForm } from "@/components/voice/dnd-settings-form"
import { useDndSettings, useExtension, useToggleDnd } from "@/lib/api/hooks/voice"

export const Route = createFileRoute("/_app/voice/extensions/$extensionId/dnd")({
  component: DndPage,
})

// -- Helpers ------------------------------------------------------------------

const DAY_LABELS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

const MODE_LABELS: Record<string, string> = {
  off: "Off",
  always: "Always On",
  scheduled: "Scheduled",
}

const MODE_DESCRIPTIONS: Record<string, string> = {
  off: "Do Not Disturb is disabled. All calls ring normally.",
  always: "All incoming calls are silenced at all times.",
  scheduled: "Calls are silenced during configured time windows.",
}

function formatScheduleTime(time: string | null): string {
  if (!time) return "--:--"
  const [hours, minutes] = time.split(":").map(Number)
  const h = hours ?? 0
  const m = minutes ?? 0
  const suffix = h >= 12 ? "PM" : "AM"
  const displayHour = h === 0 ? 12 : h > 12 ? h - 12 : h
  return `${displayHour}:${String(m).padStart(2, "0")} ${suffix}`
}

function formatScheduleDays(days: number[] | null): string {
  if (!days || days.length === 0) return "No days selected"
  if (days.length === 7) return "Every day"
  const weekdays = [0, 1, 2, 3, 4]
  const weekends = [5, 6]
  if (
    days.length === 5 &&
    weekdays.every((d) => days.includes(d))
  ) {
    return "Weekdays"
  }
  if (
    days.length === 2 &&
    weekends.every((d) => days.includes(d))
  ) {
    return "Weekends"
  }
  return days.map((d) => DAY_LABELS[d] ?? "?").join(", ")
}

// -- Main page ----------------------------------------------------------------

function DndPage() {
  const { extensionId } = Route.useParams()
  const { data: extension, isLoading: extLoading } = useExtension(extensionId)
  const { data: dnd, isLoading: dndLoading, isError } = useDndSettings(extensionId)
  const toggleMutation = useToggleDnd(extensionId)

  const isLoading = extLoading || dndLoading

  // Loading state
  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader eyebrow="Voice" title="Do Not Disturb" />
        <PageSection>
          <SkeletonCard />
        </PageSection>
        <PageSection delay={0.1}>
          <SkeletonCard />
        </PageSection>
      </PageContainer>
    )
  }

  // Error state
  if (isError || !dnd) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader
          eyebrow="Voice"
          title="Do Not Disturb"
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
                    <Link to="/voice/extensions">Extensions</Link>
                  </BreadcrumbLink>
                </BreadcrumbItem>
                <BreadcrumbSeparator />
                <BreadcrumbItem>
                  <BreadcrumbPage>Do Not Disturb</BreadcrumbPage>
                </BreadcrumbItem>
              </BreadcrumbList>
            </Breadcrumb>
          }
          actions={
            <Button variant="outline" size="sm" asChild>
              <Link to="/voice/extensions/$extensionId" params={{ extensionId }}>
                <ArrowLeft className="mr-2 h-4 w-4" /> Back to Extension
              </Link>
            </Button>
          }
        />
        <PageSection>
          <Card>
            <CardContent className="py-8 text-center text-muted-foreground">
              Unable to load DND settings for this extension.
            </CardContent>
          </Card>
        </PageSection>
      </PageContainer>
    )
  }

  const isEnabled = dnd.isEnabled
  const mode = dnd.mode ?? "off"
  const extensionName = extension
    ? `${extension.displayName} (Ext. ${extension.extensionNumber})`
    : `Extension ${extensionId.slice(0, 8)}`

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Voice"
        title="Do Not Disturb"
        description={`Manage DND settings for ${extensionName}`}
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
                  <Link to="/voice/extensions">Extensions</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbLink asChild>
                  <Link
                    to="/voice/extensions/$extensionId"
                    params={{ extensionId }}
                  >
                    {extension?.displayName ?? "Extension"}
                  </Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbPage>Do Not Disturb</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
        actions={
          <Button variant="outline" size="sm" asChild>
            <Link to="/voice/extensions/$extensionId" params={{ extensionId }}>
              <ArrowLeft className="mr-2 h-4 w-4" /> Back to Extension
            </Link>
          </Button>
        }
      />

      {/* DND Status Card -- large visual indicator with toggle */}
      <PageSection>
        <Card
          className={
            isEnabled
              ? "border-destructive/40 bg-destructive/5"
              : "border-emerald-500/30 bg-emerald-50/50 dark:bg-emerald-950/10"
          }
        >
          <CardContent className="py-8">
            <div className="flex flex-col items-center gap-6 text-center md:flex-row md:text-left">
              {/* Icon */}
              <div
                className={`flex h-20 w-20 shrink-0 items-center justify-center rounded-full ${
                  isEnabled
                    ? "bg-destructive/10 text-destructive"
                    : "bg-emerald-100 text-emerald-600 dark:bg-emerald-900/30 dark:text-emerald-400"
                }`}
              >
                {isEnabled ? (
                  <BellOff className="h-10 w-10" />
                ) : (
                  <BellRing className="h-10 w-10" />
                )}
              </div>

              {/* Status info */}
              <div className="flex-1 space-y-2">
                <div className="flex flex-col items-center gap-2 md:flex-row">
                  <h2 className="text-2xl font-semibold tracking-tight">
                    {isEnabled ? "Do Not Disturb is Active" : "Do Not Disturb is Off"}
                  </h2>
                  <Badge
                    variant={isEnabled ? "destructive" : "secondary"}
                    className="text-xs"
                  >
                    {isEnabled ? "Active" : "Inactive"}
                  </Badge>
                  {mode !== "off" && (
                    <Badge variant="outline" className="text-xs">
                      Mode: {MODE_LABELS[mode] ?? mode}
                    </Badge>
                  )}
                </div>
                <p className="text-sm text-muted-foreground">
                  {MODE_DESCRIPTIONS[mode] ?? ""}
                </p>
              </div>

              {/* Toggle */}
              <div className="flex flex-col items-center gap-2">
                <button
                  type="button"
                  className={`relative inline-flex h-10 w-[72px] shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:cursor-not-allowed disabled:opacity-50 ${
                    isEnabled ? "bg-destructive" : "bg-input"
                  }`}
                  role="switch"
                  aria-checked={isEnabled}
                  aria-label="Toggle Do Not Disturb"
                  disabled={toggleMutation.isPending}
                  onClick={() => toggleMutation.mutate()}
                >
                  <span
                    className={`pointer-events-none flex h-8 w-8 items-center justify-center rounded-full bg-background shadow-lg ring-0 transition-transform ${
                      isEnabled ? "translate-x-9" : "translate-x-0.5"
                    }`}
                  >
                    {toggleMutation.isPending ? (
                      <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
                    ) : isEnabled ? (
                      <BellOff className="h-4 w-4 text-destructive" />
                    ) : (
                      <BellRing className="h-4 w-4 text-muted-foreground" />
                    )}
                  </span>
                </button>
                <span className="text-xs text-muted-foreground">
                  {toggleMutation.isPending
                    ? "Updating..."
                    : isEnabled
                      ? "Click to disable"
                      : "Click to enable"}
                </span>
              </div>
            </div>
          </CardContent>
        </Card>
      </PageSection>

      {/* Quick Status Summary */}
      <PageSection delay={0.05}>
        <div className="grid gap-4 md:grid-cols-3">
          {/* Mode */}
          <Card>
            <CardHeader className="pb-2">
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-muted-foreground" />
                <CardTitle className="text-sm font-medium">Current Mode</CardTitle>
              </div>
            </CardHeader>
            <CardContent>
              <p className="text-lg font-semibold">{MODE_LABELS[mode] ?? mode}</p>
              <p className="text-xs text-muted-foreground">
                {mode === "scheduled"
                  ? "Active during scheduled hours"
                  : mode === "always"
                    ? "Active around the clock"
                    : "Not silencing any calls"}
              </p>
            </CardContent>
          </Card>

          {/* Schedule */}
          <Card>
            <CardHeader className="pb-2">
              <div className="flex items-center gap-2">
                <Clock className="h-4 w-4 text-muted-foreground" />
                <CardTitle className="text-sm font-medium">Schedule</CardTitle>
              </div>
            </CardHeader>
            <CardContent>
              {mode === "scheduled" && dnd.scheduleStart && dnd.scheduleEnd ? (
                <>
                  <p className="text-lg font-semibold">
                    {formatScheduleTime(dnd.scheduleStart)} - {formatScheduleTime(dnd.scheduleEnd)}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {formatScheduleDays(dnd.scheduleDays)}
                  </p>
                </>
              ) : (
                <>
                  <p className="text-lg font-semibold text-muted-foreground">--</p>
                  <p className="text-xs text-muted-foreground">No schedule configured</p>
                </>
              )}
            </CardContent>
          </Card>

          {/* Allow List */}
          <Card>
            <CardHeader className="pb-2">
              <div className="flex items-center gap-2">
                <Calendar className="h-4 w-4 text-muted-foreground" />
                <CardTitle className="text-sm font-medium">Allowed Callers</CardTitle>
              </div>
            </CardHeader>
            <CardContent>
              {dnd.allowList && dnd.allowList.length > 0 ? (
                <>
                  <p className="text-lg font-semibold">{dnd.allowList.length}</p>
                  <p className="text-xs text-muted-foreground">
                    {dnd.allowList.length === 1
                      ? "1 number can bypass DND"
                      : `${dnd.allowList.length} numbers can bypass DND`}
                  </p>
                </>
              ) : (
                <>
                  <p className="text-lg font-semibold text-muted-foreground">0</p>
                  <p className="text-xs text-muted-foreground">No exceptions configured</p>
                </>
              )}
            </CardContent>
          </Card>
        </div>
      </PageSection>

      {/* Settings Form */}
      <PageSection delay={0.1}>
        <DndSettingsForm extensionId={extensionId} />
      </PageSection>
    </PageContainer>
  )
}
