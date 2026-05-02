import { createFileRoute, Link, useBlocker, useRouter } from "@tanstack/react-router"
import { Calendar, ChevronRight, Clock, Globe, Loader2, SlidersHorizontal, Star } from "lucide-react"
import { useRef, useState } from "react"
import { toast } from "sonner"
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
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader } from "@/components/ui/page-layout"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { type ScheduleCreate, useCreateSchedule } from "@/lib/api/hooks/schedules"
import { useAuthStore } from "@/lib/auth"

export const Route = createFileRoute("/_app/schedules/new")({
  component: NewSchedulePage,
})

const SCHEDULE_TYPES: { value: ScheduleCreate["scheduleType"]; label: string }[] = [
  { value: "business_hours", label: "Business Hours" },
  { value: "holiday", label: "Holiday" },
  { value: "custom", label: "Custom" },
]

const COMMON_TIMEZONES = [
  "America/New_York",
  "America/Chicago",
  "America/Denver",
  "America/Los_Angeles",
  "America/Phoenix",
  "America/Anchorage",
  "Pacific/Honolulu",
  "America/Toronto",
  "America/Vancouver",
  "Europe/London",
  "Europe/Paris",
  "Europe/Berlin",
  "Asia/Tokyo",
  "Asia/Shanghai",
  "Asia/Kolkata",
  "Australia/Sydney",
  "Pacific/Auckland",
  "UTC",
]

function getDefaultTimezone(): string {
  try {
    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone
    if (COMMON_TIMEZONES.includes(tz)) return tz
  } catch {
    // Intl not available
  }
  return "America/New_York"
}

const tips = [
  {
    icon: Clock,
    title: "Business hours",
    description: "Define when your office is open for calls and routing.",
  },
  {
    icon: Calendar,
    title: "Holiday schedules",
    description: "Set specific dates when normal hours do not apply.",
  },
  {
    icon: SlidersHorizontal,
    title: "Custom windows",
    description: "Create flexible time windows for any purpose.",
  },
  {
    icon: Globe,
    title: "Timezone aware",
    description: "Schedules respect the timezone you configure.",
  },
]

function NewSchedulePage() {
  useDocumentTitle("New Schedule")
  const router = useRouter()
  const createSchedule = useCreateSchedule()
  const currentTeam = useAuthStore((s) => s.currentTeam)
  const justSubmittedRef = useRef(false)

  const [name, setName] = useState("")
  const [scheduleType, setScheduleType] = useState<ScheduleCreate["scheduleType"]>("business_hours")
  const [timezone, setTimezone] = useState(getDefaultTimezone)
  const [isDefault, setIsDefault] = useState(false)

  const formDirty = name.trim() !== "" || scheduleType !== "business_hours" || timezone !== getDefaultTimezone() || isDefault

  const blocker = useBlocker({
    shouldBlockFn: () => formDirty && !justSubmittedRef.current,
    withResolver: true,
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!name.trim() || !currentTeam) return

    justSubmittedRef.current = true

    const payload: ScheduleCreate = {
      name: name.trim(),
      scheduleType,
      timezone,
      ...(isDefault ? { isDefault: true } : {}),
    }

    createSchedule.mutate(payload, {
      onSuccess: (data) => {
        toast.success("Schedule created successfully")
        router.navigate({ to: "/schedules/$scheduleId", params: { scheduleId: data.id } })
      },
      onSettled: () => {
        justSubmittedRef.current = false
      },
    })
  }

  const isValid = name.trim() !== "" && currentTeam !== null

  return (
    <>
      <PageContainer className="flex-1 space-y-8">
        <PageHeader
          eyebrow="Schedules"
          title="New Schedule"
          description="Create a schedule to define operating hours, holidays, or custom time windows."
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
                    <Link to="/schedules">Schedules</Link>
                  </BreadcrumbLink>
                </BreadcrumbItem>
                <BreadcrumbSeparator />
                <BreadcrumbItem>
                  <BreadcrumbPage>New Schedule</BreadcrumbPage>
                </BreadcrumbItem>
              </BreadcrumbList>
            </Breadcrumb>
          }
        />

        <div className="flex gap-6">
          {/* Main form */}
          <SectionErrorBoundary name="Create Schedule Form">
            <Card className="min-w-0 flex-1">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-lg">
                  <Clock className="h-5 w-5" />
                  Schedule Details
                </CardTitle>
                <CardDescription>Configure the basic settings for your new schedule. You can add time entries after creation.</CardDescription>
              </CardHeader>
              <CardContent>
                <form onSubmit={handleSubmit} className="space-y-6">
                  {/* Name */}
                  <div className="space-y-2">
                    <Label htmlFor="schedule-name">
                      Name <span className="text-red-500">*</span>
                    </Label>
                    <Input id="schedule-name" placeholder="e.g., Main Office Hours" value={name} onChange={(e) => setName(e.target.value)} required autoFocus />
                    <p className="text-xs text-muted-foreground">A descriptive name for this schedule.</p>
                  </div>

                  {/* Schedule Type */}
                  <div className="space-y-2">
                    <Label htmlFor="schedule-type">Schedule Type</Label>
                    <Select value={scheduleType} onValueChange={(v) => setScheduleType(v as ScheduleCreate["scheduleType"])}>
                      <SelectTrigger id="schedule-type">
                        <SelectValue placeholder="Select a type" />
                      </SelectTrigger>
                      <SelectContent>
                        {SCHEDULE_TYPES.map((t) => (
                          <SelectItem key={t.value} value={t.value}>
                            {t.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <p className="text-xs text-muted-foreground">Determines how this schedule is used in call routing and automation.</p>
                  </div>

                  {/* Timezone */}
                  <div className="space-y-2">
                    <Label htmlFor="schedule-timezone">Timezone</Label>
                    <Select value={timezone} onValueChange={setTimezone}>
                      <SelectTrigger id="schedule-timezone">
                        <SelectValue placeholder="Select a timezone" />
                      </SelectTrigger>
                      <SelectContent>
                        {COMMON_TIMEZONES.map((tz) => (
                          <SelectItem key={tz} value={tz}>
                            {tz.replace(/_/g, " ")}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <p className="text-xs text-muted-foreground">All schedule entries will be evaluated in this timezone.</p>
                  </div>

                  {/* Default toggle */}
                  <div className="flex items-center justify-between rounded-lg border p-4">
                    <div className="space-y-0.5">
                      <Label htmlFor="schedule-default" className="flex items-center gap-2">
                        <Star className="h-4 w-4 text-amber-500" />
                        Default Schedule
                      </Label>
                      <p className="text-xs text-muted-foreground">Mark this as the default schedule for the team.</p>
                    </div>
                    <Switch id="schedule-default" checked={isDefault} onCheckedChange={setIsDefault} />
                  </div>

                  {/* Actions */}
                  <div className="flex items-center justify-end gap-2 pt-2">
                    <Button type="button" variant="ghost" onClick={() => router.navigate({ to: "/schedules" })}>
                      Cancel
                    </Button>
                    <Button type="submit" disabled={!isValid || createSchedule.isPending}>
                      {createSchedule.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                      Create Schedule
                    </Button>
                  </div>
                </form>
              </CardContent>
            </Card>
          </SectionErrorBoundary>

          {/* Sidebar tips */}
          <Card className="h-fit w-72 shrink-0 border-border/40 bg-linear-to-br from-muted/30 to-muted/10">
            <CardHeader className="space-y-1 pb-3">
              <CardTitle className="text-lg">Getting Started</CardTitle>
              <CardDescription>Tips for your new schedule</CardDescription>
            </CardHeader>
            <CardContent className="space-y-1.5">
              {tips.map((tip) => (
                <div key={tip.title} className="group flex items-center gap-3 rounded-lg bg-background/60 p-3">
                  <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
                    <tip.icon className="h-4 w-4" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="font-medium text-sm">{tip.title}</p>
                    <p className="text-xs text-muted-foreground">{tip.description}</p>
                  </div>
                  <ChevronRight className="h-4 w-4 text-muted-foreground/30" />
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </PageContainer>

      {/* Unsaved changes dialog */}
      <AlertDialog open={blocker.status === "blocked"} onOpenChange={() => blocker.reset?.()}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Unsaved changes</AlertDialogTitle>
            <AlertDialogDescription>You have unsaved changes to this schedule. Are you sure you want to leave? Your changes will be lost.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => blocker.reset?.()}>Stay on page</AlertDialogCancel>
            <AlertDialogAction onClick={() => blocker.proceed?.()}>Discard changes</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
