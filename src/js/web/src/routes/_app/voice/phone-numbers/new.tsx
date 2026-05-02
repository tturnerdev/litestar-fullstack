import { createFileRoute, Link, useBlocker, useRouter } from "@tanstack/react-router"
import { useRef, useState } from "react"
import {
  AlertTriangle,
  Flag,
  Globe,
  Hash,
  Info,
  Loader2,
  MapPin,
  Phone,
  Shield,
  Tag,
  User,
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
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader } from "@/components/ui/page-layout"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { useCreatePhoneNumber } from "@/lib/api/hooks/voice"
import { cn } from "@/lib/utils"
import { toast } from "sonner"

export const Route = createFileRoute("/_app/voice/phone-numbers/new")({
  component: NewPhoneNumberPage,
})

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const NUMBER_MAX = 20
const LABEL_MAX = 100
const CALLER_ID_MAX = 100

const TYPE_OPTIONS = [
  { value: "local", label: "Local", icon: MapPin },
  { value: "toll_free", label: "Toll-Free", icon: Globe },
  { value: "international", label: "International", icon: Flag },
] as const

const tips = [
  {
    icon: Phone,
    title: "E.164 format",
    description: "Enter the phone number in E.164 format: + followed by country code and number (e.g., +15551234567).",
  },
  {
    icon: Tag,
    title: "Labels",
    description: "Add a descriptive label to quickly identify numbers in lists and dropdowns.",
  },
  {
    icon: User,
    title: "Caller ID",
    description: "The caller ID name is displayed to the recipient on outgoing calls made from this number.",
  },
  {
    icon: Shield,
    title: "E911 registration",
    description: "After creating a number, register it for E911 to ensure emergency services can locate callers.",
  },
]

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

function NewPhoneNumberPage() {
  useDocumentTitle("New Phone Number")
  const router = useRouter()
  const createMutation = useCreatePhoneNumber()
  const justSubmittedRef = useRef(false)

  // Form state
  const [number, setNumber] = useState("")
  const [label, setLabel] = useState("")
  const [numberType, setNumberType] = useState("local")
  const [callerIdName, setCallerIdName] = useState("")
  const [isActive, setIsActive] = useState(true)

  // Validation
  const [numberTouched, setNumberTouched] = useState(false)
  const [submitAttempted, setSubmitAttempted] = useState(false)

  const numberFormatError =
    number.trim() !== "" && !/^\+\d+$/.test(number.trim())
      ? "Must be E.164 format: + followed by digits (e.g., +15551234567)"
      : ""

  const numberEmpty = (numberTouched || submitAttempted) && !number.trim()

  const isValid = number.trim() !== "" && !numberFormatError

  // Dirty check
  const formDirty =
    number.trim() !== "" ||
    label.trim() !== "" ||
    callerIdName.trim() !== "" ||
    numberType !== "local" ||
    !isActive

  const blocker = useBlocker({
    shouldBlockFn: () => formDirty && !justSubmittedRef.current,
    withResolver: true,
  })

  // Submit
  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()

    if (!isValid) {
      setSubmitAttempted(true)
      return
    }

    justSubmittedRef.current = true

    createMutation.mutate(
      {
        number: number.trim(),
        label: label.trim() || null,
        numberType,
        callerIdName: callerIdName.trim() || null,
        isActive,
      },
      {
        onSuccess: (data) => {
          toast.success("Phone number created successfully")
          router.navigate({
            to: "/voice/phone-numbers/$phoneNumberId",
            params: { phoneNumberId: data.id },
          })
        },
        onSettled: () => {
          justSubmittedRef.current = false
        },
      },
    )
  }

  return (
    <>
      <PageContainer className="flex-1 space-y-8">
        <PageHeader
          eyebrow="Voice"
          title="New Phone Number"
          description="Add a DID phone number to your system for call routing and assignment."
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
                    <Link to="/voice/phone-numbers">Voice</Link>
                  </BreadcrumbLink>
                </BreadcrumbItem>
                <BreadcrumbSeparator />
                <BreadcrumbItem>
                  <BreadcrumbLink asChild>
                    <Link to="/voice/phone-numbers">Phone Numbers</Link>
                  </BreadcrumbLink>
                </BreadcrumbItem>
                <BreadcrumbSeparator />
                <BreadcrumbItem>
                  <BreadcrumbPage>New Phone Number</BreadcrumbPage>
                </BreadcrumbItem>
              </BreadcrumbList>
            </Breadcrumb>
          }
        />

        <div className="flex gap-6">
          {/* Main form */}
          <Card className="min-w-0 flex-1">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-lg">
                <Hash className="h-5 w-5" />
                Phone Number Details
              </CardTitle>
              <CardDescription>
                Fields marked with <span className="text-destructive">*</span> are required.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleSubmit} className="space-y-6">
                {/* Phone Number */}
                <div className="space-y-2">
                  <Label htmlFor="pn-number">
                    Phone Number <span className="text-red-500">*</span>
                  </Label>
                  <Input
                    id="pn-number"
                    placeholder="+15551234567"
                    value={number}
                    onChange={(e) => setNumber(e.target.value)}
                    onBlur={() => setNumberTouched(true)}
                    maxLength={NUMBER_MAX}
                    required
                    autoFocus
                    aria-invalid={!!numberFormatError || numberEmpty}
                  />
                  <div className="flex items-center justify-between">
                    {numberEmpty ? (
                      <p className="text-xs text-destructive">Phone number is required</p>
                    ) : numberFormatError ? (
                      <p className="text-xs text-destructive">{numberFormatError}</p>
                    ) : (
                      <p className="text-xs text-muted-foreground">
                        Enter in E.164 format, e.g., +15551234567
                      </p>
                    )}
                    <p
                      className={cn(
                        "shrink-0 text-xs",
                        number.length >= NUMBER_MAX
                          ? "text-destructive"
                          : "text-muted-foreground",
                      )}
                    >
                      {number.length}/{NUMBER_MAX}
                    </p>
                  </div>
                </div>

                {/* Label */}
                <div className="space-y-2">
                  <Label htmlFor="pn-label">Label</Label>
                  <Input
                    id="pn-label"
                    placeholder="e.g., Main Line"
                    value={label}
                    onChange={(e) => setLabel(e.target.value)}
                    maxLength={LABEL_MAX}
                  />
                  <div className="flex items-center justify-between">
                    <p className="text-xs text-muted-foreground">
                      Optional friendly name to identify this number.
                    </p>
                    <p
                      className={cn(
                        "shrink-0 text-xs",
                        label.length >= LABEL_MAX
                          ? "text-destructive"
                          : "text-muted-foreground",
                      )}
                    >
                      {label.length}/{LABEL_MAX}
                    </p>
                  </div>
                </div>

                {/* Type */}
                <div className="space-y-2">
                  <Label htmlFor="pn-type">Type</Label>
                  <Select value={numberType} onValueChange={setNumberType}>
                    <SelectTrigger id="pn-type">
                      <SelectValue placeholder="Select a type" />
                    </SelectTrigger>
                    <SelectContent>
                      {TYPE_OPTIONS.map(({ value, label: optLabel, icon: Icon }) => (
                        <SelectItem key={value} value={value}>
                          <span className="flex items-center gap-2">
                            <Icon className="h-4 w-4 text-muted-foreground" />
                            {optLabel}
                          </span>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <p className="text-xs text-muted-foreground">
                    Determines routing and billing for this number.
                  </p>
                </div>

                {/* Caller ID Name */}
                <div className="space-y-2">
                  <Label htmlFor="pn-caller-id">Caller ID Name</Label>
                  <Input
                    id="pn-caller-id"
                    placeholder="e.g., Acme Corp"
                    value={callerIdName}
                    onChange={(e) => setCallerIdName(e.target.value)}
                    maxLength={CALLER_ID_MAX}
                  />
                  <div className="flex items-center justify-between">
                    <p className="text-xs text-muted-foreground">
                      Name displayed to the recipient on outgoing calls.
                    </p>
                    <p
                      className={cn(
                        "shrink-0 text-xs",
                        callerIdName.length >= CALLER_ID_MAX
                          ? "text-destructive"
                          : "text-muted-foreground",
                      )}
                    >
                      {callerIdName.length}/{CALLER_ID_MAX}
                    </p>
                  </div>
                </div>

                {/* Active toggle */}
                <div className="flex items-center gap-3 rounded-md border p-3">
                  <Switch
                    id="pn-active"
                    checked={isActive}
                    onCheckedChange={setIsActive}
                  />
                  <div className="space-y-0.5">
                    <Label htmlFor="pn-active" className="cursor-pointer">
                      Active
                    </Label>
                    <p className="text-xs text-muted-foreground">
                      When disabled, the number will not receive or route calls.
                    </p>
                  </div>
                </div>

                {/* Preview */}
                {(number.trim() || callerIdName.trim()) && (
                  <div className="rounded-lg border bg-muted/50 p-4">
                    <p className="mb-1 text-xs font-medium text-muted-foreground">Preview</p>
                    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
                      {number.trim() && (
                        <span className="font-mono">{number.trim()}</span>
                      )}
                      <span className="text-muted-foreground">
                        {TYPE_OPTIONS.find((o) => o.value === numberType)?.label ?? numberType}
                      </span>
                      {callerIdName.trim() && (
                        <>
                          <span className="text-muted-foreground">&bull;</span>
                          <span>Caller ID: {callerIdName.trim()}</span>
                        </>
                      )}
                      {label.trim() && (
                        <>
                          <span className="text-muted-foreground">&bull;</span>
                          <span className="text-muted-foreground">{label.trim()}</span>
                        </>
                      )}
                    </div>
                  </div>
                )}

                {/* Actions */}
                <div className="flex items-center justify-end gap-2 border-t pt-4">
                  <Button
                    type="button"
                    variant="ghost"
                    onClick={() => router.navigate({ to: "/voice/phone-numbers" })}
                  >
                    Cancel
                  </Button>
                  <Button
                    type="submit"
                    disabled={!isValid || createMutation.isPending}
                  >
                    {createMutation.isPending && (
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    )}
                    Create Phone Number
                  </Button>
                </div>
              </form>
            </CardContent>
          </Card>

          {/* Sidebar tips */}
          <Card className="hidden h-fit w-72 shrink-0 border-border/40 bg-linear-to-br from-muted/30 to-muted/10 lg:block">
            <CardHeader className="space-y-1 pb-3">
              <CardTitle className="flex items-center gap-2 text-lg">
                <Info className="h-4 w-4" />
                Tips
              </CardTitle>
              <CardDescription>Setting up phone numbers</CardDescription>
            </CardHeader>
            <CardContent className="space-y-1.5">
              {tips.map((tip) => (
                <div
                  key={tip.title}
                  className="group flex items-center gap-3 rounded-lg bg-background/60 p-3"
                >
                  <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
                    <tip.icon className="h-4 w-4" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="font-medium text-sm">{tip.title}</p>
                    <p className="text-xs text-muted-foreground">
                      {tip.description}
                    </p>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </PageContainer>

      {/* Unsaved changes dialog */}
      <AlertDialog
        open={blocker.status === "blocked"}
        onOpenChange={(open) => !open && blocker.reset?.()}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-amber-500" />
              Unsaved Changes
            </AlertDialogTitle>
            <AlertDialogDescription>
              You have unsaved changes on this form. If you leave now, your progress will be lost.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => blocker.reset?.()}>Stay on Page</AlertDialogCancel>
            <AlertDialogAction onClick={() => blocker.proceed?.()}>Discard Changes</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
