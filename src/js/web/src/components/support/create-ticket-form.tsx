import { zodResolver } from "@hookform/resolvers/zod"
import { Link, useBlocker, useRouter } from "@tanstack/react-router"
import {
  AlertCircle,
  AlertTriangle,
  ArrowDown,
  ArrowRight,
  ArrowUp,
  CreditCard,
  Flame,
  HelpCircle,
  Loader2,
  MonitorSmartphone,
  Phone,
  Printer,
  UserCircle,
  Wrench,
} from "lucide-react"
import { useEffect, useState } from "react"
import { useForm } from "react-hook-form"
import { z } from "zod"
import { AttachmentUpload, type PendingFile } from "@/components/support/attachment-upload"
import { MarkdownEditor } from "@/components/support/markdown-editor"
import { Alert, AlertDescription } from "@/components/ui/alert"
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
import { Button } from "@/components/ui/button"
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form"
import { Input } from "@/components/ui/input"
import { Separator } from "@/components/ui/separator"
import { useCreateTicket } from "@/lib/api/hooks/support"
import { cn } from "@/lib/utils"

// ── Field limits ──────────────────────────────────────────────────────

const SUBJECT_MAX = 200
const DESC_MAX = 2000

// ── Schema ──────────────────────────────────────────────────────────────

const createTicketSchema = z.object({
  subject: z.string().min(1, "Subject is required").max(SUBJECT_MAX, "Subject must be under 200 characters"),
  bodyMarkdown: z.string().min(10, "Description must be at least 10 characters").max(DESC_MAX, "Description must be under 2000 characters"),
  priority: z.string().min(1, "Priority is required"),
  category: z.string().optional(),
})

type CreateTicketFormData = z.infer<typeof createTicketSchema>

// ── Category config ─────────────────────────────────────────────────────

const categories = [
  { value: "general", label: "General", icon: HelpCircle, description: "General questions and feedback" },
  { value: "billing", label: "Billing", icon: CreditCard, description: "Invoices, payments, and plans" },
  { value: "technical", label: "Technical", icon: Wrench, description: "Bugs, errors, and technical issues" },
  { value: "account", label: "Account", icon: UserCircle, description: "Profile, access, and security" },
  { value: "device", label: "Device", icon: MonitorSmartphone, description: "Device setup and configuration" },
  { value: "voice", label: "Voice", icon: Phone, description: "Phone lines, calls, and voicemail" },
  { value: "fax", label: "Fax", icon: Printer, description: "Fax numbers, sending, and receiving" },
] as const

// ── Priority config ─────────────────────────────────────────────────────

const priorities = [
  {
    value: "low",
    label: "Low",
    icon: ArrowDown,
    description: "No immediate impact",
    badgeClass: "border-zinc-500/30 bg-zinc-500/10 text-zinc-700 dark:text-zinc-400",
    iconClass: "text-zinc-500",
  },
  {
    value: "medium",
    label: "Medium",
    icon: ArrowRight,
    description: "Minor disruption",
    badgeClass: "border-blue-500/30 bg-blue-500/10 text-blue-700 dark:text-blue-400",
    iconClass: "text-blue-500",
  },
  {
    value: "high",
    label: "High",
    icon: ArrowUp,
    description: "Significant impact",
    badgeClass: "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-400",
    iconClass: "text-amber-500",
  },
  {
    value: "urgent",
    label: "Urgent",
    icon: Flame,
    description: "Critical, needs immediate attention",
    badgeClass: "border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-400",
    iconClass: "text-red-500",
  },
] as const

// ── Required indicator ──────────────────────────────────────────────────

function RequiredIndicator() {
  return <span className="ml-0.5 text-destructive">*</span>
}

// ── Form ─────────────────────────────────────────────────────────────────

export function CreateTicketForm() {
  const router = useRouter()
  const createTicket = useCreateTicket()
  const [attachments, setAttachments] = useState<PendingFile[]>([])

  const form = useForm<CreateTicketFormData>({
    resolver: zodResolver(createTicketSchema),
    defaultValues: {
      subject: "",
      bodyMarkdown: "",
      priority: "medium",
      category: "",
    },
  })

  const { isDirty } = form.formState
  const hasAttachments = attachments.length > 0
  const isFormDirty = isDirty || hasAttachments

  // ── Unsaved changes: browser beforeunload ─────────────────────────────
  useEffect(() => {
    const handler = (e: BeforeUnloadEvent) => {
      if (isFormDirty) {
        e.preventDefault()
      }
    }
    window.addEventListener("beforeunload", handler)
    return () => window.removeEventListener("beforeunload", handler)
  }, [isFormDirty])

  // ── Unsaved changes: router navigation blocker ────────────────────────
  const blocker = useBlocker({
    shouldBlockFn: () => isFormDirty,
    enableBeforeUnload: false,
    withResolver: true,
  })

  const onSubmit = async (data: CreateTicketFormData) => {
    try {
      const ticket = await createTicket.mutateAsync({
        subject: data.subject,
        bodyMarkdown: data.bodyMarkdown,
        priority: data.priority,
        category: data.category || null,
      })
      // Reset dirty state before navigating so blocker doesn't fire
      form.reset(data)
      setAttachments([])
      router.navigate({
        to: "/support/$ticketId",
        params: { ticketId: ticket.id },
      })
    } catch (_error) {
      form.setError("root", {
        message: "Failed to create ticket. Please try again.",
      })
    }
  }

  const selectedPriority = priorities.find((p) => p.value === form.watch("priority"))

  return (
    <>
      <Form {...form}>
        <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
          {/* Subject */}
          <FormField
            control={form.control}
            name="subject"
            render={({ field }) => (
              <FormItem>
                <FormLabel>
                  Subject <RequiredIndicator />
                </FormLabel>
                <FormControl>
                  <Input placeholder="Brief summary of your issue" maxLength={SUBJECT_MAX} {...field} />
                </FormControl>
                <div className="flex items-center justify-between">
                  <FormDescription>A clear, concise title helps our team triage faster.</FormDescription>
                  <p className={cn("shrink-0 text-xs", field.value.length >= SUBJECT_MAX ? "text-destructive" : field.value.length >= SUBJECT_MAX * 0.8 ? "text-amber-500" : "text-muted-foreground")}>
                    {field.value.length}/{SUBJECT_MAX}
                  </p>
                </div>
                <FormMessage />
              </FormItem>
            )}
          />

          {/* Category & Priority */}
          <div className="grid gap-6 sm:grid-cols-2">
            {/* Category */}
            <FormField
              control={form.control}
              name="category"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Category</FormLabel>
                  <div className="grid grid-cols-2 gap-2">
                    {categories.map((cat) => {
                      const isSelected = field.value === cat.value
                      return (
                        <button
                          key={cat.value}
                          type="button"
                          onClick={() => field.onChange(isSelected ? "" : cat.value)}
                          className={cn(
                            "flex items-center gap-2 rounded-lg border px-3 py-2.5 text-left text-sm transition-all",
                            isSelected
                              ? "border-primary bg-primary/5 ring-1 ring-primary/20"
                              : "border-border/60 bg-card hover:border-border hover:bg-muted/40",
                          )}
                        >
                          <cat.icon className={cn("h-4 w-4 shrink-0", isSelected ? "text-primary" : "text-muted-foreground")} />
                          <div className="min-w-0">
                            <p className={cn("font-medium text-xs leading-none", isSelected && "text-primary")}>{cat.label}</p>
                          </div>
                        </button>
                      )
                    })}
                  </div>
                  <FormDescription>Select the area most related to your issue.</FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            {/* Priority */}
            <FormField
              control={form.control}
              name="priority"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>
                    Priority <RequiredIndicator />
                  </FormLabel>
                  <div className="space-y-2">
                    {priorities.map((prio) => {
                      const isSelected = field.value === prio.value
                      return (
                        <button
                          key={prio.value}
                          type="button"
                          onClick={() => field.onChange(prio.value)}
                          className={cn(
                            "flex w-full items-center gap-3 rounded-lg border px-3 py-2.5 text-left transition-all",
                            isSelected
                              ? "border-primary bg-primary/5 ring-1 ring-primary/20"
                              : "border-border/60 bg-card hover:border-border hover:bg-muted/40",
                          )}
                        >
                          <prio.icon className={cn("h-4 w-4 shrink-0", prio.iconClass)} />
                          <div className="min-w-0 flex-1">
                            <p className="font-medium text-sm leading-none">{prio.label}</p>
                            <p className="mt-0.5 text-xs text-muted-foreground">{prio.description}</p>
                          </div>
                          {isSelected && (
                            <Badge variant="outline" className={cn("shrink-0 text-[10px]", prio.badgeClass)}>
                              Selected
                            </Badge>
                          )}
                        </button>
                      )
                    })}
                  </div>
                  <FormDescription>
                    {selectedPriority
                      ? `${selectedPriority.label}: ${selectedPriority.description}.`
                      : "Choose based on business impact."}
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />
          </div>

          {/* Description */}
          <FormField
            control={form.control}
            name="bodyMarkdown"
            render={({ field }) => (
              <FormItem>
                <FormLabel>
                  Description <RequiredIndicator />
                </FormLabel>
                <FormControl>
                  <MarkdownEditor
                    value={field.value}
                    onChange={field.onChange}
                    placeholder="Describe your issue in detail... (Markdown supported)"
                    minHeight="180px"
                  />
                </FormControl>
                <div className="flex items-center justify-between">
                  <FormDescription>
                    Include steps to reproduce, expected behavior, and any error messages. Markdown formatting is supported.
                  </FormDescription>
                  <p className={cn("shrink-0 text-xs", field.value.length >= DESC_MAX ? "text-destructive" : field.value.length >= DESC_MAX * 0.8 ? "text-amber-500" : "text-muted-foreground")}>
                    {field.value.length}/{DESC_MAX}
                  </p>
                </div>
                <FormMessage />
              </FormItem>
            )}
          />

          {/* Attachments */}
          <div>
            <p className="mb-1 text-sm font-medium">Attachments</p>
            <p className="mb-3 text-xs text-muted-foreground">
              Screenshots, logs, or other files that help explain the issue. Max 10 MB per file.
            </p>
            <AttachmentUpload files={attachments} onFilesChange={setAttachments} />
          </div>

          {/* Error */}
          {form.formState.errors.root && (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>{form.formState.errors.root.message}</AlertDescription>
            </Alert>
          )}

          <Separator />

          {/* Actions */}
          <div className="flex items-center justify-between">
            <Button type="button" variant="ghost" asChild>
              <Link to="/support">Cancel</Link>
            </Button>
            <Button type="submit" disabled={form.formState.isSubmitting}>
              {form.formState.isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {form.formState.isSubmitting ? "Creating..." : "Create Ticket"}
            </Button>
          </div>
        </form>
      </Form>

      {/* Unsaved changes dialog */}
      <AlertDialog open={blocker.status === "blocked"} onOpenChange={(open) => !open && blocker.reset?.()}>
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
